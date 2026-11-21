//! The profile language: `${{ name }}` placeholders, declarations, and `extend`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

pub use strands_box_cli_telemetry::PackLocation;

use crate::error::Error;
use crate::host::{canonical, is_executable_file, resolved, utf8, within};
use crate::locate::{self, line_of, unknown_key};
use crate::mcp;
use crate::plugin::{self, PLUGINS, SECRET_SOURCE};
use crate::reference::{Credentials, Sources};
use crate::storage_edit::{Edit, KeyPath, Setting, shown};
use crate::storage_files::{Refusals, StorageFile};

/// The opening of a placeholder.
pub(crate) const OPEN: &str = "${{";
const CLOSE: &str = "}}";

/// The prefix of a pack that `box` ships.
pub const VENDORED: &str = "@box/";

/// The sections `box run` reads itself and never passes to Box Core.
const LANGUAGE_KEYS: &[&str] = &[
    EXTEND,
    INCLUDE,
    PROFILE_HEADER,
    "packs",
    "pack",
    "inputs",
    "options",
    "storage",
    "policies",
    BANNER,
    PLUGINS,
    MCP_SERVERS,
];

/// The profile table that names a profile `box run` loads from a path.
pub(crate) const PROFILE_HEADER: &str = "profile";

/// The pack key that names the host files that hold the agent's MCP servers.
pub const MCP_SERVERS: &str = "mcp-servers";

/// The `[pack]` key that names the packs this one builds on, merged before it.
pub const EXTEND: &str = "extend";

/// The `[pack]` key that names tool packs to load as tools of their own beside this pack, as a
/// profile's `packs` does. Unlike `extend`, nothing of them is merged into this pack.
pub const INCLUDE: &str = "include";

/// The sections that reach `box.toml` as a pack or a profile writes them.
const BOX_KEYS: &[&str] = &["agent", "tool", "egress", "mcp", "telemetry"];

/// The keys of a tool pack, as the load reads it, that stay out of its tool table. Every other key
/// moves into the tool table.
pub(crate) const TOOL_PACK_TOP: &[&str] = &["pack", EXTEND, INCLUDE, "inputs"];

/// The keys of a tool table that `box` reads, which a tool pack writes at its top.
pub(crate) const TOOL_KEYS: &[&str] = &[
    "program",
    "helpers",
    "hosts",
    "installation",
    "upgrade_http",
];

/// The tables a tool pack cannot write, because it writes one tool.
const NOT_IN_A_TOOL_PACK: &[&str] = &["agent", "egress", "mcp", "tool", "telemetry"];
/// The profile key that fills the slot of `[agent] command`, and the name of that slot.
const AGENT_ARGS: &str = "agent-args";

/// The profile key that sets Box Core's `file-attributes` switch.
pub(crate) const FILE_ATTRIBUTES: &str = "file-attributes";

/// The profile table that sets Box Core's `[limits]`.
const LIMITS: &str = "limits";

/// The table that enables experimental Box Core features.
const EXPERIMENTAL_FEATURES: &str = "experimental-features";

/// The switch that selects native filesystem policy checks.
const NATIVE_FILESYSTEM_POLICY: &str = "native-filesystem-policy";

/// The profile table that sets how much of the project a run reaches.
pub const PROJECT: &str = "project";

/// The profile table whose `deny` and `deny_write` reach every process.
pub const PROFILE_FILESYSTEM: &str = "filesystem";

/// The lists of a profile's `[filesystem]`.
const PROFILE_LISTS: &[&str] = &["deny", "deny_write"];

/// The table, in a profile and in `~/.strands/box/config.toml`, that turns the activity banner on or off.
pub const BANNER: &str = "banner";

/// The key of the `[agent] command` element that marks where `agent-args` goes.
const SLOT: &str = "slot";

/// The file that holds a profile pack.
pub const PACK_FILE: &str = "pack.toml";

/// The keys of an `[agent]` table.
const AGENT_KEYS: &[&str] = &[
    "command",
    "dependency",
    "env",
    "file-watching",
    "filesystem",
    "ingress",
    NATIVE_FILESYSTEM_POLICY,
    "when",
];

/// The keys of a process that a profile writes in `[agent]` or a `[tool.<name>]` table, never at
/// its top.
const PROCESS_KEYS: &[&str] = &[
    "command",
    "dependency",
    "env",
    "filesystem",
    NATIVE_FILESYSTEM_POLICY,
];

/// The top-level keys that the load refuses in a pack with a reason of their own: the keys of a
/// profile, and the keys that `box run` sets for each run.
const REFUSED_WITH_A_REASON: &[&str] = &[
    "packs",
    PLUGINS,
    "policies",
    AGENT_ARGS,
    FILE_ATTRIBUTES,
    "name",
    "box_dir",
    "workspace",
];

/// The table of an agent pack or a tool pack that holds how its program starts.
const RUN: &str = "run";

/// The keys of an agent pack's `[run]`.
const AGENT_RUN_KEYS: &[&str] = &["command", "dependency", "file-watching", "when"];

/// The keys of a tool pack's `[run]`.
const TOOL_RUN_KEYS: &[&str] = &[
    "command",
    "file-watching",
    "helpers",
    "hosts",
    "installation",
    "upgrade_http",
    "when",
];

/// The tables that only an agent pack or a tool pack holds, for its one program.
const PROGRAM_TABLES: &[&str] = &[RUN, "env", "filesystem"];

/// The table of a tool's connections, which only a profile writes.
const TOOL_NETWORK: &str = "network";

/// Why a pack holds no `network` table.
const NETWORK_IS_THE_PROFILES: &str =
    "a tool's network containment is the operator's choice, so only a profile turns it off";

/// The keys of a `[tool.<name>]` table.
const TOOL_TABLE_KEYS: &[&str] = &[
    "command",
    "dependency",
    "env",
    "file-watching",
    "filesystem",
    "helpers",
    "hosts",
    "installation",
    "grammar",
    NATIVE_FILESYSTEM_POLICY,
    "network",
    "program",
    "storage",
    "upgrade_http",
    "when",
];

/// The file beside a tool pack's `pack.toml` that holds its tool grammar.
pub(crate) const GRAMMAR_FILE: &str = "grammar.toml";

/// The keys a `[tool.<name>]` table refuses in `tool`, which names what to write instead.
const TOOL_TABLE_REFUSED_IN_TOOL: &[&str] = &["detect", "pack", EXTEND, INCLUDE, "inputs"];

/// The keys of a `filesystem` table.
const FILESYSTEM_KEYS: &[&str] = &[
    "read",
    "write",
    "read_file",
    "write_file",
    "list",
    "metadata",
    "exec",
    "deny",
    "deny_write",
    "when",
];

/// The keys of a `[tool.<name>.network]` table.
const NETWORK_KEYS: &[&str] = &["contain_egress"];

/// The keys of `[storage]`.
const STORAGE_KEYS: &[&str] = &["directories", "files", "hooks"];

/// The keys of `[pack]`.
const HEADER_KEYS: &[&str] = &["name", "version", "kind", "engine"];

/// The name of the profile's own layer.
pub(crate) const THE_PROFILE: &str = "the profile";

/// The values of `[pack] kind`.
const PACK_KINDS: &[&str] = &[AGENT_KIND, TOOL_KIND, SUPPORT_KIND];
/// The kind of a pack that runs an agent.
const AGENT_KIND: &str = "agent";
/// The kind of a pack that holds one tool table.
const TOOL_KIND: &str = "tool";
/// The kind of every other pack.
const SUPPORT_KIND: &str = "support";

/// The keys of an input declaration.
pub const DECLARATION_KEYS: &[&str] = &[
    "description",
    "type",
    "default",
    "from",
    "key",
    "pattern",
    "values",
    "program",
    "search",
    "warning",
];

/// Where a `program` input finds its program: the file name, and the folders it lies in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Search {
    program: String,
    folders: Vec<Folder>,
}

/// One entry of an input's `search`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Folder {
    /// A folder, with placeholders and `*`.
    Path(String),
    /// Each folder in a host variable, such as `PATH`.
    Env(String),
}

impl std::fmt::Display for Search {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let folders: Vec<String> = self
            .folders
            .iter()
            .map(|folder| match folder {
                Folder::Path(path) => path.clone(),
                Folder::Env(variable) => format!("${variable}"),
            })
            .collect();
        write!(formatter, "{} in {}", self.program, folders.join(", "))
    }
}

/// One part of a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    Text(String),
    Name(String),
}

/// `text` split into literal text and placeholder names.
pub fn pieces(text: &str) -> Result<Vec<Piece>, String> {
    let mut out = Vec::new();
    let mut literal = String::new();
    let mut rest = text;
    while let Some(start) = rest.find(OPEN) {
        if rest[..start].ends_with('$') {
            literal.push_str(&rest[..start - 1]);
            literal.push_str(OPEN);
            rest = &rest[start + OPEN.len()..];
            continue;
        }
        literal.push_str(&rest[..start]);
        let after = &rest[start + OPEN.len()..];
        let end = after
            .find(CLOSE)
            .ok_or_else(|| format!("{text:?} opens `${{{{` with no closing `}}}}`"))?;
        let name = after[..end].trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            return Err(format!("`${{{{ {name} }}}}` in {text:?} is not a name"));
        }
        if !literal.is_empty() {
            out.push(Piece::Text(std::mem::take(&mut literal)));
        }
        out.push(Piece::Name(name.to_string()));
        rest = &after[end + CLOSE.len()..];
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        out.push(Piece::Text(literal));
    }
    Ok(out)
}

fn has_placeholder(text: &str) -> bool {
    pieces(text).is_ok_and(|parts| parts.iter().any(|part| matches!(part, Piece::Name(_))))
}

/// `text` with `name` replaced by `value`, and every other placeholder and escape kept.
fn bind(text: &str, name: &str, value: &str) -> Result<String, String> {
    replace_name(text, name, &value.replace(OPEN, "$${{"))
}

fn replace_name(text: &str, name: &str, with: &str) -> Result<String, String> {
    Ok(pieces(text)?
        .into_iter()
        .map(|piece| match piece {
            Piece::Text(text) => text.replace(OPEN, "$${{"),
            Piece::Name(found) if found == name => with.to_string(),
            Piece::Name(other) => format!("${{{{ {other} }}}}"),
        })
        .collect())
}

/// Apply `change` to every string in `value`.
fn each_string(
    value: &mut toml::Value,
    change: &mut dyn FnMut(&str) -> Result<String, String>,
) -> Result<(), String> {
    match value {
        toml::Value::String(text) => *text = change(text)?,
        toml::Value::Array(items) => {
            for item in items {
                each_string(item, change)?;
            }
        }
        toml::Value::Table(table) => {
            for (_, item) in table.iter_mut() {
                each_string(item, change)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// `value` with every `${{` escaped, so a detected value holds no placeholder.
pub(crate) fn escape_all(value: &mut toml::Value) {
    let _ = each_string(value, &mut |text| Ok(text.replace(OPEN, "$${{")));
}

/// Refuse a malformed placeholder anywhere in `table`.
pub(crate) fn check_syntax(table: &toml::Table) -> Result<(), String> {
    let mut value = toml::Value::Table(table.clone());
    each_string(&mut value, &mut |text| {
        pieces(text).map(|_| text.to_string())
    })
}

/// One profile file in an `extend` chain.
#[derive(Debug, Clone)]
pub struct Layer {
    pub name: String,
    pub path: PathBuf,
    pub location: PackLocation,
    /// A pack or a plugin, as opposed to the operator's profile.
    pub shared: bool,
    /// A plugin that the profile lists in `plugins`.
    pub plugin: bool,
    pub table: toml::Table,
    /// The file as written, which a refusal finds its line in.
    pub text: String,
    /// The optional `grammar.toml` as read beside this pack.
    pub grammar_text: Option<String>,
    pub(crate) policy: Option<String>,
    /// The `[tool.<name>.grammar]` tables this file sets, by tool name, kept apart from `table`.
    pub(crate) grammars: BTreeMap<String, Grammar>,
    /// The name of a tool pack's program input, which the load removes from `table`.
    pub(crate) program_input: Option<String>,
}

/// One tool grammar as its file holds it, which `box` copies into `box.toml` unchanged.
#[derive(Debug, Clone)]
pub(crate) struct Grammar {
    pub(crate) table: toml::Table,
    /// The file that holds it.
    pub(crate) path: PathBuf,
}

/// Why a file is refused, and the key the refusal is about.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) reason: String,
    pub(crate) at: Vec<String>,
}

impl Refusal {
    pub(crate) fn at(reason: String, at: &[&str]) -> Self {
        Self {
            reason,
            at: at.iter().map(|part| (*part).to_string()).collect(),
        }
    }

    /// The error for the file `path` with the text `text`, at the line of the key. A key that an
    /// agent pack or a tool pack writes at its top is found at its top.
    pub(crate) fn in_file(self, path: &Path, text: &str) -> Error {
        let line = line_of(text, &self.at).or_else(|| match self.at.as_slice() {
            [agent, rest @ ..] if agent == "agent" && !rest.is_empty() => line_of(text, rest),
            [tool, _, rest @ ..] if tool == "tool" && !rest.is_empty() => line_of(text, rest),
            [extends, ..] if extends == EXTEND || extends == INCLUDE => {
                line_of(text, &["pack".into(), extends.clone()])
            }
            _ => None,
        });
        Error::Profile {
            path: path.to_path_buf(),
            line,
            reason: self.reason,
        }
    }
}

impl From<String> for Refusal {
    fn from(reason: String) -> Self {
        Self {
            reason,
            at: Vec::new(),
        }
    }
}

impl From<&str> for Refusal {
    fn from(reason: &str) -> Self {
        reason.to_string().into()
    }
}

/// Where `packs` and `extend` find a profile pack.
#[derive(Debug, Clone)]
pub struct Lookup {
    pub vendored: Option<PathBuf>,
    pub operator: PathBuf,
    /// The collections in the box home's `external/`, in folder-name order.
    pub collections: Vec<Collection>,
    /// The version of `box` that a pack's `engine` floor is checked against.
    pub version: &'static str,
}

/// A folder of packs, plugins, starters, and policy starters in the box home's `external/`,
/// whose names start with `@<folder>/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    /// The folder name, which is the scope without `@` and `/`, such as `acme` for `@acme/<name>`.
    pub scope: String,
    /// The folder, `<box home>/external/<scope>`.
    pub root: PathBuf,
}

impl Lookup {
    /// The collection folder and short name of `name` when it is `@<scope>/<name>` for a scope
    /// other than `@box`, or `None` for any other name. An unknown scope is an error.
    pub fn in_collection<'a>(&self, name: &'a str) -> Option<Result<(&Path, &'a str), String>> {
        if name.starts_with(VENDORED) {
            return None;
        }
        let (scope, short) = name.strip_prefix('@')?.split_once('/')?;
        Some(
            match self
                .collections
                .iter()
                .find(|collection| collection.scope == scope)
            {
                Some(collection) => Ok((collection.root.as_path(), short)),
                None => Err(format!(
                    "{name:?} names the collection @{scope}, and {} does not exist; clone the \
                     collection's repository there",
                    self.external_folder().join(scope).display()
                )),
            },
        )
    }

    /// The folder that holds the collections: `external` beside the operator's packs.
    pub fn external_folder(&self) -> PathBuf {
        self.operator
            .parent()
            .map(|home| home.join("external"))
            .unwrap_or_else(|| PathBuf::from("external"))
    }

    /// The operator's `config.toml`: beside the operator's packs.
    pub fn config_file(&self) -> PathBuf {
        self.operator
            .parent()
            .map(|home| home.join("config.toml"))
            .unwrap_or_else(|| PathBuf::from("config.toml"))
    }
}

/// One MCP launcher's merged requirements and the pack files that supply them.
pub struct LauncherPack {
    pub name: String,
    pub(crate) merged: Merged,
    pub layers: Vec<Layer>,
}

impl Lookup {
    fn folder(&self, name: &str) -> Result<PathBuf, String> {
        let (root, short) = match (name.strip_prefix(VENDORED), self.in_collection(name)) {
            (Some(short), _) => (
                self.vendored
                    .clone()
                    .ok_or("box's own packs were not found; set BOX_RESOURCES")?,
                short,
            ),
            (None, Some(found)) => {
                let (collection, short) = found?;
                (collection.join(crate::profile::PACKS), short)
            }
            (None, None) => (self.operator.clone(), name),
        };
        if !is_pack_name(short) {
            let shipped = renamed(name).filter(|shipped| self.folder(shipped).is_ok());
            return Err(match shipped {
                Some(shipped) => {
                    format!("{name:?} is not a pack name; the pack that box ships is {shipped}")
                }
                None => format!("{name:?} is not a pack name"),
            });
        }
        let folder = root.join(short);
        if !folder.join(PACK_FILE).is_file() {
            return Err(format!(
                "the pack {name:?} does not exist: {} is missing",
                folder.join(PACK_FILE).display()
            ));
        }
        Ok(folder)
    }
}

/// The `@box/<name>` spelling of `name` when `name` is the `box/<name>` spelling that a shipped
/// pack or starter had before it took the `@box/` scope.
pub fn renamed(name: &str) -> Option<String> {
    name.strip_prefix("box/")
        .map(|short| format!("{VENDORED}{short}"))
}

/// Whether `short` is a pack's or a plugin's folder name.
pub(crate) fn is_pack_name(short: &str) -> bool {
    !short.is_empty()
        && !short.starts_with('.')
        && short
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl Lookup {
    /// The full name of `pack`: a short name is the operator's pack when it exists, else
    /// `@box/<pack>`.
    pub fn full_name(&self, pack: &str) -> Result<String, String> {
        if pack.contains('/') {
            if !pack.starts_with(VENDORED) {
                self.folder(pack)?;
            }
            return Ok(pack.to_string());
        }
        let vendored = format!("{VENDORED}{pack}");
        match (self.folder(pack), self.folder(&vendored)) {
            (Ok(_), _) => Ok(pack.to_string()),
            (Err(_), Ok(_)) => Ok(vendored),
            (Err(_), Err(shipped)) => match &self.vendored {
                Some(root) if is_pack_name(pack) => Err(format!(
                    "the pack {pack:?} does not exist: {} and {} are missing",
                    root.join(pack).join(PACK_FILE).display(),
                    self.operator.join(pack).join(PACK_FILE).display()
                )),
                _ => Err(shipped),
            },
        }
    }

    /// The `--with` entry that names `pack`: its short name, unless that names another pack.
    pub fn spelling(&self, pack: &str) -> String {
        let short = pack.strip_prefix(VENDORED).unwrap_or(pack);
        if self.full_name(short).is_ok_and(|full| full == pack) {
            short.to_string()
        } else {
            pack.to_string()
        }
    }

    /// Whether the pack `name` exists.
    pub(crate) fn has_pack(&self, name: &str) -> bool {
        self.folder(name).is_ok()
    }

    /// Whether `pack` is the operator's pack and a shipped pack has its name.
    pub fn shadows(&self, pack: &str) -> bool {
        !pack.contains('/') && self.folder(&format!("{VENDORED}{pack}")).is_ok()
    }

    /// Each tool pack that `box` ships, in name order.
    pub fn tool_packs(&self) -> Vec<String> {
        let Some(root) = &self.vendored else {
            return Vec::new();
        };
        let mut names: Vec<String> = std::fs::read_dir(root)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .map(|short| format!("{VENDORED}{short}"))
            .filter(|name| self.table(name).is_ok_and(|table| is_tool_pack(&table)))
            .collect();
        names.sort();
        names
    }

    /// The ordinary tool packs used by detected MCP launchers.
    pub fn launchers(&self) -> Result<BTreeMap<String, LauncherPack>, String> {
        let mut found = BTreeMap::new();
        for program in crate::mcp::LAUNCHERS {
            let name = format!("{VENDORED}{program}");
            let Ok(table) = self.table(&name) else {
                continue;
            };
            if table.get("program").and_then(toml::Value::as_str) != Some(*program) {
                continue;
            }
            let text = format!("packs = [{name:?}]\n[agent]\ncommand = []\n");
            let table = toml::from_str(&text).map_err(|error| format!("{error}"))?;
            let layers = chain(&table, &text, Path::new("MCP launcher"), None, self)
                .map_err(|error| error.to_string())?;
            let merged = merge(&layers).map_err(|error| error.to_string())?;
            found.insert(
                program.to_string(),
                LauncherPack {
                    name,
                    merged,
                    layers,
                },
            );
        }
        Ok(found)
    }

    /// The table of the pack `name`.
    pub fn table(&self, name: &str) -> Result<toml::Table, String> {
        let path = self.folder(name)?.join(PACK_FILE);
        let text = crate::files::read_regular(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let table =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        pack_layout(table, &text)
            .map(|(table, _)| table)
            .map_err(|refusal| refusal.in_file(&path, &text).to_string())
    }
}

pub(crate) fn imports_of(table: &toml::Table, key: &str) -> Result<Vec<String>, String> {
    let noun = if key == PLUGINS { "plugin" } else { "pack" };
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|name| !has_placeholder(name))
                    .map(str::to_string)
                    .ok_or_else(|| format!("`{key}` holds a value that is not a {noun} name"))
            })
            .collect(),
        Some(_) => Err(format!("`{key}` is not a list of {noun} names")),
    }
}

/// The profile and every pack it imports, bases first, each pack once.
pub fn chain(
    table: &toml::Table,
    text: &str,
    path: &Path,
    policy: Option<String>,
    lookup: &Lookup,
) -> Result<Vec<Layer>, Error> {
    let mut out = Vec::new();
    let mut stack = Vec::new();
    let mut seen = BTreeSet::new();
    visit(
        Layer {
            name: THE_PROFILE.to_string(),
            path: path.to_path_buf(),
            location: PackLocation::Other,
            shared: false,
            plugin: false,
            table: table.clone(),
            text: text.to_string(),
            grammar_text: None,
            policy,
            grammars: BTreeMap::new(),
            program_input: None,
        },
        lookup,
        &mut stack,
        &mut seen,
        &mut out,
    )?;
    Ok(out)
}

/// Read the pack file `path`, imported as `name`, and say where it was read from.
fn read_pack(path: &Path, name: &str, lookup: &Lookup) -> Result<(String, PackLocation), Error> {
    let bundled = lookup.vendored.as_deref().zip(name.strip_prefix(VENDORED));
    strands_box_cli_telemetry::read_pack(path, bundled).map_err(|source| Error::Io {
        action: "read",
        path: path.to_path_buf(),
        source,
    })
}

/// Each pack of a chain with its `[pack] version`, in the order `packs` and `extend` name them.
pub fn pack_versions(layers: &[Layer]) -> Vec<(String, String)> {
    fn walk<'a>(
        layer: &'a Layer,
        packs: &BTreeMap<&str, &'a Layer>,
        seen: &mut BTreeSet<String>,
        out: &mut Vec<(String, String)>,
    ) {
        let names = if layer.shared {
            imports_of(&layer.table, EXTEND)
                .unwrap_or_default()
                .into_iter()
                .chain(imports_of(&layer.table, INCLUDE).unwrap_or_default())
                .collect()
        } else {
            imports_of(&layer.table, "packs").unwrap_or_default()
        };
        for name in names {
            let Some(pack) = packs.get(name.as_str()).copied() else {
                continue;
            };
            if !seen.insert(name.clone()) {
                continue;
            }
            let version = pack
                .table
                .get("pack")
                .and_then(|header| header.get("version"))
                .and_then(toml::Value::as_integer)
                .map(|version| version.to_string())
                .unwrap_or_default();
            out.push((name, version));
            walk(pack, packs, seen, out);
        }
    }
    let packs: BTreeMap<&str, &Layer> = layers
        .iter()
        .filter(|layer| layer.shared)
        .map(|layer| (layer.name.as_str(), layer))
        .collect();
    let mut out = Vec::new();
    if let Some(profile) = layers.iter().find(|layer| !layer.shared) {
        walk(profile, &packs, &mut BTreeSet::new(), &mut out);
    }
    out
}

fn visit(
    mut layer: Layer,
    lookup: &Lookup,
    stack: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<Layer>,
) -> Result<(), Error> {
    let invalid = |path: &Path, reason: String| Error::Profile {
        path: path.to_path_buf(),
        line: None,
        reason,
    };
    let tool_pack = layer.shared && is_tool_pack(&layer.table);
    if tool_pack && layer.table.contains_key("grammar") {
        return Err(Refusal::at(
            format!("a tool pack writes its grammar in {GRAMMAR_FILE}, beside {PACK_FILE}"),
            &["grammar"],
        )
        .in_file(&layer.path, &layer.text));
    }
    check_kind(&mut layer, lookup.version)
        .map_err(|refusal| refusal.in_file(&layer.path, &layer.text))?;
    take_grammars(&mut layer, tool_pack)?;
    let key = if layer.shared { EXTEND } else { "packs" };
    let bases = imports_of(&layer.table, key).map_err(|reason| invalid(&layer.path, reason))?;
    let included = if layer.shared {
        imports_of(&layer.table, INCLUDE).map_err(|reason| invalid(&layer.path, reason))?
    } else {
        Vec::new()
    };
    stack.push(layer.name.clone());
    for base in bases.iter().chain(&included).cloned() {
        if stack.contains(&base) {
            return Err(invalid(
                &layer.path,
                format!("`{key}` names {base:?}, which imports this pack"),
            ));
        }
        if !seen.insert(base.clone()) {
            continue;
        }
        let named_by = if bases.contains(&base) { key } else { INCLUDE };
        let folder = lookup.folder(&base).map_err(|reason| {
            invalid(
                &layer.path,
                plugin::named_as_pack(lookup, named_by, &base).unwrap_or(reason),
            )
        })?;
        let path = folder.join(PACK_FILE);
        let (text, location) = read_pack(&path, &base, lookup)?;
        let table: toml::Table =
            toml::from_str(&text).map_err(|error| invalid(&path, error.to_string()))?;
        let (table, program_input) =
            pack_layout(table, &text).map_err(|refusal| refusal.in_file(&path, &text))?;
        let policy = None;
        visit(
            Layer {
                name: base,
                path,
                location,
                shared: true,
                plugin: false,
                table,
                text,
                grammar_text: None,
                policy,
                grammars: BTreeMap::new(),
                program_input,
            },
            lookup,
            stack,
            seen,
            out,
        )?;
    }
    stack.pop();
    if layer.shared {
        check_kind_of_bases(&layer, tool_pack, &bases, &included, out)
            .map_err(|refusal| refusal.in_file(&layer.path, &layer.text))?;
    } else {
        let plugins =
            imports_of(&layer.table, PLUGINS).map_err(|reason| invalid(&layer.path, reason))?;
        let mut listed = BTreeSet::new();
        for name in plugins {
            if listed.insert(name.clone()) {
                out.push(plugin::load(&name, lookup, &layer.path)?);
            }
        }
    }
    bind_pack(&mut layer)?;
    out.push(layer);
    Ok(())
}

/// `layer` with `${{ pack }}` bound to the real folder of its file.
pub(crate) fn bind_pack(layer: &mut Layer) -> Result<(), Error> {
    let folder = layer
        .path
        .parent()
        .map(|folder| canonical(folder).unwrap_or_else(|| folder.to_path_buf()))
        .unwrap_or_default();
    let folder = utf8(&folder)?;
    let mut value = toml::Value::Table(std::mem::take(&mut layer.table));
    let bound = each_string(&mut value, &mut |text| bind(text, "pack", &folder));
    if let toml::Value::Table(table) = value {
        layer.table = table;
    }
    bound.map_err(|reason| Error::Profile {
        path: layer.path.clone(),
        line: None,
        reason,
    })
}

/// The keys of a pack's `[mcp.<name>]` table.
const PACK_ADDITION_KEYS: &[&str] = &["filesystem", "network"];

/// Refuse a pack's `[mcp]` table unless each `[mcp.<name>]` holds only the grants that it adds to a
/// server that the run finds.
fn check_pack_additions(table: &toml::Table) -> Result<(), Refusal> {
    let Some(mcp) = table.get("mcp") else {
        return Ok(());
    };
    let declares = "a pack declares no MCP server; it names its agent's MCP configuration in \
                    `[[mcp-servers]]`, and `[mcp.<name>]` with a `type` belongs in a profile";
    let Some(entries) = mcp.as_table() else {
        return Err(Refusal::at(declares.to_string(), &["mcp"]));
    };
    for (name, entry) in entries {
        let Some(entry) = entry.as_table() else {
            return Err(Refusal::at(declares.to_string(), &["mcp", name]));
        };
        let refused = match entry.contains_key("type") {
            true => Some("type"),
            false => entry
                .keys()
                .map(String::as_str)
                .find(|key| !PACK_ADDITION_KEYS.contains(key)),
        };
        if let Some(key) = refused {
            return Err(Refusal::at(
                format!(
                    "{declares}; a pack's `[mcp.{name}]` adds to a server this run finds, and \
                     holds only `filesystem` and `network`, not `{key}`"
                ),
                &["mcp", name, key],
            ));
        }
        for section in PACK_ADDITION_KEYS {
            if entry
                .get(*section)
                .and_then(toml::Value::as_table)
                .is_some_and(|table| table.contains_key("when"))
            {
                return Err(Refusal::at(
                    format!(
                        "a pack's `[mcp.{name}.{section}]` takes no `when`, because the merged \
                         table would drop the profile's own keys too; put `when` on one \
                         filesystem entry"
                    ),
                    &["mcp", name, section, "when"],
                ));
            }
        }
    }
    Ok(())
}

/// The longest Shell timeout a profile sets, one year in seconds.
const LONGEST_SHELL_TIMEOUT: i64 = 365 * 24 * 60 * 60;

/// Refuse a `[limits]` table that holds a key other than `shell.timeout`, set to whole seconds from
/// one second to one year or to `false`, `shell.max_input` and `shell.max_output`, set to a number
/// of bytes or to `0` for no limit, or `shell.max_stdin`, set to a positive number of bytes.
fn check_limits(table: &toml::Table) -> Result<(), Refusal> {
    let Some(limits) = table.get(LIMITS) else {
        return Ok(());
    };
    let shape = |at: &[&str]| {
        Refusal::at(
            format!(
                "`[{LIMITS}]` holds only `shell.timeout`, `shell.max_input`, `shell.max_stdin`, \
                 and `shell.max_output`"
            ),
            at,
        )
    };
    let shell = match limits {
        toml::Value::Table(limits) => limits.get("shell"),
        _ => return Err(shape(&[LIMITS])),
    };
    refuse_unknown_keys(table, &[LIMITS], &["shell"])?;
    match shell {
        None | Some(toml::Value::Table(_)) => {}
        Some(_) => return Err(shape(&[LIMITS, "shell"])),
    }
    refuse_unknown_keys(
        table,
        &[LIMITS, "shell"],
        &["timeout", "max_input", "max_stdin", "max_output"],
    )?;
    match shell.and_then(|shell| shell.get("timeout")) {
        None | Some(toml::Value::Boolean(false)) => {}
        Some(toml::Value::Integer(seconds)) if (1..=LONGEST_SHELL_TIMEOUT).contains(seconds) => {}
        Some(_) => {
            return Err(Refusal::at(
                format!(
                    "`{LIMITS}.shell.timeout` is a whole number of seconds from 1 to \
                     {LONGEST_SHELL_TIMEOUT} (one year), or `false` for no limit"
                ),
                &[LIMITS, "shell", "timeout"],
            ));
        }
    }
    for key in ["max_input", "max_output"] {
        match shell.and_then(|shell| shell.get(key)) {
            None => {}
            Some(toml::Value::Integer(bytes)) if usize::try_from(*bytes).is_ok() => {}
            Some(_) => {
                return Err(Refusal::at(
                    format!(
                        "`{LIMITS}.shell.{key}` is a whole number of bytes, such as 1048576, or `0` \
                         for no limit"
                    ),
                    &[LIMITS, "shell", key],
                ));
            }
        }
    }
    match shell.and_then(|shell| shell.get("max_stdin")) {
        None => Ok(()),
        Some(toml::Value::Integer(bytes))
            if usize::try_from(*bytes).is_ok_and(|bytes| bytes >= 1) =>
        {
            Ok(())
        }
        Some(_) => Err(Refusal::at(
            format!(
                "`{LIMITS}.shell.max_stdin` is a whole number of bytes from 1, such as 1048576; \
                 it cannot be turned off"
            ),
            &[LIMITS, "shell", "max_stdin"],
        )),
    }
}

/// Refuse an experimental feature other than the boolean native filesystem policy switch.
fn check_experimental_features(table: &toml::Table) -> Result<(), Refusal> {
    let Some(value) = table.get(EXPERIMENTAL_FEATURES) else {
        return Ok(());
    };
    let Some(features) = value.as_table() else {
        return Err(Refusal::at(
            format!("`[{EXPERIMENTAL_FEATURES}]` is a table"),
            &[EXPERIMENTAL_FEATURES],
        ));
    };
    refuse_unknown_keys(
        table,
        &[EXPERIMENTAL_FEATURES],
        &[NATIVE_FILESYSTEM_POLICY, "when"],
    )?;
    if let Some(value) = features.get(NATIVE_FILESYSTEM_POLICY)
        && !unwrapped(value).is_bool()
    {
        return Err(Refusal::at(
            format!("`{EXPERIMENTAL_FEATURES}.{NATIVE_FILESYSTEM_POLICY}` is `true` or `false`"),
            &[EXPERIMENTAL_FEATURES, NATIVE_FILESYSTEM_POLICY],
        ));
    }
    Ok(())
}

/// Refuse a `[project]` table that holds a key other than `access`, or an `access` other than
/// `"none"`, `"read"`, or `"write"`.
fn check_project(table: &toml::Table) -> Result<(), Refusal> {
    let Some(project) = table.get(PROJECT) else {
        return Ok(());
    };
    let values = crate::profile::ProjectAccess::VALUES
        .map(|value| format!("{value:?}"))
        .join(", ");
    let toml::Value::Table(project) = project else {
        return Err(Refusal::at(
            format!("`[{PROJECT}]` is a table with `access`, one of {values}"),
            &[PROJECT],
        ));
    };
    refuse_unknown_keys(table, &[PROJECT], &["access"])?;
    match project.get("access") {
        Some(toml::Value::String(value))
            if crate::profile::ProjectAccess::parse(value).is_some() =>
        {
            Ok(())
        }
        Some(_) => Err(Refusal::at(
            format!("`{PROJECT}.access` is one of {values}"),
            &[PROJECT, "access"],
        )),
        None => Err(Refusal::at(
            format!("`[{PROJECT}]` needs `access`, one of {values}"),
            &[PROJECT],
        )),
    }
}

/// Refuse a profile's `[filesystem]` that is not a table, or that holds a key other than `deny`,
/// `deny_write`, and `when`. A per-process list is sent to the tables that take it.
fn check_profile_filesystem(table: &toml::Table) -> Result<(), Refusal> {
    let Some(filesystem) = table.get(PROFILE_FILESYSTEM) else {
        return Ok(());
    };
    let Some(filesystem) = filesystem.as_table() else {
        return Err(Refusal::at(
            format!(
                "`[{PROFILE_FILESYSTEM}]` is a table with `deny` and `deny_write`, lists of paths"
            ),
            &[PROFILE_FILESYSTEM],
        ));
    };
    let Some(key) = filesystem.keys().find(|key| {
        FILESYSTEM_LISTS.contains(&key.as_str()) && !PROFILE_LISTS.contains(&key.as_str())
    }) else {
        return refuse_unknown_keys(
            table,
            &[PROFILE_FILESYSTEM],
            &["deny", "deny_write", "when"],
        );
    };
    let tables = if matches!(key.as_str(), "exec" | "metadata") {
        "`[agent.filesystem]`".to_string()
    } else {
        "`[agent.filesystem]` or a `[tool.<name>.filesystem]` table".to_string()
    };
    Err(Refusal::at(
        format!(
            "a profile's `[{PROFILE_FILESYSTEM}]` holds only `deny` and `deny_write`, for every \
             process; write `{key}` in {tables}"
        ),
        &[PROFILE_FILESYSTEM, key],
    ))
}

/// The `enabled` of the `[banner]` table in `table`, or `None` when it sets none. Refuses a
/// `[banner]` that holds another key, or an `enabled` that is not `true` or `false`.
pub(crate) fn read_banner(table: &toml::Table) -> Result<Option<bool>, Refusal> {
    let Some(banner) = table.get(BANNER) else {
        return Ok(None);
    };
    if !banner.is_table() {
        return Err(Refusal::at(
            format!("`[{BANNER}]` is a table with `enabled`, `true` or `false`"),
            &[BANNER],
        ));
    }
    refuse_unknown_keys(table, &[BANNER], &["enabled"])?;
    match banner.get("enabled") {
        None => Ok(None),
        Some(toml::Value::Boolean(enabled)) => Ok(Some(*enabled)),
        Some(_) => Err(Refusal::at(
            format!("`{BANNER}.enabled` is `true` or `false`"),
            &[BANNER, "enabled"],
        )),
    }
}

/// The `[banner] enabled` of a file such as `~/.strands/box/config.toml`, or the reason it is refused.
pub fn banner_enabled(table: &toml::Table) -> Result<Option<bool>, String> {
    read_banner(table).map_err(|refusal| refusal.reason)
}

/// Move each `[tool.<name>.grammar]` of `layer`, and the `grammar.toml` beside a tool pack, out of
/// its table into `layer.grammars`.
fn take_grammars(layer: &mut Layer, tool_pack: bool) -> Result<(), Error> {
    let invalid = |path: &Path, reason: String| Error::Profile {
        path: path.to_path_buf(),
        line: None,
        reason,
    };
    if let Some(toml::Value::Table(tools)) = layer.table.get_mut("tool") {
        for (name, tool) in tools.iter_mut() {
            let Some(tool) = tool.as_table_mut() else {
                continue;
            };
            match tool.remove("grammar") {
                None => {}
                Some(toml::Value::Table(table)) => {
                    layer.grammars.insert(
                        name.clone(),
                        Grammar {
                            table,
                            path: layer.path.clone(),
                        },
                    );
                }
                Some(_) => {
                    return Err(Refusal::at(
                        format!("`[tool.{name}] grammar` is a table"),
                        &["tool", name, "grammar"],
                    )
                    .in_file(&layer.path, &layer.text));
                }
            }
        }
    }
    if !layer.shared {
        return Ok(());
    }
    let path = layer.path.with_file_name(GRAMMAR_FILE);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        _ => {}
    }
    let tool = layer
        .name
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string();
    if !tool_pack {
        return Err(invalid(
            &path,
            format!(
                "{} is not a tool pack, so it takes no {GRAMMAR_FILE}; a grammar goes beside the \
                 `pack.toml` of a tool pack",
                layer.name
            ),
        ));
    }
    let text = read(&path)?;
    let table = toml::from_str(&text).map_err(|error| invalid(&path, error.to_string()))?;
    layer.grammars.insert(tool, Grammar { table, path });
    layer.grammar_text = Some(text);
    Ok(())
}

/// Refuse a key that belongs to the other kind of file or to neither, write a tool pack as its tool
/// table, and check a pack's header against the `box` version `version`.
fn check_kind(layer: &mut Layer, version: &str) -> Result<(), Refusal> {
    let refused: &[&str] = if layer.shared {
        &[
            "packs",
            PLUGINS,
            "options",
            "policies",
            AGENT_ARGS,
            FILE_ATTRIBUTES,
            LIMITS,
            PROJECT,
            BANNER,
        ]
    } else {
        &[EXTEND, INCLUDE, "inputs", "pack", MCP_SERVERS]
    };
    if layer.shared && !is_tool_pack(&layer.table) {
        check_pack_additions(&layer.table)?;
    }
    if let Some(key) = refused.iter().find(|key| layer.table.contains_key(**key)) {
        let reason = if layer.shared {
            format!("a pack holds no `{key}`; `{key}` belongs in a profile")
        } else {
            format!("a profile holds no `{key}`; `{key}` belongs in a pack")
        };
        return Err(Refusal::at(reason, &[key]));
    }
    if layer.shared && layer.table.contains_key(SECRET_SOURCE) {
        return Err(Refusal::at(
            format!(
                "{} is a pack, and a pack declares no secret source; a plugin declares one, \
                 and a profile lists the plugin in `{PLUGINS}`",
                layer.name
            ),
            &[SECRET_SOURCE],
        ));
    }
    if layer.shared {
        let kind = if is_tool_pack(&layer.table) {
            "tool pack"
        } else {
            "pack"
        };
        if let Some(refusal) = crate::profile::run_key(&layer.table, kind) {
            return Err(refusal);
        }
    }
    if layer.shared && is_tool_pack(&layer.table) {
        lift_tool_pack(layer)?;
    } else {
        if layer.shared && is_agent_pack(&layer.table) {
            lift_agent_pack(&mut layer.table)?;
        }
        refuse_root(&layer.table)?;
    }
    if !layer.shared
        && let Some(key) = PROCESS_KEYS
            .iter()
            .filter(|key| **key != PROFILE_FILESYSTEM)
            .find(|key| layer.table.contains_key(**key))
    {
        let reason = if *key == NATIVE_FILESYSTEM_POLICY {
            format!(
                "a profile holds no top-level `{key}`; write it in `[experimental-features]` to \
                 select it for every process, or in `[agent]` / `[tool.<name>]` to override one process"
            )
        } else {
            format!(
                "a profile holds no top-level `{key}`; write it in `[agent]` or in a \
                 `[tool.<name>]` table"
            )
        };
        return Err(Refusal::at(reason, &[key]));
    }
    if !layer.shared
        && let Some(key) = TOOL_KEYS.iter().find(|key| layer.table.contains_key(**key))
    {
        return Err(Refusal::at(
            format!(
                "a profile holds no top-level `{key}`; write `{key}` in a `[tool.<name>]` table"
            ),
            &[key],
        ));
    }
    check_slots(&layer.table)?;
    check_programs(&layer.table)?;
    check_secrets(&layer.table)?;
    check_agent_args(&layer.table)?;
    let (kind, own): (&str, &[&str]) = if layer.shared {
        (
            "pack",
            &["pack", EXTEND, INCLUDE, "inputs", "storage", MCP_SERVERS],
        )
    } else {
        (
            "profile",
            &[
                "packs",
                "options",
                AGENT_ARGS,
                FILE_ATTRIBUTES,
                LIMITS,
                EXPERIMENTAL_FEATURES,
                PROJECT,
                PROFILE_FILESYSTEM,
                BANNER,
                "storage",
                "policies",
                PROFILE_HEADER,
                PLUGINS,
                SECRET_SOURCE,
            ],
        )
    };
    if let Some(value) = layer.table.get(FILE_ATTRIBUTES)
        && !value.is_bool()
    {
        return Err(Refusal::at(
            format!("`{FILE_ATTRIBUTES}` is `true` or `false`"),
            &[FILE_ATTRIBUTES],
        ));
    }
    check_limits(&layer.table)?;
    check_experimental_features(&layer.table)?;
    check_project(&layer.table)?;
    if !layer.shared {
        check_profile_filesystem(&layer.table)?;
    }
    let known: Vec<&str> = own.iter().chain(BOX_KEYS).copied().collect();
    if let Some(key) = layer
        .table
        .keys()
        .find(|key| !known.contains(&key.as_str()))
    {
        return Err(Refusal::at(
            unknown_key(&format!("a {kind}"), key, &known),
            &[key],
        ));
    }
    refuse_unknown_keys(&layer.table, &[PROFILE_HEADER], &["name"])?;
    refuse_unknown_keys(&layer.table, &["storage"], STORAGE_KEYS)?;
    refuse_unknown_keys(&layer.table, &["agent"], AGENT_KEYS)?;
    refuse_unknown_keys(&layer.table, &["agent", "filesystem"], FILESYSTEM_KEYS)?;
    if let Some(toml::Value::Table(tools)) = layer.table.get("tool") {
        for name in tools.keys() {
            refuse_unknown_keys_except(
                &layer.table,
                &["tool", name],
                TOOL_TABLE_KEYS,
                TOOL_TABLE_REFUSED_IN_TOOL,
            )?;
            refuse_unknown_keys(&layer.table, &["tool", name, "filesystem"], FILESYSTEM_KEYS)?;
            if layer.shared && tools[name].get(TOOL_NETWORK).is_some() {
                return Err(Refusal::at(
                    format!(
                        "a pack holds no `[tool.{name}.{TOOL_NETWORK}]`; {NETWORK_IS_THE_PROFILES}"
                    ),
                    &["tool", name, TOOL_NETWORK],
                ));
            }
            if tools[name]
                .get(TOOL_NETWORK)
                .and_then(toml::Value::as_table)
                .is_some_and(|network| network.contains_key("when"))
            {
                return Err(Refusal::at(
                    format!(
                        "`[tool.{name}.{TOOL_NETWORK}]` takes no `when`; put it on the value, as \
                         `contain_egress = {{ value = false, when = \"...\" }}`"
                    ),
                    &["tool", name, TOOL_NETWORK, "when"],
                ));
            }
            refuse_unknown_keys(&layer.table, &["tool", name, TOOL_NETWORK], NETWORK_KEYS)?;
        }
    }
    if !layer.shared {
        return plugin::check_sources(&layer.table);
    }
    let header = layer
        .table
        .get("pack")
        .and_then(toml::Value::as_table)
        .ok_or("a pack needs a `[pack]` header with `name` and `version`")?;
    check_header(header, "pack", &layer.name, version)
}

/// Refuse a `[pack]` or `[plugin]` header `header`, named `section`, that holds an unknown key,
/// lacks `name` or `version`, names another file than `imported_as`, or needs a later `box` than
/// `version`.
pub(crate) fn check_header(
    header: &toml::Table,
    section: &str,
    imported_as: &str,
    version: &str,
) -> Result<(), Refusal> {
    let known = if section == plugin::HEADER {
        plugin::HEADER_KEYS
    } else {
        HEADER_KEYS
    };
    if let Some(key) = header.keys().find(|key| !known.contains(&key.as_str())) {
        return Err(Refusal::at(
            unknown_key(&format!("`[{section}]`"), key, known),
            &[section, key],
        ));
    }
    let owner = format!("[{section}]");
    if string_field(header, "name", &owner)?.is_none() {
        return Err(format!("`[{section}]` needs `name`").into());
    }
    match header.get("version") {
        None => return Err(format!("`[{section}]` needs `version`").into()),
        Some(toml::Value::Integer(version)) if *version >= 0 => {}
        Some(_) => {
            return Err(Refusal::at(
                format!("`[{section}] version` is a whole number, such as 1"),
                &[section, "version"],
            ));
        }
    }
    let listed = if section == plugin::HEADER {
        "listed"
    } else {
        "imported"
    };
    if let Some(name) = string_field(header, "name", &owner)?
        && name != imported_as
    {
        return Err(Refusal::at(
            format!(
                "`[{section}] name = {name:?}`, but this {section} is {listed} as {imported_as:?}"
            ),
            &[section, "name"],
        ));
    }
    if let Some(requirement) = string_field(header, "engine", &owner)? {
        let needed = floor(&requirement)?;
        let this = release_of(version).unwrap_or_default();
        if this < needed {
            return Err(Refusal::at(
                format!("this {section} needs box {requirement}, and this is box {version}"),
                &[section, "engine"],
            ));
        }
    }
    Ok(())
}

/// The `[pack] kind` line for a test pack's body: none when the body states `kind` itself, as a
/// tool pack's does; `[run] command` or an `extend` of a test agent pack makes an agent pack, and
/// any other pack is a support pack.
#[cfg(any(test, feature = "test-support"))]
pub fn test_kind_line(body: &str) -> String {
    const TEST_AGENTS: &[&str] = &["claude", "codex", "kiro", "pi", "agent"];
    let table: toml::Table = toml::from_str(body).unwrap_or_default();
    if table.contains_key("kind") {
        return String::new();
    }
    let extends_agent = imports_of(&table, EXTEND)
        .unwrap_or_default()
        .iter()
        .any(|base| TEST_AGENTS.contains(&base.rsplit('/').next().unwrap_or_default()));
    let run = table.get(RUN);
    let kind = if run.is_some_and(|run| run.get("command").is_some()) || extends_agent {
        AGENT_KIND
    } else {
        SUPPORT_KIND
    };
    format!("kind = {kind:?}\n")
}

/// The body of a test tool pack for the program `program`, after its header: its kind, the input
/// that finds the program on `PATH`, `[run] command`, and `rest`.
#[cfg(any(test, feature = "test-support"))]
pub fn test_tool_pack(program: &str, rest: &str) -> String {
    format!(
        "kind = \"tool\"\n[inputs.{program}.path]\ntype = \"program\"\nprogram = {program:?}\n\
         search = [{{ env = \"PATH\" }}]\n[run]\ncommand = [\"${{{{ inputs.{program}.path }}}}\"]\n{rest}"
    )
}

/// The `[pack] kind` of a pack's table.
fn pack_kind(table: &toml::Table) -> Option<&str> {
    table
        .get("pack")
        .and_then(|header| header.get("kind"))
        .and_then(toml::Value::as_str)
}

/// Refuse a pack whose `[pack] kind` does not agree with the packs it extends: a pack that extends
/// an agent pack is an agent pack, an agent pack holds `[run] command` or extends one that does,
/// and no other pack extends an agent pack.
fn check_kind_of_bases(
    layer: &Layer,
    tool: bool,
    bases: &[String],
    included: &[String],
    out: &[Layer],
) -> Result<(), Refusal> {
    let kind_of = |name: &str| {
        out.iter()
            .find(|base| base.name == name)
            .and_then(|base| pack_kind(&base.table))
    };
    if let Some(base) = included
        .iter()
        .find(|base| kind_of(base) != Some(TOOL_KIND))
    {
        return Err(Refusal::at(
            format!(
                "`include` names tool packs, and {base} is not one; name it in `extend` to \
                 build on it"
            ),
            &[INCLUDE],
        ));
    }
    if pack_kind(&layer.table) == Some(SUPPORT_KIND)
        && let Some(base) = bases.iter().find(|base| kind_of(base) == Some(TOOL_KIND))
    {
        return Err(Refusal::at(
            format!(
                "a support pack extends only support packs, and {base} is a tool pack; name it \
                 in `include` to add to its tool"
            ),
            &[EXTEND],
        ));
    }
    if pack_kind(&layer.table) == Some(AGENT_KIND)
        && let Some(base) = bases.iter().find(|base| kind_of(base) == Some(TOOL_KIND))
    {
        return Err(Refusal::at(
            format!(
                "an agent pack cannot extend the tool pack {base}; name it in `include` to run \
                 it as a tool of its own"
            ),
            &[EXTEND],
        ));
    }
    let agent_base = bases.iter().find(|base| kind_of(base) == Some(AGENT_KIND));
    if tool && let Some(base) = agent_base {
        return Err(Refusal::at(
            format!(
                "a tool pack cannot extend the agent pack {base}; remove it from `extend`, or \
                 write the tool in a `[tool.<name>]` table of an agent pack"
            ),
            &[EXTEND],
        ));
    }
    let Some(kind) = pack_kind(&layer.table) else {
        return Ok(());
    };
    match (kind, agent_base) {
        (AGENT_KIND, None) if !is_agent(&layer.table) => Err(Refusal::at(
            "`[pack] kind = \"agent\"`, but neither this pack nor a pack it extends holds \
             `[run] command`"
                .into(),
            &["pack", "kind"],
        )),
        (AGENT_KIND, _) => Ok(()),
        (_, Some(base)) => Err(Refusal::at(
            format!(
                "`[pack] kind = {kind:?}`, but the pack extends the agent pack {base}; write \
                 kind = \"agent\""
            ),
            &["pack", "kind"],
        )),
        _ => Ok(()),
    }
}

/// Refuse a profile whose agent packs do not have one head: two packs that each declare
/// `[agent] command` when neither extends the other, or two agent packs that no agent pack of the
/// profile extends. So a profile runs one agent, and names it by one pack.
fn refuse_two_agents(layers: &[Layer]) -> Result<(), String> {
    let packs: Vec<&Layer> = layers.iter().filter(|layer| layer.shared).collect();
    let bases = |name: &str| -> Vec<String> {
        packs
            .iter()
            .find(|layer| layer.name == name)
            .map(|layer| imports_of(&layer.table, EXTEND).unwrap_or_default())
            .unwrap_or_default()
    };
    let extends = |from: &str, to: &str| -> bool {
        let mut next = bases(from);
        let mut seen = Vec::new();
        while let Some(pack) = next.pop() {
            if pack == to {
                return true;
            }
            if !seen.contains(&pack) {
                next.extend(bases(&pack));
                seen.push(pack);
            }
        }
        false
    };
    let mut agents: Vec<&Layer> = Vec::new();
    for layer in packs.iter().filter(|layer| is_agent(&layer.table)) {
        if !agents.iter().any(|seen| seen.path == layer.path) {
            agents.push(layer);
        }
    }
    for (index, first) in agents.iter().enumerate() {
        for second in &agents[index + 1..] {
            if !extends(&first.name, &second.name) && !extends(&second.name, &first.name) {
                return Err(format!(
                    "the profile has two agent packs, {} and {}; keep one",
                    first.name, second.name
                ));
            }
        }
    }
    let mut kinds: Vec<&Layer> = Vec::new();
    for layer in packs
        .iter()
        .filter(|layer| pack_kind(&layer.table) == Some(AGENT_KIND))
    {
        if !kinds.iter().any(|seen| seen.path == layer.path) {
            kinds.push(layer);
        }
    }
    let heads: Vec<&&Layer> = kinds
        .iter()
        .filter(|head| {
            !kinds
                .iter()
                .any(|other| other.name != head.name && extends(&other.name, &head.name))
        })
        .collect();
    if let [first, second, ..] = heads.as_slice() {
        return Err(format!(
            "the profile has two agent packs, {} and {}; keep one, or name a pack that extends \
             both",
            first.name, second.name
        ));
    }
    Ok(())
}

/// Refuse a key of the table at `at` in `table` that is not one of `known`.
fn refuse_unknown_keys(table: &toml::Table, at: &[&str], known: &[&str]) -> Result<(), Refusal> {
    refuse_unknown_keys_except(table, at, known, &[])
}

/// Refuse a key of the table at `at` in `table` that is neither one of `known` nor one of `later`.
fn refuse_unknown_keys_except(
    table: &toml::Table,
    at: &[&str],
    known: &[&str],
    later: &[&str],
) -> Result<(), Refusal> {
    let mut section = table;
    for part in at {
        match section.get(*part) {
            Some(toml::Value::Table(inner)) => section = inner,
            _ => return Ok(()),
        }
    }
    let Some(key) = section
        .keys()
        .find(|key| !known.contains(&key.as_str()) && !later.contains(&key.as_str()))
    else {
        return Ok(());
    };
    let owner = format!("`[{}]`", at.join("."));
    let mut path = at.to_vec();
    path.push(key);
    Err(Refusal::at(unknown_key(&owner, key, known), &path))
}

/// Refuse `${{ root }}` outside `[agent]` in a file that is not a tool pack, whatever `when` governs it.
fn refuse_root(table: &toml::Table) -> Result<(), String> {
    let mut outside: toml::Table = table.clone();
    outside.remove("agent");
    let mut value = toml::Value::Table(outside);
    each_string(&mut value, &mut |text| {
        if pieces(text)
            .unwrap_or_default()
            .iter()
            .any(|piece| matches!(piece, Piece::Name(name) if is_root_name(name)))
        {
            return Err(format!(
                "{text:?} names `root`, which is valid only in a tool pack or an `[agent]` table; \
                 for a tool elsewhere, use `tool.<name>.root`"
            ));
        }
        Ok(text.to_string())
    })
}

/// Whether `name` is `root`, with or without steps such as `root.parent`.
fn is_root_name(name: &str) -> bool {
    name == "root" || name.starts_with("root.")
}

/// `folder` after each step in `steps`, such as `parent.parent`, for the placeholder `name` that
/// the steps follow.
fn climb(folder: &Path, steps: &str, name: &str) -> Result<PathBuf, String> {
    let mut folder = folder.to_path_buf();
    for step in steps.split('.').filter(|step| !step.is_empty()) {
        match step {
            "parent" => {
                if let Some(parent) = folder.parent() {
                    folder = parent.to_path_buf();
                }
            }
            other => {
                return Err(format!("`{other}` is not a step of `{name}`; use `parent`"));
            }
        }
    }
    Ok(folder)
}

/// The value of `workspace` followed by `rest`: `dashed`, or steps such as `parent.parent`.
pub fn workspace_value(workspace: &Path, rest: &str) -> Result<String, String> {
    let text = |path: &Path| utf8(path).map_err(|error| error.to_string());
    if rest == "dashed" {
        return text(workspace).map(|path| dashed(&path));
    }
    if rest.split('.').any(|step| step == "dashed") {
        return Err(format!(
            "`workspace.{rest}`: `dashed` comes only right after `workspace`, as \
             `workspace.dashed`"
        ));
    }
    text(&climb(workspace, rest, "workspace")?)
}

/// Write the tool pack of `layer` as the full form: its keys, except the header, `extend`, and
/// `inputs`, move into `[tool.<name>]`, where `<name>` is the last part of the pack name, and
/// `${{ root }}` and each `${{ root.<steps> }}` become `${{ tool.<name>.root }}` with the same steps.
fn lift_tool_pack(layer: &mut Layer) -> Result<(), String> {
    let name = layer
        .name
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string();
    if !crate::tool::is_tool_name(&name) {
        return Err(format!(
            "the tool pack {:?} writes `[tool.{name}]`, so the last part of its name is letters, \
             digits, `_`, and `-`",
            layer.name
        ));
    }
    let table = &layer.table;
    if table.contains_key("command") {
        return Err("a tool pack holds no `command`; box writes the command from `program`".into());
    }
    if let Some(key) = NOT_IN_A_TOOL_PACK
        .iter()
        .find(|key| table.contains_key(**key))
    {
        return Err(format!(
            "a tool pack writes one tool; put `[{key}]` in another pack"
        ));
    }
    let target = format!("tool.{name}.");
    let mut value = toml::Value::Table(std::mem::take(&mut layer.table));
    each_string(&mut value, &mut |text| {
        Ok(pieces(text)?
            .into_iter()
            .map(|piece| match piece {
                Piece::Text(text) => text.replace(OPEN, "$${{"),
                Piece::Name(found) if is_root_name(&found) => format!("${{{{ {target}{found} }}}}"),
                Piece::Name(other) => format!("${{{{ {other} }}}}"),
            })
            .collect())
    })?;
    let toml::Value::Table(table) = value else {
        unreachable!("a table stays a table");
    };
    let (mut top, tool): (toml::Table, toml::Table) = table
        .into_iter()
        .partition(|(key, _)| TOOL_PACK_TOP.contains(&key.as_str()));
    top.insert(
        "tool".into(),
        toml::Value::Table(toml::Table::from_iter([(name, toml::Value::Table(tool))])),
    );
    layer.table = top;
    Ok(())
}

/// `value`, or its `value` when it is written as `{ value, when }`.
pub(crate) fn unwrapped(value: &toml::Value) -> &toml::Value {
    match value.get("when").and(value.get("value")) {
        Some(inner) => inner,
        None => value,
    }
}

/// `value`, or its `value` when it is written as `{ value, when }`.
fn unwrapped_mut(value: &mut toml::Value) -> &mut toml::Value {
    if value.get("when").is_some() && value.get("value").is_some() {
        return value.get_mut("value").expect("a value");
    }
    value
}

/// Refuse an `agent-args` that is not a list of strings.
fn check_agent_args(table: &toml::Table) -> Result<(), String> {
    let name = AGENT_ARGS;
    let items = match table.get(name) {
        None => return Ok(()),
        Some(toml::Value::Array(items)) => items,
        Some(_) => return Err(format!("`{name}` is a list of arguments")),
    };
    match items.iter().position(|item| !item.is_str()) {
        Some(index) => Err(format!(
            "`{name}` element {index} is not a string; a profile is one configuration, \
             so `{name}` holds the arguments it uses and no `{{ value, when }}`"
        )),
        None => Ok(()),
    }
}

/// The merged `table` with the slot of `[agent] command` replaced by a bare marker, followed by
/// the slot's `default` when the profile sets no `agent-args`. `fill_slot` finds the marker once
/// `when` has run, so a refusal names the `agent-args` element.
fn place_slot(table: &mut toml::Table) -> Result<(), String> {
    let name = AGENT_ARGS;
    let given = table.contains_key(name);
    let command = table
        .get_mut("agent")
        .map(unwrapped_mut)
        .and_then(|agent| agent.get_mut("command"))
        .map(unwrapped_mut);
    let Some(toml::Value::Array(command)) = command else {
        return match given {
            true => Err(format!(
                "`{name}` fills a `{{ slot = \"{name}\" }}` in `[agent] command`, and nothing \
                 sets a command"
            )),
            false => Ok(()),
        };
    };
    let Some(index) = command.iter().position(|item| item.get(SLOT).is_some()) else {
        return match given {
            true => Err(format!(
                "`{name}` is set, and `[agent] command` has no `{{ slot = \"{name}\" }}` to put \
                 it in"
            )),
            false => Ok(()),
        };
    };
    let default = match command[index].get("default") {
        Some(toml::Value::Array(items)) if !given => items.clone(),
        _ => Vec::new(),
    };
    let mut marker = toml::Table::new();
    marker.insert(SLOT.into(), name.into());
    command.splice(
        index..=index,
        std::iter::once(toml::Value::Table(marker)).chain(default),
    );
    Ok(())
}

/// `table`, which `expand` resolved, with the resolved `agent-args` (or nothing) in place of the
/// slot marker that `place_slot` left.
fn fill_slot(table: &mut toml::Table) -> Result<(), String> {
    let name = AGENT_ARGS;
    let args = match table.remove(name) {
        Some(toml::Value::Array(args)) => Some(args),
        _ => None,
    };
    let command = table
        .get_mut("agent")
        .and_then(|agent| agent.get_mut("command"))
        .and_then(toml::Value::as_array_mut);
    let Some((command, index)) = command.and_then(|command| {
        let index = command.iter().position(|item| item.get(SLOT).is_some())?;
        Some((command, index))
    }) else {
        return match args {
            Some(_) => Err(format!(
                "`{name}` fills a `{{ slot = \"{name}\" }}` in `[agent] command`, and nothing \
                 sets a command"
            )),
            None => Ok(()),
        };
    };
    command.splice(index..=index, args.unwrap_or_default());
    Ok(())
}

/// Refuse a `when` on element 0, the program, of an `[agent]`, `[tool.<name>]`, or `[mcp.<name>]`
/// `command`.
fn check_programs(table: &toml::Table) -> Result<(), String> {
    let program = |process: &toml::Value| {
        unwrapped(process)
            .get("command")
            .map(unwrapped)
            .and_then(toml::Value::as_array)
            .and_then(|items| items.first())
            .is_some_and(|first| first.get("when").is_some())
    };
    let mut commands = vec![("[agent] command".to_string(), table.get("agent"))];
    for section in ["tool", "mcp"] {
        if let Some(processes) = table
            .get(section)
            .map(unwrapped)
            .and_then(toml::Value::as_table)
        {
            for (name, process) in processes {
                commands.push((format!("[{section}.{name}] command"), Some(process)));
            }
        }
    }
    match commands
        .into_iter()
        .find(|(_, process)| process.is_some_and(program))
    {
        Some((at, _)) => Err(format!(
            "`{at}` element 0 is the program, so it takes no `when`"
        )),
        None => Ok(()),
    }
}

/// Refuse a `when` on the `secret` of an `[egress.<name>]` route.
fn check_secrets(table: &toml::Table) -> Result<(), String> {
    let routes = table
        .get("egress")
        .map(unwrapped)
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
        .map(|(name, item)| (name, unwrapped(item)));
    for (name, route) in routes {
        if route
            .get("secret")
            .is_some_and(|secret| secret.get("when").is_some())
        {
            return Err(format!(
                "`[egress.{name}] secret` takes no `when`, because the route without it opens \
                 its hosts with no credential"
            ));
        }
    }
    Ok(())
}

/// Refuse a slot anywhere but `[agent] command`, and a slot there that is not one
/// `{ slot = "agent-args" }` after the program.
fn check_slots(table: &toml::Table) -> Result<(), String> {
    let is_slot = |item: &toml::Value| unwrapped(item).get(SLOT).is_some();
    for section in ["tool", "mcp"] {
        let Some(processes) = table
            .get(section)
            .map(unwrapped)
            .and_then(toml::Value::as_table)
        else {
            continue;
        };
        for (name, process) in processes {
            let command = unwrapped(process).get("command").map(unwrapped);
            if command
                .and_then(toml::Value::as_array)
                .is_some_and(|items| items.iter().any(is_slot))
            {
                return Err(format!(
                    "`[{section}.{name}] command` holds a slot; only `[agent] command` takes \
                     `{{ slot = \"{AGENT_ARGS}\" }}`"
                ));
            }
        }
    }
    let Some(items) = table
        .get("agent")
        .map(unwrapped)
        .and_then(|agent| agent.get("command"))
        .map(unwrapped)
        .and_then(toml::Value::as_array)
    else {
        return Ok(());
    };
    if items
        .iter()
        .any(|item| item.get(SLOT).is_none() && is_slot(item))
    {
        return Err("a slot in `[agent] command` takes no `when`".to_string());
    }
    let slots: Vec<(usize, &toml::Value)> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| is_slot(item))
        .collect();
    let (index, slot) = match slots.as_slice() {
        [] => return Ok(()),
        [one] => *one,
        _ => return Err("`[agent] command` holds more than one slot".to_string()),
    };
    if index == 0 {
        return Err(
            "`[agent] command` starts with a slot; its first element is the program".to_string(),
        );
    }
    let slot = slot.as_table().expect("a slot is a table");
    if let Some(key) = slot
        .keys()
        .find(|key| !matches!(key.as_str(), "slot" | "default"))
    {
        return Err(format!("a slot holds `slot` and `default`, not `{key}`"));
    }
    if slot.get(SLOT).and_then(toml::Value::as_str) != Some(AGENT_ARGS) {
        return Err(format!(
            "the one slot of `[agent] command` is `slot = \"{AGENT_ARGS}\"`"
        ));
    }
    if slot
        .get("default")
        .is_some_and(|default| !default.is_array())
    {
        return Err("a slot's `default` is a list of arguments".to_string());
    }
    Ok(())
}

fn read(path: &Path) -> Result<String, Error> {
    crate::files::read_regular(path).map_err(|source| Error::Io {
        action: "read",
        path: path.to_path_buf(),
        source,
    })
}

/// The host variable an input reads, and the `key` of that variable's `key=value` list, if any.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HostSource {
    from: String,
    key: Option<String>,
}

impl std::fmt::Display for HostSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.key {
            None => write!(formatter, "{}", self.from),
            Some(key) => write!(formatter, "{} key {key}", self.from),
        }
    }
}

/// An input as the packs that declare it state it.
#[derive(Debug, Clone, Default)]
pub struct Declaration {
    pub kind: String,
    descriptions: Vec<String>,
    warnings: Vec<String>,
    defaults: Vec<(String, String)>,
    froms: Vec<(String, HostSource)>,
    patterns: Vec<String>,
    values: Vec<Vec<String>>,
    searches: Vec<(String, Search)>,
    pub(crate) packs: Vec<String>,
}

impl Declaration {
    /// The first `description` a pack gives.
    pub fn description(&self) -> Option<&str> {
        self.descriptions.first().map(String::as_str)
    }

    /// Each distinct `warning` the packs give, in pack order.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The `default` that applies when no option sets the input: the one default that every pack
    /// that gives one agrees on.
    pub fn default_value(&self) -> Option<&str> {
        let (_, first) = self.defaults.first()?;
        self.defaults
            .iter()
            .all(|(_, value)| value == first)
            .then_some(first.as_str())
    }

    /// Whether a `pattern` or `values` bounds the input.
    pub fn is_bounded(&self) -> bool {
        !self.patterns.is_empty() || !self.values.is_empty()
    }

    /// Whether a run reads the input from the host, with `from` or `search`.
    pub fn reads_host(&self) -> bool {
        !self.froms.is_empty() || !self.searches.is_empty()
    }

    /// The values the input accepts, when a `values` list or the `bool` type limits them.
    pub fn allowed(&self) -> Vec<String> {
        if self.kind == "bool" {
            return vec!["true".to_string(), "false".to_string()];
        }
        let mut allowed = self.values.first().cloned().unwrap_or_default();
        allowed.retain(|value| self.values.iter().all(|list| list.contains(value)));
        allowed
    }
}

/// The packs and the profile merged into one table, with the inputs apart.
#[derive(Clone)]
pub struct Merged {
    pub table: toml::Table,
    pub(crate) policy: String,
    pub declarations: BTreeMap<String, Declaration>,
    pub(crate) values: BTreeMap<String, String>,
    /// The file that last set each `[tool.<name>] program`, by tool name.
    pub(crate) tool_packs: BTreeMap<String, String>,
    /// The tools of the tool packs that each tool's tool pack extends, by tool name, nearest
    /// first and through the whole chain: `go` has `["git"]` when `@box/go` extends `@box/git`.
    pub(crate) tool_bases: BTreeMap<String, Vec<String>>,
    /// The tools that only a tool pack's `extend` brings in: their tables are inherited and then
    /// left out of the box, as an agent pack's base is not a second agent. A tool whose `program`
    /// the profile or a support pack sets is never hidden.
    pub(crate) hidden_tools: BTreeSet<String>,
    /// The one grammar of each tool that has one, by tool name.
    pub(crate) grammars: BTreeMap<String, toml::Table>,
    /// The pack file that last set each `[mcp.<name>]` that the profile does not set, by name.
    pub(crate) mcp_packs: BTreeMap<String, PathBuf>,
    /// The plugin, or `the profile`, that declares each `[secret-source.<scheme>]`, by scheme.
    pub sources: BTreeMap<String, String>,
}

/// Operator command tools that replace shipped program tools.
fn operator_commands(layers: &[Layer]) -> BTreeSet<String> {
    let mut commands = BTreeSet::new();
    for layer in layers
        .iter()
        .filter(|layer| layer.shared && !layer.name.starts_with(VENDORED))
    {
        if let Some(tools) = layer.table.get("tool").and_then(toml::Value::as_table) {
            for (name, tool) in tools {
                if tool.get("command").is_some() && tool.get("program").is_none() {
                    commands.insert(name.clone());
                }
            }
        }
    }
    commands.retain(|name| {
        layers.iter().any(|layer| {
            layer.name.starts_with(VENDORED)
                && layer
                    .table
                    .get("tool")
                    .and_then(|tools| tools.get(name))
                    .is_some_and(|tool| tool.get("program").is_some())
        })
    });
    commands
}

/// The layers merged in order, with the inputs that the packs declare and the profile sets.
pub fn merge(layers: &[Layer]) -> Result<Merged, Error> {
    let mut merged = toml::Table::new();
    let mut policies = Vec::new();
    let mut declarations: BTreeMap<String, Declaration> = BTreeMap::new();
    let mut values = BTreeMap::new();
    let mut routes = RouteOwners::default();
    let mut targets = BTreeMap::new();
    let mut tool_packs = BTreeMap::new();
    let mut tool_pack_bases: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    // The packs that run as tools of their own: the profile's `packs`, each pack's `include`, and
    // what a pack that is not a tool pack extends.
    let mut shown: BTreeSet<String> = BTreeSet::new();
    // The tools whose `program` a layer that is not a tool pack sets: the profile or a support
    // pack declares them as tools of their own, so `extend` never hides them.
    let mut declared_tools: BTreeSet<String> = BTreeSet::new();
    let mut grammars: BTreeMap<String, (String, Grammar)> = BTreeMap::new();
    let mut mcp_packs = BTreeMap::new();
    let mut program_inputs = BTreeMap::new();
    let operator_commands = operator_commands(layers);
    let root = layers
        .last()
        .map(|layer| layer.path.clone())
        .unwrap_or_default();
    refuse_two_agents(layers).map_err(|reason| Error::Profile {
        path: root.clone(),
        line: None,
        reason,
    })?;
    let declared = plugin::declared(layers).map_err(|reason| Error::Profile {
        path: root.clone(),
        line: None,
        reason,
    })?;
    let plugin_inputs = plugin::inputs(layers);
    for layer in layers {
        let mut table = layer.table.clone();
        if layer.name.starts_with(VENDORED)
            && let Some(tools) = table.get_mut("tool").and_then(toml::Value::as_table_mut)
        {
            tools.retain(|name, _| !operator_commands.contains(name));
        }
        let invalid = |reason| Error::Profile {
            path: layer.path.clone(),
            line: None,
            reason,
        };
        for key in [
            EXTEND,
            INCLUDE,
            "packs",
            "pack",
            "policies",
            PLUGINS,
            plugin::HEADER,
        ] {
            table.remove(key);
        }
        if let Some(input) = &layer.program_input {
            program_inputs.insert(input.clone(), layer.name.clone());
        }
        if layer.shared {
            plugin::refuse_foreign_inputs(layer, &table, &plugin_inputs)
                .map_err(|refusal| refusal.in_file(&layer.path, &layer.text))?;
        }
        if let Some(section) = table.remove("inputs") {
            let mut found = Vec::new();
            collect_declarations(&section, &mut Vec::new(), &mut found).map_err(invalid)?;
            for (name, declaration) in found {
                declare(&mut declarations, &name, &layer.name, &declaration).map_err(invalid)?;
            }
        }
        if let Some(section) = table.remove("options") {
            collect_values(&section, &mut Vec::new(), &mut values).map_err(invalid)?;
        }
        check_mcp_rows(&table).map_err(invalid)?;
        refuse_duplicate_targets(&mut targets, &layer.name, &table).map_err(|reason| {
            Error::Profile {
                path: root.clone(),
                line: None,
                reason,
            }
        })?;
        if layer.shared {
            refuse_route_merge(&mut routes, &layer.name, &table).map_err(|reason| {
                Error::Profile {
                    path: root.clone(),
                    line: None,
                    reason,
                }
            })?;
        }
        if layer.shared {
            shown.extend(imports_of(&layer.table, INCLUDE).unwrap_or_default());
            if !is_tool_pack(&layer.table) {
                shown.extend(imports_of(&layer.table, EXTEND).unwrap_or_default());
            }
        } else {
            shown.extend(imports_of(&layer.table, "packs").unwrap_or_default());
        }
        if layer.shared && is_tool_pack(&layer.table) {
            let written = layer
                .table
                .get("tool")
                .and_then(toml::Value::as_table)
                .into_iter()
                .flatten()
                .filter(|(_, tool)| tool.get("program").is_some())
                .map(|(name, _)| name.clone())
                .collect();
            tool_pack_bases.insert(
                layer.name.clone(),
                (
                    written,
                    imports_of(&layer.table, EXTEND).unwrap_or_default(),
                ),
            );
        }
        if layer.shared && !layer.plugin {
            plugin::refuse_pack_references(&layer.name, &table, &declared)
                .map_err(|refusal| refusal.in_file(&layer.path, &layer.text))?;
        }
        if let Some(tools) = table.get("tool").and_then(toml::Value::as_table) {
            for (name, tool) in tools {
                if tool.get("program").is_some() && !(layer.shared && is_tool_pack(&layer.table)) {
                    declared_tools.insert(name.clone());
                }
                if layer.shared && tool.get("program").is_some() {
                    tool_packs.insert(name.clone(), layer.name.clone());
                } else if !layer.shared
                    && tool.get("command").is_some()
                    && tool.get("program").is_none()
                    && let Some(inherited) =
                        merged.get_mut("tool").and_then(toml::Value::as_table_mut)
                    && inherited
                        .get(name)
                        .is_some_and(|tool| tool.get("program").is_some())
                {
                    inherited.remove(name);
                    tool_packs.remove(name);
                    grammars.remove(name);
                }
            }
        }
        refuse_grammar_merge(&mut grammars, layer, &operator_commands).map_err(|reason| {
            Error::Profile {
                path: root.clone(),
                line: None,
                reason,
            }
        })?;
        if let Some(servers) = table.get("mcp").and_then(toml::Value::as_table) {
            for name in servers.keys() {
                if layer.shared {
                    mcp_packs.insert(name.clone(), layer.path.clone());
                } else {
                    mcp_packs.remove(name);
                }
            }
        }
        if !layer.shared {
            mark_profile_ingress(&mut table);
        }
        merge_table(&mut merged, table, &mut Vec::new());
        if let Some(policy) = layer.policy.as_deref().filter(|p| !p.is_empty()) {
            policies.push(policy.to_string());
        }
    }
    let profile = layers.last().map_or("", |layer| layer.text.as_str());
    let in_profile = |reason| Error::Profile {
        path: root.clone(),
        line: None,
        reason,
    };
    if let Some((name, declaration)) = declarations
        .iter()
        .find(|(name, _)| program_inputs.contains_key(*name))
    {
        return Err(in_profile(format!(
            "{} declares {}",
            declaration.packs.join(", "),
            program_input_of(name, &program_inputs[name])
        )));
    }
    let mut named = toml::Value::Table(merged.clone());
    each_string(&mut named, &mut |text| {
        for piece in pieces(text).unwrap_or_default() {
            if let Piece::Name(found) = piece
                && let Some(pack) = found
                    .strip_prefix("inputs.")
                    .and_then(|name| program_inputs.get(name))
            {
                return Err(format!(
                    "{text:?} names {}",
                    program_input_of(&found["inputs.".len()..], pack)
                ));
            }
        }
        Ok(text.to_string())
    })
    .map_err(in_profile)?;
    for (name, value) in &values {
        let whole = ["options".to_string(), name.clone()];
        let at: Vec<String> = std::iter::once("options")
            .chain(name.split('.'))
            .map(str::to_string)
            .collect();
        let line = locate::exact_line_of(profile, &whole).or_else(|| line_of(profile, &at));
        let invalid = |reason| Error::Profile {
            path: root.clone(),
            line,
            reason,
        };
        if program_inputs.contains_key(name) {
            return Err(invalid(only_path(name)));
        }
        let Some(declaration) = declarations.get(name) else {
            let mut reason = format!("`[options] {name}` sets an input that no pack declares");
            if let Some(near) = locate::closest(name, declarations.keys().map(String::as_str)) {
                reason.push_str(&format!("; did you mean `{near}`?"));
            }
            return Err(invalid(reason));
        };
        check_value(name, declaration, value).map_err(invalid)?;
    }
    let grammars = check_grammars(&merged, grammars)?;
    let policy = policies.join("\n\n");
    place_slot(&mut merged).map_err(|reason| Error::Profile {
        path: root.clone(),
        line: locate::exact_line_of(profile, &[AGENT_ARGS.to_string()]),
        reason,
    })?;
    let tool_bases = tool_bases(&tool_pack_bases);
    let shown_tools: BTreeSet<&String> = tool_pack_bases
        .iter()
        .filter(|(pack, _)| shown.contains(*pack))
        .flat_map(|(_, (written, _))| written)
        .collect();
    let hidden_tools = tool_pack_bases
        .iter()
        .filter(|(pack, _)| !shown.contains(*pack))
        .flat_map(|(_, (written, _))| written)
        .filter(|tool| !shown_tools.contains(tool) && !declared_tools.contains(*tool))
        .cloned()
        .collect();
    Ok(Merged {
        table: merged,
        policy,
        declarations,
        values,
        tool_packs,
        tool_bases,
        hidden_tools,
        grammars,
        mcp_packs,
        sources: declared,
    })
}

/// The tools each tool inherits from: for each tool that a tool pack writes, the tools of the
/// tool packs that pack extends, then of the ones those extend, each once and never itself.
/// `packs` holds each tool pack's own tools and its `extend`. A base is the tool its own pack
/// writes, so a later pack that sets `[tool.git] program` again does not take git from go.
fn tool_bases(
    packs: &BTreeMap<String, (Vec<String>, Vec<String>)>,
) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (pack, (tools, extends)) in packs {
        let mut seen = vec![pack.clone()];
        let mut queue: std::collections::VecDeque<String> = extends.iter().cloned().collect();
        let mut bases = Vec::new();
        while let Some(base) = queue.pop_front() {
            if seen.contains(&base) {
                continue;
            }
            seen.push(base.clone());
            let Some((written, next)) = packs.get(&base) else {
                continue;
            };
            for name in written {
                if !bases.contains(name) {
                    bases.push(name.clone());
                }
            }
            queue.extend(next.iter().cloned());
        }
        for tool in tools {
            let entry = out.entry(tool.clone()).or_default();
            for base in bases.iter().filter(|base| *base != tool) {
                if !entry.contains(base) {
                    entry.push(base.clone());
                }
            }
        }
    }
    out.retain(|_, bases| !bases.is_empty());
    out
}

/// Each input declaration in `section`, by its full dotted name.
pub(crate) fn collect_declarations(
    section: &toml::Value,
    at: &mut Vec<String>,
    out: &mut Vec<(String, toml::Table)>,
) -> Result<(), String> {
    let table = section
        .as_table()
        .ok_or_else(|| format!("`inputs.{}` is not a table", at.join(".")))?;
    let declares =
        |key: &str, item: &toml::Value| DECLARATION_KEYS.contains(&key) && !item.is_table();
    if table.iter().any(|(key, item)| declares(key, item)) {
        if let Some(key) = table
            .iter()
            .find(|(key, item)| !declares(key, item))
            .map(|(key, _)| key)
        {
            return Err(format!(
                "`[inputs.{}]` holds `{key}`, which is not a declaration key; an input name \
                 cannot also hold other inputs",
                at.join(".")
            ));
        }
        out.push((at.join("."), table.clone()));
        return Ok(());
    }
    for (key, item) in table {
        at.push(key.clone());
        collect_declarations(item, at, out)?;
        at.pop();
    }
    Ok(())
}

/// Each value in a profile's `[options]`, by its full dotted name.
pub fn collect_values(
    section: &toml::Value,
    at: &mut Vec<String>,
    out: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let name = at.join(".");
    let value = match section {
        toml::Value::Table(table) => {
            for (key, item) in table {
                at.push(key.clone());
                collect_values(item, at, out)?;
                at.pop();
            }
            return Ok(());
        }
        toml::Value::String(text) => text.clone(),
        toml::Value::Boolean(flag) => flag.to_string(),
        toml::Value::Integer(number) => number.to_string(),
        _ => {
            return Err(format!(
                "`[options] {name}` is not a string, a number, or true or false"
            ));
        }
    };
    if value.contains(OPEN) {
        return Err(format!(
            "`[options] {name}` holds a placeholder; a value is literal"
        ));
    }
    out.insert(name, value);
    Ok(())
}

/// Add one pack's declaration of `name`: the same type, and every constraint kept.
fn declare(
    declarations: &mut BTreeMap<String, Declaration>,
    name: &str,
    pack: &str,
    table: &toml::Table,
) -> Result<(), String> {
    let owner = format!("[inputs.{name}]");
    for literal in ["description", "type", "pattern", "from", "key", "warning"] {
        if string_field(table, literal, &owner)?.is_some_and(|text| has_placeholder(&text)) {
            return Err(format!(
                "`{owner} {literal}` is literal and holds no placeholder"
            ));
        }
    }
    let kind = string_field(table, "type", &owner)?.unwrap_or_else(|| "string".into());
    if !matches!(kind.as_str(), "string" | "bool" | "program") {
        return Err(format!(
            "`{owner} type = {kind:?}`; use string, bool, or program"
        ));
    }
    let default = match table.get("default") {
        None => None,
        Some(toml::Value::String(text)) => Some(text.clone()),
        Some(toml::Value::Boolean(flag)) => Some(flag.to_string()),
        Some(_) => {
            return Err(format!(
                "`{owner} default` is not a string or true or false"
            ));
        }
    };
    let from = string_field(table, "from", &owner)?;
    if let Some(from) = &from
        && !from.starts_with("env:")
    {
        return Err(format!("`{owner} from = {from:?}`; use env:<NAME>"));
    }
    let key = string_field(table, "key", &owner)?;
    if let Some(key) = &key {
        if from.is_none() {
            return Err(format!(
                "`{owner} key` names a key of the `from` variable, so it needs `from`"
            ));
        }
        if key.is_empty() || key.trim() != key || key.contains([',', '=']) {
            return Err(format!(
                "`{owner} key = {key:?}` is not one key of a `key=value` list; a key is not \
                 empty, has no space at either end, and holds no `,` or `=`"
            ));
        }
    }
    let values = match table.get("values") {
        None => None,
        Some(toml::Value::Array(items)) => Some(
            items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| format!("`{owner} values` is not a list of strings"))?,
        ),
        Some(_) => return Err(format!("`{owner} values` is not a list of strings")),
    };
    let pattern = string_field(table, "pattern", &owner)?;
    if let Some(pattern) = &pattern {
        regex::Regex::new(&format!("^(?:{pattern})$"))
            .map_err(|error| format!("`{owner} pattern` is invalid: {error}"))?;
    }
    let search = search_of(table, &owner)?;
    if search.is_some() && kind != "program" {
        return Err(format!(
            "`{owner}`: `program` and `search` are only for `type = \"program\"`"
        ));
    }
    if search.is_some() && default.is_some() {
        return Err(format!(
            "`{owner}` holds `program` and `default`; a program input is found by `search` or \
             given by `default`"
        ));
    }
    if table.contains_key("warning") && (from.is_some() || search.is_some()) {
        return Err(format!(
            "`{owner}` holds `warning` and takes its value from the host; a warning goes on an \
             input that the operator answers"
        ));
    }
    let entry = declarations.entry(name.to_string()).or_default();
    if entry.packs.is_empty() {
        entry.kind = kind;
    } else if entry.kind != kind {
        return Err(format!(
            "`inputs.{name}` is a {} in {} and a {kind} in {pack}; two packs can share an input \
             only with one type",
            entry.kind,
            entry.packs.join(", ")
        ));
    }
    entry.packs.push(pack.to_string());
    entry
        .descriptions
        .extend(string_field(table, "description", &owner)?);
    if let Some(warning) = string_field(table, "warning", &owner)?
        && !entry.warnings.contains(&warning)
    {
        entry.warnings.push(warning);
    }
    entry
        .defaults
        .extend(default.map(|value| (pack.to_string(), value)));
    entry
        .froms
        .extend(from.map(|from| (pack.to_string(), HostSource { from, key })));
    entry.patterns.extend(pattern);
    entry.values.extend(values);
    entry
        .searches
        .extend(search.map(|search| (pack.to_string(), search)));
    Ok(())
}

/// The `program` and `search` of an input declaration, with `search` as `PATH` when absent.
fn search_of(table: &toml::Table, owner: &str) -> Result<Option<Search>, String> {
    let program = match table.get("program") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .filter(|program| crate::tool::is_program_name(program))
                .ok_or_else(|| {
                    format!("`{owner} program` is not a program name, such as \"claude\"")
                })?
                .to_string(),
        ),
    };
    let not_folders = || format!("`{owner} search` is a list of folders");
    let folders = match table.get("search") {
        None => vec![Folder::Env("PATH".to_string())],
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                toml::Value::String(path) => Ok(Folder::Path(path.clone())),
                toml::Value::Table(entry) => match entry.get("env") {
                    Some(toml::Value::String(variable))
                        if entry.len() == 1
                            && !variable.is_empty()
                            && !variable.contains(['=', '\0'])
                            && !has_placeholder(variable) =>
                    {
                        Ok(Folder::Env(variable.clone()))
                    }
                    _ => Err(format!(
                        "`{owner} search` entry {item} takes only `env`, the name of a host \
                         variable that holds folders, such as {{ env = \"PATH\" }}"
                    )),
                },
                _ => Err(not_folders()),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(not_folders()),
    };
    match program {
        Some(program) => Ok(Some(Search { program, folders })),
        None if table.contains_key("search") => Err(format!("`{owner} search` needs `program`")),
        None => Ok(None),
    }
}

/// Whether a pack is a tool pack: its `[pack] kind` is `"tool"`.
pub(crate) fn is_tool_pack(table: &toml::Table) -> bool {
    pack_kind(table) == Some(TOOL_KIND)
}

/// Whether a pack is an agent pack: its `[pack] kind` is `"agent"`.
fn is_agent_pack(table: &toml::Table) -> bool {
    pack_kind(table) == Some(AGENT_KIND)
}

/// Refuse native filesystem policy settings in a pack's original tables.
fn check_native_policy_in_pack(table: &toml::Table) -> Result<(), Refusal> {
    if table.contains_key(EXPERIMENTAL_FEATURES) {
        return Err(Refusal::at(
            "a pack holds no `[experimental-features]`; write `[experimental-features]` in \
             `profile.toml`"
                .into(),
            &[EXPERIMENTAL_FEATURES],
        ));
    }
    let refusal = |path: &[&str]| {
        Refusal::at(
            format!(
                "a pack holds no `{}`; write `native-filesystem-policy` in `profile.toml` under \
                 `[agent]`, `[tool.<name>]`, or `[mcp.<name>]`",
                path.join(".")
            ),
            path,
        )
    };
    if table.contains_key(NATIVE_FILESYSTEM_POLICY) {
        return Err(refusal(&[NATIVE_FILESYSTEM_POLICY]));
    }
    // Follow the one-level `{ when, value }` shape that `Resolver::walk` unwraps at each
    // collection or process boundary. Keep `value` in the source path for the refusal.
    fn conditional<'a>(value: &'a toml::Value, path: &mut Vec<&str>) -> &'a toml::Value {
        if let Some(table) = value.as_table()
            && table.len() == 2
            && table.contains_key("when")
            && let Some(inner) = table.get("value")
        {
            path.push("value");
            return inner;
        }
        value
    }
    let process_refusal = |process: &toml::Value, mut path: Vec<&str>| {
        conditional(process, &mut path)
            .get(NATIVE_FILESYSTEM_POLICY)
            .map(|_| {
                path.push(NATIVE_FILESYSTEM_POLICY);
                refusal(&path)
            })
    };
    for section in [RUN, "agent"] {
        if let Some(process) = table.get(section)
            && let Some(refusal) = process_refusal(process, vec![section])
        {
            return Err(refusal);
        }
    }
    if let Some(tools) = table.get("tool") {
        let mut path = vec!["tool"];
        if let Some(tools) = conditional(tools, &mut path).as_table() {
            for (name, tool) in tools {
                let mut path = path.clone();
                path.push(name);
                if let Some(refusal) = process_refusal(tool, path) {
                    return Err(refusal);
                }
            }
        }
    }
    Ok(())
}

/// Check the layout of a pack file, and return the pack as the load reads it.
///
/// A pack holds only tables. `[pack]` holds the header and `extend`. Its `kind` decides the rest:
/// an agent pack's `[run]` holds `command`, `dependency`, and `when`, a tool pack's `[run]` holds
/// `command` and the other keys of a tool, and a support pack holds no `[run]`, `[env]`, or
/// `[filesystem]`. The load reads `extend` and the keys of `[run]` at the top of the table. A tool
/// pack's program input leaves the table, and its name comes back beside it.
pub(crate) fn pack_layout(
    mut table: toml::Table,
    text: &str,
) -> Result<(toml::Table, Option<String>), Refusal> {
    let Some(toml::Value::Table(header)) = table.get("pack") else {
        if table.contains_key(plugin::HEADER) {
            return Err(Refusal::at(
                format!(
                    "this file starts with `[{}]`, so it is a plugin, not a pack; a plugin is \
                     `{}` in a folder of `{PLUGINS}`, and a profile lists it in `{PLUGINS}`",
                    plugin::HEADER,
                    plugin::PLUGIN_FILE
                ),
                &[plugin::HEADER],
            ));
        }
        return Err("a pack needs a `[pack]` header with `name`, `version`, and `kind`".into());
    };
    let kind = match header.get("kind") {
        None => {
            return Err(Refusal::at(
                format!(
                    "`[pack]` needs `kind`: {AGENT_KIND:?}, {TOOL_KIND:?}, or {SUPPORT_KIND:?}"
                ),
                &["pack"],
            ));
        }
        Some(toml::Value::String(kind)) if PACK_KINDS.contains(&kind.as_str()) => kind.clone(),
        Some(_) => {
            return Err(Refusal::at(
                format!("`[pack] kind` is {AGENT_KIND:?}, {TOOL_KIND:?}, or {SUPPORT_KIND:?}"),
                &["pack", "kind"],
            ));
        }
    };
    refuse_header_not_first(text, "pack", "a pack")?;
    check_native_policy_in_pack(&table)?;
    let is_table = |value: &toml::Value| match value {
        toml::Value::Table(_) => true,
        toml::Value::Array(rows) => !rows.is_empty() && rows.iter().all(toml::Value::is_table),
        _ => false,
    };
    if let Some(key) = table
        .iter()
        .find(|(key, value)| !is_table(value) && !REFUSED_WITH_A_REASON.contains(&key.as_str()))
        .map(|(key, _)| key.clone())
    {
        return Err(Refusal::at(
            format!(
                "a pack holds no top-level `{key}`; each of its keys is in a table, such as \
                 `[pack]` or `[run]`"
            ),
            &[&key],
        ));
    }
    let Some(toml::Value::Table(header)) = table.get_mut("pack") else {
        unreachable!("the header was read above");
    };
    let extends = header.remove(EXTEND);
    let include = header.remove(INCLUDE);
    if let Some(key) = header
        .keys()
        .find(|key| !HEADER_KEYS.contains(&key.as_str()))
    {
        let known: Vec<&str> = HEADER_KEYS
            .iter()
            .copied()
            .chain([EXTEND, INCLUDE])
            .collect();
        return Err(Refusal::at(
            unknown_key("`[pack]`", key, &known),
            &["pack", key],
        ));
    }
    if let Some(extends) = extends {
        table.insert(EXTEND.into(), extends);
    }
    if let Some(include) = include {
        table.insert(INCLUDE.into(), include);
    }
    let run = match table.remove(RUN) {
        None => None,
        Some(toml::Value::Table(run)) => Some(run),
        Some(_) => return Err(Refusal::at(format!("`{RUN}` is a table"), &[RUN])),
    };
    if table.contains_key(TOOL_NETWORK) {
        return Err(Refusal::at(
            format!(
                "a pack holds no `[{TOOL_NETWORK}]`; {NETWORK_IS_THE_PROFILES}, in \
                 `[tool.<name>.{TOOL_NETWORK}]`"
            ),
            &[TOOL_NETWORK],
        ));
    }
    let known = match kind.as_str() {
        AGENT_KIND => AGENT_RUN_KEYS,
        TOOL_KIND => TOOL_RUN_KEYS,
        _ => {
            if let Some(key) = PROGRAM_TABLES.iter().find(|key| {
                if **key == RUN {
                    run.is_some()
                } else {
                    table.contains_key(**key)
                }
            }) {
                return Err(Refusal::at(
                    format!(
                        "a support pack holds no `[{key}]`; only an agent pack or a tool pack \
                         runs a program"
                    ),
                    &[key],
                ));
            }
            return Ok((table, None));
        }
    };
    let run = run.unwrap_or_default();
    if let Some(key) = run.keys().find(|key| !known.contains(&key.as_str())) {
        return Err(Refusal::at(
            unknown_key(
                &format!("the `[{RUN}]` of {kind} pack", kind = an(&kind)),
                key,
                known,
            ),
            &[RUN, key],
        ));
    }
    let mut run = run;
    let mut program_input = None;
    if kind == TOOL_KIND {
        let (program, input) = tool_program(&mut table, &run)?;
        run.remove("command");
        run.insert("program".into(), toml::Value::String(program));
        program_input = Some(input);
    }
    table.extend(run);
    Ok((table, program_input))
}

/// The keys of the input that names a tool pack's program.
const TOOL_PROGRAM_INPUT_KEYS: &[&str] = &["description", "type", "program", "search"];

/// The program of the tool pack `table`, and the name of the one input that its `[run] command`
/// names. The input finds the program on `PATH` only, so it holds no other folder and no set
/// path, and no other value of the pack names it. The input leaves the pack: the tool's program is
/// its table's `program`, as the load reads it.
///
/// Box Core's Shell runs a tool table's file for the name of its real file, and finds any other
/// bare name on `PATH`. A file that the agent's `PATH` does not find first, through a link with
/// another name, would never run for the name the agent types.
fn tool_program(table: &mut toml::Table, run: &toml::Table) -> Result<(String, String), Refusal> {
    let at = &[RUN, "command"];
    let shape = || {
        Refusal::at(
            "a tool pack's `[run] command` is its program input alone, such as \
             `command = [\"${{ inputs.git.path }}\"]`"
                .into(),
            at,
        )
    };
    let Some(command) = run.get("command") else {
        return Err(Refusal::at(
            format!("a tool pack needs `[{RUN}] command`, the program it runs"),
            &["pack", "kind"],
        ));
    };
    let [toml::Value::String(head)] = command.as_array().map(Vec::as_slice).unwrap_or_default()
    else {
        return Err(shape());
    };
    let name = match pieces(head)
        .map_err(|reason| Refusal::at(reason, at))?
        .as_slice()
    {
        [Piece::Name(name)] => name
            .strip_prefix("inputs.")
            .map(str::to_string)
            .ok_or_else(shape)?,
        _ => return Err(shape()),
    };
    let parts: Vec<&str> = name.split('.').collect();
    let mut path = vec!["inputs"];
    path.extend(&parts);
    let declaration = parts
        .iter()
        .try_fold(table.get("inputs"), |item, part| {
            Some(item.and_then(|item| item.get(*part)))
        })
        .flatten()
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            Refusal::at(
                format!("`[run] command` names `inputs.{name}`, which this pack does not declare"),
                at,
            )
        })?;
    if declaration.get("type").and_then(toml::Value::as_str) != Some("program") {
        return Err(Refusal::at(
            format!("`[inputs.{name}]` is the program of the tool, so it is `type = \"program\"`"),
            &path,
        ));
    }
    let only_path = only_path(&name);
    if let Some(key) = declaration
        .keys()
        .find(|key| !TOOL_PROGRAM_INPUT_KEYS.contains(&key.as_str()))
    {
        let mut at = path.clone();
        at.push(key);
        return Err(Refusal::at(format!("{only_path}; remove `{key}`"), &at));
    }
    let path_only = toml::Value::Array(vec![toml::Value::Table(toml::Table::from_iter([(
        "env".to_string(),
        toml::Value::String("PATH".into()),
    )]))]);
    if declaration
        .get("search")
        .is_some_and(|search| search != &path_only)
    {
        let mut at = path.clone();
        at.push("search");
        return Err(Refusal::at(only_path, &at));
    }
    let program = declaration
        .get("program")
        .and_then(toml::Value::as_str)
        .filter(|program| crate::tool::is_program_name(program))
        .ok_or_else(|| {
            Refusal::at(
                format!("`[inputs.{name}] program` is the name of a program, such as \"git\""),
                &path,
            )
        })?
        .to_string();
    declare(&mut BTreeMap::new(), &name, "", declaration)
        .map_err(|reason| Refusal::at(reason, &path))?;
    remove_declaration(table, &parts);
    let mut rest = table.clone();
    rest.extend(
        run.iter()
            .filter(|(key, _)| key.as_str() != "command")
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    let mut rest = toml::Value::Table(rest);
    let wanted = format!("inputs.{name}");
    each_string(&mut rest, &mut |text| {
        if pieces(text)
            .unwrap_or_default()
            .iter()
            .any(|piece| matches!(piece, Piece::Name(found) if *found == wanted))
        {
            return Err(format!(
                "{text:?} names `{wanted}`, the program of the tool; only `[run] command` names \
                 it. Use `${{{{ root }}}}` for the folder of the program"
            ));
        }
        Ok(text.to_string())
    })?;
    Ok((program, name))
}

/// A tool pack's program input `name`, which the pack `pack` declares, and what to write instead.
fn program_input_of(name: &str, pack: &str) -> String {
    let tool = pack.rsplit('/').next().unwrap_or(pack);
    format!(
        "`inputs.{name}`, the program of the tool pack {pack}; only its `[run] command` names it. \
         Declare a program input of your own, or use `${{{{ tool.{tool}.root }}}}` for the folder \
         of its program"
    )
}

/// The refusal of a tool's program input that searches more than `PATH` or is set.
fn only_path(name: &str) -> String {
    format!(
        "`[inputs.{name}]` is the program of the tool, so it finds the program on `PATH` only: \
         write `search = [{{ env = \"PATH\" }}]`. Other folders and a set path are not \
         supported for a tool yet"
    )
}

/// Remove the input declaration at `parts` under `[inputs]`, and each table it leaves empty.
fn remove_declaration(table: &mut toml::Table, parts: &[&str]) {
    fn remove(table: &mut toml::Table, parts: &[&str]) {
        match parts {
            [] => {}
            [last] => {
                table.remove(*last);
            }
            [first, rest @ ..] => {
                if let Some(toml::Value::Table(inner)) = table.get_mut(*first) {
                    remove(inner, rest);
                    if inner.is_empty() {
                        table.remove(*first);
                    }
                }
            }
        }
    }
    let mut path = vec!["inputs"];
    path.extend(parts);
    remove(table, &path);
}

/// Refuse a file, `a pack` or `a plugin` as `file` names it, whose first table is not `[header]`.
pub(crate) fn refuse_header_not_first(text: &str, header: &str, file: &str) -> Result<(), Refusal> {
    let Some(first) = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
    else {
        return Ok(());
    };
    let Some(name) = first
        .strip_prefix("[[")
        .or_else(|| first.strip_prefix('['))
        .and_then(|rest| rest.split(']').next())
    else {
        return Ok(());
    };
    let name = name.trim();
    if name == header {
        return Ok(());
    }
    let table = name.split('.').next().unwrap_or(name).trim().to_string();
    Err(Refusal::at(
        format!("{file} starts with `[{header}]`, and this one starts with `{first}`"),
        &[&table],
    ))
}

/// `kind` with its article, as in "an agent".
fn an(kind: &str) -> String {
    match kind {
        AGENT_KIND => "an agent".to_string(),
        other => format!("a {other}"),
    }
}

/// Write the agent pack `table` as the full form: the keys of its `[run]`, which `pack_layout` put
/// at the top, and its `[env]` and `[filesystem]` move into `[agent]`. Refuse an `[agent]` that the pack writes itself.
fn lift_agent_pack(table: &mut toml::Table) -> Result<(), Refusal> {
    if table.contains_key("agent") {
        return Err(Refusal::at(
            "an agent pack holds no `[agent]`; its agent's keys are in `[run]`, `[env]`, and \
             `[filesystem]`"
                .into(),
            &["agent"],
        ));
    }
    let agent: toml::Table = AGENT_KEYS
        .iter()
        .filter(|key| **key != "ingress")
        .filter_map(|key| table.remove(*key).map(|value| ((*key).to_string(), value)))
        .collect();
    if !agent.is_empty() {
        table.insert("agent".into(), toml::Value::Table(agent));
    }
    Ok(())
}

/// Whether the pack `name`, or a pack it extends, runs an agent.
pub fn runs_agent(lookup: &Lookup, name: &str) -> Result<bool, String> {
    Ok(agent_pack(lookup, name)?.is_some())
}

/// Each pack in `packs` and each pack that they extend.
pub fn imported(lookup: &Lookup, packs: &[String]) -> Result<Vec<String>, String> {
    let mut seen: Vec<String> = Vec::new();
    let mut next: Vec<String> = packs.to_vec();
    while let Some(pack) = next.pop() {
        if seen.contains(&pack) {
            continue;
        }
        let table = lookup.table(&pack)?;
        next.extend(imports_of(&table, EXTEND)?);
        next.extend(imports_of(&table, INCLUDE)?);
        seen.push(pack);
    }
    Ok(seen)
}

/// The table of the pack `name`, or of a pack it extends, that holds `[run] command`.
pub fn agent_pack(lookup: &Lookup, name: &str) -> Result<Option<toml::Table>, String> {
    let mut seen: Vec<String> = Vec::new();
    let mut next = vec![name.to_string()];
    while let Some(pack) = next.pop() {
        if seen.contains(&pack) {
            continue;
        }
        let table = lookup.table(&pack)?;
        if is_agent(&table) {
            return Ok(Some(table));
        }
        next.extend(imports_of(&table, EXTEND)?);
        seen.push(pack);
    }
    Ok(None)
}

/// Whether `table` runs an agent: a pack as `pack_layout` returns it holds `command` at its top,
/// and a pack after the load, or a profile, holds `[agent] command`.
fn is_agent(table: &toml::Table) -> bool {
    table.contains_key("command")
        || table
            .get("agent")
            .and_then(|agent| agent.get("command"))
            .is_some()
}

/// The routes and the `env://` variables that the packs declare, each with the pack and route that
/// declare it.
#[derive(Default)]
struct RouteOwners {
    routes: BTreeMap<String, String>,
    variables: BTreeMap<String, (String, String)>,
}

/// Refuse a pack that declares an `[egress.<name>]` route that an earlier pack declared, or a route
/// whose `env://` variable a route of an earlier pack reads, and record what each pack declares.
fn refuse_route_merge(
    owners: &mut RouteOwners,
    pack: &str,
    table: &toml::Table,
) -> Result<(), String> {
    let Some(toml::Value::Table(egress)) = table.get("egress").map(unwrapped) else {
        return Ok(());
    };
    for (name, route) in egress {
        if let Some(first) = owners.routes.get(name) {
            return Err(format!(
                "`[egress.{name}]` is declared by both {first} and {pack}, and two packs cannot \
                 declare one route"
            ));
        }
        owners.routes.insert(name.clone(), pack.to_string());
        let variable = unwrapped(route)
            .get("secret")
            .map(unwrapped)
            .and_then(|secret| secret.get("ref"))
            .map(unwrapped)
            .and_then(toml::Value::as_str)
            .and_then(|reference| reference.strip_prefix("env://"));
        let Some(variable) = variable else {
            continue;
        };
        match owners.variables.get(variable) {
            Some((first, route)) if first != pack => {
                return Err(format!(
                    "`[egress.{name}]` in {pack} reads env://{variable}, which `[egress.{route}]` \
                     in {first} reads, and two packs cannot read one key"
                ));
            }
            Some(_) => {}
            None => {
                owners
                    .variables
                    .insert(variable.to_string(), (pack.to_string(), name.clone()));
            }
        }
    }
    Ok(())
}

/// Refuse a grammar for a tool that an earlier file gave a grammar, and a grammar whose `name` or
/// `program` an earlier file's grammar names, and record in `grammars` each grammar and its file.
fn refuse_grammar_merge(
    grammars: &mut BTreeMap<String, (String, Grammar)>,
    layer: &Layer,
    operator_commands: &BTreeSet<String>,
) -> Result<(), String> {
    for (tool, grammar) in &layer.grammars {
        if layer.name.starts_with(VENDORED) && operator_commands.contains(tool) {
            continue;
        }
        if let Some((first, _)) = grammars.get(tool) {
            return Err(format!(
                "`[tool.{tool}.grammar]` is set by both {first} and {}, and box merges no grammar; \
                 a tool has one grammar",
                layer.name
            ));
        }
        for key in ["name", "program"] {
            let Some(value) = grammar.table.get(key).and_then(toml::Value::as_str) else {
                continue;
            };
            if let Some((first, _)) = grammars.values().find(|(_, other)| {
                other.table.get(key).and_then(toml::Value::as_str) == Some(value)
            }) {
                return Err(format!(
                    "the grammars of {first} and {} both have `{key} = {value:?}`, and two \
                     grammars cannot share a {key}",
                    layer.name
                ));
            }
        }
        grammars.insert(tool.clone(), (layer.name.clone(), grammar.clone()));
    }
    Ok(())
}

/// Each grammar of `grammars` whose `name` is its tool's name and whose `program` is its tool's
/// `program` in `merged`, by tool name.
fn check_grammars(
    merged: &toml::Table,
    grammars: BTreeMap<String, (String, Grammar)>,
) -> Result<BTreeMap<String, toml::Table>, Error> {
    let mut out = BTreeMap::new();
    for (tool, (file, grammar)) in grammars {
        let invalid = |reason: String| Error::Profile {
            path: grammar.path.clone(),
            line: None,
            reason,
        };
        let field = |key: &str| {
            grammar
                .table
                .get(key)
                .and_then(toml::Value::as_str)
                .ok_or_else(|| {
                    invalid(format!(
                        "the grammar of `[tool.{tool}]` in {file} needs `{key}`, a string"
                    ))
                })
        };
        let identifier = tool.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && tool.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !identifier {
            return Err(invalid(format!(
                "`[tool.{tool}]` has a grammar in {file}, so its name is letters, digits, and `_`, \
                 starting with a letter or `_`, which Box Core can use as a policy namespace"
            )));
        }
        let name = field("name")?;
        if name != tool {
            return Err(invalid(format!(
                "the grammar of `[tool.{tool}]` in {file} has `name = {name:?}`; a tool's grammar \
                 has the tool's name, `name = {tool:?}`"
            )));
        }
        let program = field("program")?;
        let expected = merged
            .get("tool")
            .and_then(|tools| tools.get(&tool))
            .and_then(|table| table.get("program"))
            .and_then(toml::Value::as_str);
        match expected {
            Some(expected) if expected == program => {}
            Some(expected) => {
                return Err(invalid(format!(
                    "the grammar of `[tool.{tool}]` in {file} has `program = {program:?}`, and \
                     the tool's program is {expected:?}; a grammar reads the program its own tool \
                     runs"
                )));
            }
            None => {
                return Err(invalid(format!(
                    "the grammar of `[tool.{tool}]` in {file} needs the tool's `program`; a \
                     grammar goes on a tool that names its program"
                )));
            }
        }
        out.insert(tool, grammar.table);
    }
    Ok(out)
}

/// The policy namespace of `grammar`: `Tool::<name>` for version 1, and `Tool::<name>::v<version>`
/// after it.
pub(crate) fn grammar_namespace(grammar: &toml::Table) -> Option<String> {
    let name = grammar.get("name").and_then(toml::Value::as_str)?;
    match grammar.get("version").and_then(toml::Value::as_integer) {
        Some(version) if version > 1 => Some(format!("Tool::{name}::v{version}")),
        _ => Some(format!("Tool::{name}")),
    }
}

/// Refuse a `[[storage.files]]` row whose `target` an earlier row names, and record in `targets`
/// the file that names each target.
fn refuse_duplicate_targets(
    targets: &mut BTreeMap<String, String>,
    file: &str,
    table: &toml::Table,
) -> Result<(), String> {
    let Some(rows) = table
        .get("storage")
        .and_then(|storage| storage.get("files"))
    else {
        return Ok(());
    };
    let rows = rows
        .as_array()
        .ok_or("`storage.files` is a list of `[[storage.files]]` rows")?;
    for row in rows {
        if row.get("when").is_some() {
            continue;
        }
        let Some(target) = row.get("target").and_then(toml::Value::as_str) else {
            continue;
        };
        let nested = targets.iter().find(|(other, _)| {
            Path::new(other).starts_with(target) || Path::new(target).starts_with(other.as_str())
        });
        if let Some((other, first)) = nested {
            let what = if other == target {
                format!("`[[storage.files]] target = {target:?}` is in both {first} and {file}")
            } else {
                format!(
                    "`[[storage.files]] target = {target:?}` in {file} and `target = {other:?}` \
                     in {first} overlap"
                )
            };
            return Err(format!(
                "{what}; two rows cannot copy to one target or one inside another"
            ));
        }
        targets.insert(target.to_string(), file.to_string());
    }
    Ok(())
}

/// The value of `key` in `list`, a comma-separated list of `key=value` items, percent-decoded, or
/// `None` when no item names `key` or its value is empty.
fn list_value(list: &str, key: &str) -> Result<Option<String>, String> {
    let mut found = list
        .split(',')
        .filter_map(|item| item.split_once('='))
        .filter(|(name, _)| name.trim() == key)
        .map(|(_, value)| value.trim());
    let Some(value) = found.next() else {
        return Ok(None);
    };
    if found.next().is_some() {
        return Err("which holds it twice".to_string());
    }
    let value = percent_decoded(value)
        .filter(|value| !value.contains('\0'))
        .ok_or("whose value is not percent-encoded UTF-8 text without NUL".to_string())?;
    Ok((!value.is_empty()).then_some(value))
}

/// `text` with each `%XX` replaced by its byte, or `None` when an escape or the result is invalid.
fn percent_decoded(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&byte, after)) = rest.split_first() {
        if byte == b'%' {
            let digits = after
                .get(..2)
                .filter(|digits| digits.iter().all(u8::is_ascii_hexdigit))?;
            bytes.push(u8::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?);
            rest = &after[2..];
        } else {
            bytes.push(byte);
            rest = after;
        }
    }
    String::from_utf8(bytes).ok()
}

/// Refuse a value that breaks the type, a `values` list, or a pattern of its input.
pub fn check_value(name: &str, declaration: &Declaration, value: &str) -> Result<(), String> {
    let key = format!("inputs.{name}");
    if declaration.kind == "bool" && !matches!(value, "true" | "false") {
        return Err(format!("`{key}` = {value:?} is not true or false"));
    }
    for values in &declaration.values {
        if !values.iter().any(|allowed| allowed == value) {
            return Err(format!(
                "`{key}` = {value:?} is not one of {}",
                values.join(", ")
            ));
        }
    }
    for pattern in &declaration.patterns {
        let pattern = regex::Regex::new(&format!("^(?:{pattern})$"))
            .map_err(|error| format!("`[inputs.{name}] pattern` is invalid: {error}"))?;
        if !pattern.is_match(value) {
            return Err(format!("`{key}` = {value:?} does not match its pattern"));
        }
    }
    Ok(())
}

pub(crate) fn merge_table(base: &mut toml::Table, over: toml::Table, at: &mut Vec<String>) {
    for (key, value) in over {
        at.push(key.clone());
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(old)), toml::Value::Table(new)) if !is_env_value(at) => {
                merge_table(old, new, at)
            }
            (Some(toml::Value::Array(old)), toml::Value::Array(new)) if joins(at) => {
                for item in new {
                    if !old.contains(&item) {
                        old.push(item);
                    }
                }
            }
            (_, value) => {
                base.insert(key, value);
            }
        }
        at.pop();
    }
}

/// The key that marks an `[[agent.ingress]]` row the profile wrote, until `when` resolves.
const PROFILE_INGRESS: &str = "\0profile";

/// Mark each `[[agent.ingress]]` row of the profile's own `table`.
fn mark_profile_ingress(table: &mut toml::Table) {
    let rows = table
        .get_mut("agent")
        .and_then(toml::Value::as_table_mut)
        .and_then(|agent| agent.get_mut("ingress"))
        .and_then(toml::Value::as_array_mut);
    for row in rows.into_iter().flatten() {
        if let toml::Value::Table(row) = row {
            row.insert(PROFILE_INGRESS.to_string(), toml::Value::Boolean(true));
        }
    }
}

/// `rows` without each pack row for a `workload_port` that a profile row in `rows` names.
fn replace_pack_ingress(rows: &mut Vec<toml::Value>) {
    let profile: Vec<bool> = rows
        .iter_mut()
        .map(|row| {
            row.as_table_mut()
                .is_some_and(|row| row.remove(PROFILE_INGRESS).is_some())
        })
        .collect();
    let ports: Vec<toml::Value> = rows
        .iter()
        .zip(&profile)
        .filter(|(_, profile)| **profile)
        .filter_map(|(row, _)| row.get("workload_port").cloned())
        .collect();
    let mut profile = profile.into_iter();
    rows.retain(|row| {
        profile.next().unwrap_or(false)
            || row
                .get("workload_port")
                .is_none_or(|port| !ports.contains(port))
    });
}

/// Whether the list at `at` joins across profiles: a filesystem list, `dependency`,
/// `[storage] directories`, or `[[storage.files]]`. Every other list is replaced, so `command` keeps its order.
fn joins(at: &[String]) -> bool {
    is_filesystem_list(at)
        || at.last().is_some_and(|key| key == "dependency")
        || at == ["storage", "directories"]
        || matches!(at, [tool, _, storage, list] if tool == "tool" && storage == "storage" && (list == "directories" || list == "files"))
        || at == ["storage", "files"]
        || at == ["storage", "hooks"]
        || at == [MCP_SERVERS]
        || at == ["agent", "ingress"]
}

/// Refuse a malformed `[[mcp-servers]]` row in `table`.
fn check_mcp_rows(table: &toml::Table) -> Result<(), String> {
    let Some(rows) = table.get(MCP_SERVERS) else {
        return Ok(());
    };
    let rows = rows
        .as_array()
        .ok_or("`mcp-servers` is a list of `[[mcp-servers]]` rows")?;
    for (index, row) in rows.iter().enumerate() {
        mcp_row(row, &format!("mcp-servers[{index}]"))?;
    }
    Ok(())
}

/// One `[[mcp-servers]]` row as written.
struct McpRow<'a> {
    file: String,
    kind: mcp::Format,
    keys: Vec<String>,
    env_var_locations: BTreeMap<String, mcp::Role>,
    env_var_syntax: Option<mcp::Syntax>,
    target: Option<(String, Vec<String>)>,
    when: Option<&'a toml::Value>,
}

/// One `[[mcp-servers]]` row: its `file`, its `kind`, its `key` list, its `env-var-locations`, its
/// `env-var-syntax`, and its `when`.
fn mcp_row<'a>(row: &'a toml::Value, at: &str) -> Result<McpRow<'a>, String> {
    let row = row
        .as_table()
        .ok_or_else(|| format!("`{at}` is not a `[[mcp-servers]]` row"))?;
    if let Some(key) = row.keys().find(|key| {
        !matches!(
            key.as_str(),
            "file"
                | "kind"
                | "key"
                | "env-var-locations"
                | "env-var-syntax"
                | "command-prefix"
                | "when"
                | "target"
                | "target-key"
        )
    }) {
        return Err(format!(
            "`{at}` holds the unknown key `{key}`; a row holds `file`, `kind`, `key`, \
             `env-var-locations`, `env-var-syntax`, `command-prefix`, `target`, `target-key`, \
             and `when`"
        ));
    }
    let forms = match row.get("env-var-syntax") {
        None => None,
        Some(toml::Value::String(form)) => Some(vec![form.clone()]),
        Some(toml::Value::Array(items)) if !items.is_empty() => Some(
            items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    format!("`{at} env-var-syntax` is not a string or a list of strings")
                })?,
        ),
        Some(_) => {
            return Err(format!(
                "`{at} env-var-syntax` is not a string or a list of strings"
            ));
        }
    };
    let command_prefix = string_field(row, "command-prefix", at)?;
    if command_prefix.as_deref() == Some("") {
        return Err(format!("`{at} command-prefix` is empty"));
    }
    let env_var_syntax = match forms {
        None if command_prefix.is_some() => {
            return Err(format!(
                "`{at} command-prefix` needs the row's `env-var-syntax`, such as \"${{NAME}}\""
            ));
        }
        None => None,
        Some(forms) => Some(mcp::Syntax::new(&forms, command_prefix).map_err(|form| {
            format!(
                "`{at} env-var-syntax = {form:?}` holds `NAME` once, after the text that opens a \
                 variable, such as \"${{NAME}}\""
            )
        })?),
    };
    let mut env_var_locations = BTreeMap::new();
    if let Some(table) = row.get("env-var-locations") {
        let table = table.as_table().ok_or_else(|| {
            format!("`{at} env-var-locations` is a table from a server field to what it holds")
        })?;
        for (field, role) in table {
            let role = role.as_str().and_then(mcp::Role::named).ok_or_else(|| {
                format!(
                    "`{at} env-var-locations.{field}` names no role; known: {}",
                    mcp::Role::NAMES
                        .iter()
                        .map(|(name, _)| *name)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            if role.expands() {
                if !mcp::EXPANDED_FIELDS.contains(&field.as_str()) {
                    return Err(format!(
                        "`{at} env-var-locations.{field}` is `{}`, which goes on `command`, \
                         `args`, or `env`",
                        role.name()
                    ));
                }
            } else if mcp::KNOWN_FIELDS.contains(&field.as_str()) {
                return Err(format!(
                    "`{at} env-var-locations.{field}` names a field box already reads; a role goes on \
                     a field that names a key"
                ));
            }
            if role.needs_syntax() && env_var_syntax.is_none() {
                return Err(format!(
                    "`{at} env-var-locations.{field}` is `{}`, which needs the row's \
                     `env-var-syntax`, such as \"${{NAME}}\"",
                    role.name()
                ));
            }
            env_var_locations.insert(field.clone(), role);
        }
    }
    let file = string_field(row, "file", at)?.ok_or_else(|| format!("`{at}` needs `file`"))?;
    let kind = string_field(row, "kind", at)?
        .ok_or_else(|| format!("`{at}` needs `kind`, \"json\" or \"toml\""))?;
    let kind = mcp::Format::named(&kind)
        .ok_or_else(|| format!("`{at} kind = {kind:?}` is not \"json\" or \"toml\""))?;
    let keys = match row.get("key") {
        Some(toml::Value::Array(items)) if !items.is_empty() => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>(),
        _ => None,
    }
    .ok_or_else(|| format!("`{at} key` is a list of one or more keys, such as [\"mcpServers\"]"))?;
    let target_key = match row.get("target-key") {
        None => None,
        Some(toml::Value::String(key)) if !key.is_empty() && !has_placeholder(key) => {
            Some(vec![key.clone()])
        }
        Some(toml::Value::Array(keys))
            if !keys.is_empty()
                && keys
                    .iter()
                    .all(|key| key.as_str().is_some_and(|key| !key.is_empty())) =>
        {
            Some(
                keys.iter()
                    .filter_map(|key| key.as_str().map(str::to_string))
                    .collect(),
            )
        }
        Some(_) => {
            return Err(format!(
                "`{at} target-key` is a nonempty literal key, or a list of one or more keys, \
                 such as [\"projects\", \"${{{{ workspace }}}}\", \"mcpServers\"]"
            ));
        }
    };
    let target = match (string_field(row, "target", at)?, target_key) {
        (None, None) => None,
        (Some(path), Some(key)) => Some((path, key)),
        _ => {
            return Err(format!(
                "`{at}` needs both `target` and a nonempty `target-key`"
            ));
        }
    };
    Ok(McpRow {
        target,
        file,
        kind,
        keys,
        env_var_locations,
        env_var_syntax,
        when: row.get("when"),
    })
}

/// An absolute path without parent traversal, or a path relative to the host home.
fn check_path(value: &str, at: &str) -> Result<(), String> {
    if value.is_empty() {
        return Ok(());
    }
    let path = Path::new(value);
    if !(path.is_absolute() || value.starts_with("~/")) {
        return Err(format!("`{at}` = {value:?} is not an absolute path"));
    }
    if path.components().any(|part| part == Component::ParentDir) {
        return Err(format!("`{at}` = {value:?} holds `..`"));
    }
    Ok(())
}

/// The version in a `>=X.Y.Z` requirement.
fn floor(requirement: &str) -> Result<Vec<u64>, String> {
    let version = requirement
        .trim()
        .strip_prefix(">=")
        .ok_or_else(|| format!("version {requirement:?} is not `>=X.Y.Z`"))?;
    parse_version(version).ok_or_else(|| format!("version {requirement:?} is not `>=X.Y.Z`"))
}

fn parse_version(text: &str) -> Option<Vec<u64>> {
    let text = text.trim().trim_start_matches('v');
    let parts: Option<Vec<u64>> = text.split('.').map(|part| part.parse().ok()).collect();
    parts.filter(|parts| !parts.is_empty())
}

/// The release a `box` build counts as: a preview build such as `0.3.0-linux-preview.1` is `0.3.0`.
fn release_of(version: &str) -> Option<Vec<u64>> {
    let release = version
        .split_once('-')
        .map_or(version, |(release, _)| release);
    parse_version(release)
}

/// The namespace of a profile's storage that every run uses.
pub(crate) const DEFAULT_NAMESPACE: &str = "default";

/// The storage directory of `profile`, which every workspace the profile runs in shares.
pub fn storage_root(box_home: &Path, profile: &str) -> PathBuf {
    box_home
        .join("storage")
        .join(profile)
        .join(DEFAULT_NAMESPACE)
}

/// The storage directory `directory` of the tool `tool` in the profile's storage `storage`, which
/// every workspace of the profile shares and only the tool reaches.
pub(crate) fn tool_storage(storage: &Path, tool: &str, directory: &str) -> PathBuf {
    storage.join(TOOL_STORAGE).join(tool).join(directory)
}

/// The storage folder that holds each tool's own storage.
const TOOL_STORAGE: &str = "tool";

/// The storage folder that holds the agent's `[storage] directories`.
const AGENT_STORAGE: &str = "agent";

/// What one run's resolution knows besides the profile.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    pub home: &'a Path,
    pub box_home: &'a Path,
    pub workspace: &'a Path,
    pub profile: &'a Path,
    /// The profile's own file: `profile.toml` in its folder, or the file a path named.
    pub profile_file: &'a Path,
    pub box_dir: &'a Path,
    pub storage: &'a Path,
    pub os: &'a str,
    pub tool_cache: Option<&'a Path>,
    /// The folder of box's own packs.
    pub packs: Option<&'a Path>,
}

/// Storage for one run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Storage {
    pub root: PathBuf,
    pub directories: Vec<PathBuf>,
    /// Each tool's state in storage, which a tool's `storage.directories` names: a run creates
    /// it, and any write grant may reach it.
    pub tool_states: Vec<PathBuf>,
    /// Each MCP launcher's cache in storage: a run creates it, and only the servers that its
    /// launcher starts write it.
    pub launcher_caches: Vec<PathBuf>,
    /// Each copy row of `[[storage.files]]`: the agent's, then each tool's.
    pub files: Vec<StorageFile>,
    /// Each host import omitted because its environment-derived root is unsafe.
    pub skipped: Vec<(PathBuf, String)>,
    /// Each link that a `mode = "link"` or `"link-children"` row of a tool's `[[storage.files]]`
    /// puts in its storage.
    pub links: Vec<StorageLink>,
    /// Each `[[storage.hooks]]` row.
    pub hooks: Vec<HookImport>,
    /// Each script that an imported hook runs, by its real path, which the policy permits the box
    /// to read.
    pub hook_scripts: Vec<PathBuf>,
    pub refusals: Refusals,
}

/// One `[[storage.hooks]]` row, resolved.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HookImport {
    /// The host file that holds the hooks.
    pub source: PathBuf,
    pub refused: Option<String>,
    /// The copy in storage that the agent reads.
    pub target: PathBuf,
    /// The target relative to the storage root.
    pub relative: String,
    /// The row as an error names it, such as `storage.hooks[0]`.
    pub at: String,
    /// Whether the run imports hooks, or only removes them from the copy.
    pub import: bool,
    /// The keys from the top of the file to each hook, where [`EVERY`] is each key or each item.
    pub key: KeyPath,
    /// The keys that an object between the first key and a hook holds beside the next key.
    pub keep_above: Vec<String>,
    /// The field of a hook and the one value that marks a hook that runs a command.
    pub only: Option<(KeyPath, String)>,
    /// The field of a hook that holds its command.
    pub command: KeyPath,
    /// The field of a hook that holds the arguments of its command.
    pub args: Option<KeyPath>,
    /// The fields of a hook that the copy keeps unchanged.
    pub keep: Vec<KeyPath>,
    /// The fields of a hook that the copy leaves out.
    pub drop: Vec<HookDrop>,
    /// The fields that each imported hook gets.
    pub set: Vec<HookSetting>,
    /// The top-level key that turns every hook off when it is `true`.
    pub disable_key: Option<String>,
}

/// The step of a `[[storage.hooks]]` `key` that names each key of an object or each item of a list.
pub const EVERY: &str = "*";

/// The name that a `[[storage.hooks.set]]` value holds where the script's real path goes.
const SCRIPT: &str = "script";

/// One `drop` entry of a `[[storage.hooks]]` row: a field that the copy leaves out, and the one
/// string that a hook can hold there, or `None` for any value.
#[derive(Debug, Clone, PartialEq)]
pub struct HookDrop {
    pub key: KeyPath,
    pub equals: Option<String>,
}

/// One `[[storage.hooks.set]]` row: a field that each imported hook gets, and its value.
#[derive(Debug, Clone, PartialEq)]
pub struct HookSetting {
    pub key: KeyPath,
    pub value: HookValue,
}

/// The value of one `[[storage.hooks.set]]` row.
#[derive(Debug, Clone, PartialEq)]
pub enum HookValue {
    /// Text, with the script's real path between each two parts.
    Text(Vec<String>),
    /// A number or a boolean.
    Fixed(toml::Value),
    List(Vec<HookValue>),
}

impl HookValue {
    /// How many times the value holds the script's path.
    fn scripts(&self) -> usize {
        match self {
            Self::Text(parts) => parts.len() - 1,
            Self::Fixed(_) => 0,
            Self::List(items) => items.iter().map(Self::scripts).sum(),
        }
    }
}

/// One link row of a tool's `[[storage.files]]`: a link in the tool's storage to a host path.
#[derive(Debug, Clone, PartialEq)]
pub struct StorageLink {
    /// The host path the link names.
    pub source: PathBuf,
    /// The link, or with `link-children` the folder of links, in the tool's storage directory.
    pub target: PathBuf,
    /// The tool's storage directory that holds the target.
    pub root: PathBuf,
    /// Whether the target is a folder with one link for each entry of the source folder
    /// (`mode = "link-children"`), not one link to the source (`mode = "link"`).
    pub children: bool,
    /// The row, such as `tool.cargo.storage.files[1]`.
    pub at: String,
}

/// One input a run read, for `box profile show`.
#[derive(Debug, Clone, PartialEq)]
pub struct Input {
    pub name: String,
    pub value: String,
    pub source: String,
}

/// The merged profile with every placeholder filled in.
pub(crate) struct Expanded {
    pub(crate) table: toml::Table,
    pub(crate) storage: Storage,
    pub(crate) inputs: Vec<Input>,
    pub(crate) mcp_sources: Vec<mcp::Source>,
    /// Each tool table path that does not exist on this host, as `(tool, path)`.
    pub(crate) dropped: Vec<(String, String)>,
}

/// Why `expand` stopped, and whether the reason is a file or a program the host lacks.
#[derive(Debug)]
pub(crate) struct Unresolved {
    pub(crate) reason: String,
    pub(crate) absent: bool,
    /// The tool table whose command input failed, and why.
    pub(crate) tool: Option<(String, String)>,
}

/// A program that a `program` input names.
struct HostProgram {
    /// The key that names the program, such as `inputs.tool.program`.
    name: String,
    value: String,
}

struct Resolver<'a, S> {
    inputs: &'a Inputs<'a>,
    sources: &'a mut S,
    declarations: BTreeMap<String, Declaration>,
    values: BTreeMap<String, String>,
    storage: BTreeMap<String, PathBuf>,
    credentials: Credentials,
    cache: BTreeMap<String, String>,
    active: Vec<String>,
    read: Vec<Input>,
    programs: Vec<HostProgram>,
    absent: bool,
    routing: bool,
    /// The URL field that the value being filled reaches, whose input needs a bound.
    url_reach: Option<&'static str>,
    /// The telemetry setting that the value being filled reaches, which Box Core sends as a header.
    header_reach: Option<&'static str>,
    commanding: bool,
    command_head: bool,
    roots: BTreeMap<String, PathBuf>,
    dropped: Vec<(String, String)>,
    globbing: bool,
    tool: Option<String>,
    /// The `kind` of the `[telemetry.<label>]` target that the walk is in.
    telemetry_kind: Option<String>,
    /// Each tool's own storage directories, by tool and then by name.
    tool_storage: BTreeMap<String, BTreeMap<String, PathBuf>>,
    /// Each tool storage directory, which the run creates and only its tool reaches.
    states: Vec<PathBuf>,
    failed: Option<(String, String)>,
    developer_dir: Option<Result<String, String>>,
    /// The field `commanding` names in a refusal: `command` or `agent-args`.
    field: &'static str,
    /// `[agent] command` element 0 as written, which `root` in `[agent]` comes from.
    agent_head: Option<String>,
    /// The folder of the agent's program, once a `root` in `[agent]` asks for it.
    agent_root: Option<PathBuf>,
    skipped: BTreeMap<PathBuf, (PathBuf, String)>,
}

/// The character that stands for a pack's literal `*` in a path until it is matched.
const WILDCARD: char = '\0';

/// Fill in every placeholder of `table`, which `merge` produced.
pub(crate) fn expand(
    mut table: toml::Table,
    declarations: BTreeMap<String, Declaration>,
    values: BTreeMap<String, String>,
    sources: &mut impl Sources,
    inputs: &Inputs<'_>,
    credentials: Credentials,
    roots: BTreeMap<String, PathBuf>,
) -> Result<Expanded, Unresolved> {
    let refused = |reason: String| Unresolved {
        reason,
        absent: false,
        tool: None,
    };
    let storage_section = table
        .get("storage")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    let storage = storage_directories(&storage_section, inputs.storage).map_err(refused)?;
    let rows = match storage_section.get("files") {
        None => Vec::new(),
        Some(toml::Value::Array(rows)) => rows.clone(),
        Some(_) => {
            return Err(refused(
                "`storage.files` is a list of `[[storage.files]]` rows".into(),
            ));
        }
    };
    let hook_rows = match storage_section.get("hooks") {
        None => Vec::new(),
        Some(toml::Value::Array(rows)) => rows.clone(),
        Some(_) => {
            return Err(refused(
                "`storage.hooks` is a list of `[[storage.hooks]]` rows".into(),
            ));
        }
    };
    let mcp_rows = match table.get(MCP_SERVERS) {
        None => Vec::new(),
        Some(toml::Value::Array(rows)) => rows.clone(),
        Some(_) => {
            return Err(refused(
                "`mcp-servers` is a list of `[[mcp-servers]]` rows".into(),
            ));
        }
    };
    let mut tool_rows: Vec<(String, toml::Value)> = Vec::new();
    let mut tool_storage: BTreeMap<String, BTreeMap<String, PathBuf>> = BTreeMap::new();
    if let Some(toml::Value::Table(tools)) = table.get_mut("tool") {
        for (name, tool) in tools.iter_mut() {
            let Some(section) = tool.as_table_mut().and_then(|tool| tool.remove("storage")) else {
                continue;
            };
            let at = format!("tool.{name}.storage");
            let section = section
                .as_table()
                .ok_or_else(|| refused(format!("`[{at}]` is a table")))?;
            let directories =
                tool_storage_directories(section, inputs.storage, name).map_err(refused)?;
            match section.get("files") {
                None => {}
                Some(rows @ toml::Value::Array(_)) => tool_rows.push((name.clone(), rows.clone())),
                Some(_) => {
                    return Err(refused(format!(
                        "`{at}.files` is a list of `[[{at}.files]]` rows"
                    )));
                }
            }
            tool_storage.insert(name.clone(), directories);
        }
    }
    for key in LANGUAGE_KEYS {
        table.remove(*key);
    }
    let mut resolver = Resolver {
        inputs,
        sources,
        declarations,
        values,
        storage,
        credentials,
        cache: BTreeMap::new(),
        active: Vec::new(),
        read: Vec::new(),
        programs: Vec::new(),
        absent: false,
        routing: false,
        url_reach: None,
        header_reach: None,
        commanding: false,
        command_head: false,
        roots,
        dropped: Vec::new(),
        globbing: false,
        tool: None,
        telemetry_kind: None,
        states: tool_storage
            .values()
            .flat_map(|dirs| dirs.values().cloned())
            .collect(),
        tool_storage,
        failed: None,
        developer_dir: None,
        field: "command",
        agent_head: table
            .get("agent")
            .and_then(|agent| agent.get("command"))
            .and_then(toml::Value::as_array)
            .and_then(|command| command.first())
            .and_then(toml::Value::as_str)
            .map(str::to_string),
        agent_root: None,
        skipped: BTreeMap::new(),
    };
    let mut table = resolver.fill(table).map_err(|reason| Unresolved {
        reason,
        absent: resolver.absent,
        tool: resolver.failed.take(),
    })?;
    fill_slot(&mut table).map_err(refused)?;
    let kept: BTreeSet<String> = table
        .get("tool")
        .and_then(toml::Value::as_table)
        .map(|tools| tools.keys().cloned().collect())
        .unwrap_or_default();
    resolver.tool_storage.retain(|tool, _| kept.contains(tool));
    resolver.states = resolver
        .tool_storage
        .values()
        .flat_map(|directories| directories.values().cloned())
        .collect();
    tool_rows.retain(|(tool, _)| kept.contains(tool));
    let refusals = resolver.refusals(&table);
    let files = resolver
        .files(&rows, &refusals)
        .map_err(|reason| Unresolved {
            reason,
            absent: resolver.absent,
            tool: None,
        })?;
    let hooks = resolver
        .hook_imports(&hook_rows, &files, &refusals)
        .map_err(|reason| Unresolved {
            reason,
            absent: resolver.absent,
            tool: None,
        })?;
    let mcp_sources = resolver
        .mcp_sources(&mcp_rows, &refusals)
        .map_err(|reason| Unresolved {
            reason,
            absent: resolver.absent,
            tool: None,
        })?;
    for target in mcp_sources
        .iter()
        .filter_map(|source| source.target.as_ref())
    {
        if files.iter().any(|file| {
            let overlaps =
                file.target.starts_with(&target.path) || target.path.starts_with(&file.target);
            overlaps && !fills_beside(file, target)
        }) {
            return Err(refused("an MCP target overlaps a `storage.files` target; give generated MCP configuration its own file".into()));
        }
    }
    let (copies, links) = resolver
        .tool_files(&tool_rows, &refusals)
        .map_err(|reason| Unresolved {
            reason,
            absent: resolver.absent,
            tool: None,
        })?;
    let mut files = files;
    files.extend(copies);
    files.retain(|file| !resolver.skipped.contains_key(&file.target));
    let storage = Storage {
        root: inputs.storage.to_path_buf(),
        directories: resolver.storage.values().cloned().collect(),
        tool_states: resolver.states.clone(),
        launcher_caches: Vec::new(),
        files,
        skipped: resolver.skipped.into_values().collect(),
        links,
        hooks,
        hook_scripts: Vec::new(),
        refusals,
    };
    Ok(Expanded {
        table,
        storage,
        inputs: resolver.read,
        mcp_sources,
        dropped: resolver.dropped,
    })
}

/// Each directory that `[storage] directories` names, by name: one folder for each in the agent's
/// folder of the storage root, beside what box keeps there.
fn storage_directories(
    section: &toml::Table,
    root: &Path,
) -> Result<BTreeMap<String, PathBuf>, String> {
    let directories = match section.get("directories") {
        None => Vec::new(),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or("`[storage] directories` is not a list of names")?,
        Some(_) => return Err("`[storage] directories` is not a list of names".into()),
    };
    let mut storage = BTreeMap::new();
    for directory in &directories {
        if !is_one_name(directory) {
            return Err(format!(
                "`[storage] directories` entry {directory:?} is not one directory name"
            ));
        }
        storage.insert(directory.clone(), root.join(AGENT_STORAGE).join(directory));
    }
    if let Some(key) = section
        .keys()
        .find(|key| !matches!(key.as_str(), "directories" | "files" | "hooks"))
    {
        return Err(format!("`[storage]` holds the unknown key `{key}`"));
    }
    Ok(storage)
}

/// Each directory that a tool's `[storage] directories` names, by name: one folder for each in
/// the tool's own storage, which the agent never reaches.
fn tool_storage_directories(
    section: &toml::Table,
    root: &Path,
    tool: &str,
) -> Result<BTreeMap<String, PathBuf>, String> {
    let at = format!("tool.{tool}.storage");
    if let Some(key) = section
        .keys()
        .find(|key| !matches!(key.as_str(), "directories" | "files"))
    {
        return Err(format!("`[{at}]` holds the unknown key `{key}`"));
    }
    let directories = match section.get("directories") {
        None => Vec::new(),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| format!("`[{at}] directories` is not a list of names"))?,
        Some(_) => return Err(format!("`[{at}] directories` is not a list of names")),
    };
    let mut storage = BTreeMap::new();
    for directory in &directories {
        if !is_one_name(directory) {
            return Err(format!(
                "`[{at}] directories` entry {directory:?} is not one directory name"
            ));
        }
        storage.insert(directory.clone(), tool_storage(root, tool, directory));
    }
    Ok(storage)
}

/// Every `write` and `write_file` entry of the agent, each tool, each stdio MCP server, and each
/// `[mcp.<name>]` table with no `type`, which adds to a detected server.
pub fn write_grants(table: &toml::Table, home: &Path) -> Vec<PathBuf> {
    let mut filesystems: Vec<&toml::Value> = Vec::new();
    filesystems.extend(table.get("agent").and_then(|agent| agent.get("filesystem")));
    for section in ["tool", "mcp"] {
        let Some(entries) = table.get(section).and_then(toml::Value::as_table) else {
            continue;
        };
        filesystems.extend(
            entries
                .values()
                .filter(|entry| {
                    section == "tool"
                        || matches!(
                            entry.get("type").and_then(toml::Value::as_str),
                            None | Some("stdio")
                        )
                })
                .filter_map(|entry| entry.get("filesystem")),
        );
    }
    filesystems
        .into_iter()
        .flat_map(|filesystem| {
            ["write", "write_file"]
                .into_iter()
                .filter_map(|list| filesystem.get(list).and_then(toml::Value::as_array))
                .flatten()
        })
        .filter_map(toml::Value::as_str)
        .map(|entry| match entry.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None => PathBuf::from(entry),
        })
        .filter(|grant| grant.is_absolute())
        .collect()
}

/// Whether `path`, as written or through its links, lies in `root` or in the real `root`.
pub(crate) fn lies_under(path: &Path, root: &Path) -> bool {
    let real = resolved(path);
    let real_root = resolved(root);
    [root, real_root.as_path()]
        .into_iter()
        .any(|root| within(path, root) || within(&real, root))
}

fn is_one_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && !name.contains('/')
}

fn not_a_set_value(at: &str) -> String {
    format!("`{at}` is not a string, a number, true or false, or a list of those")
}

/// `path` with one `-` for each UTF-16 unit of a character other than an ASCII letter or digit, the
/// name that Claude Code gives a project's folder.
pub fn dashed(path: &str) -> String {
    path.chars()
        .flat_map(|c| {
            let dashes = if c.is_ascii_alphanumeric() {
                0
            } else {
                c.len_utf16()
            };
            std::iter::repeat_n('-', dashes).chain((dashes == 0).then_some(c))
        })
        .collect()
}

/// Whether `file` fills the file that the MCP import `target` writes, and keeps no value in
/// the import's section.
fn fills_beside(file: &StorageFile, target: &crate::mcp_config::Target) -> bool {
    file.target == target.path
        && file.edit.as_ref().is_some_and(|edit| {
            edit.fill
                && edit.kind == target.kind
                && edit.keep.as_ref().is_some_and(|keep| {
                    keep.iter()
                        .all(|path| !path.starts_with(&target.key) && !target.key.starts_with(path))
                })
        })
}

fn string_field(table: &toml::Table, key: &str, owner: &str) -> Result<Option<String>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(toml::Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(format!("`{owner} {key}` is not a string")),
    }
}

/// The keys of a `[[storage.hooks]]` row.
const HOOK_KEYS: &[&str] = &[
    "source",
    "target",
    "kind",
    "when",
    "key",
    "keep-above",
    "only",
    "command",
    "args",
    "keep",
    "drop",
    "set",
    "disable-key",
];

/// The filesystem lists Box Core reads.
const FILESYSTEM_LISTS: &[&str] = &[
    "read",
    "write",
    "read_file",
    "write_file",
    "list",
    "metadata",
    "exec",
    "deny",
    "deny_write",
];

impl<S: Sources> Resolver<'_, S> {
    /// `table` with every placeholder filled in, then each program checked.
    fn fill(&mut self, table: toml::Table) -> Result<toml::Table, String> {
        let mut value = toml::Value::Table(table);
        refuse_unguarded_developer_dir(&value, false, &mut Vec::new())?;
        self.walk(&mut value, &mut Vec::new())?;
        let toml::Value::Table(table) = value else {
            unreachable!("a table stays a table");
        };
        self.refuse_under_grants(&table)?;
        self.refuse_node_agent(&table)?;
        Ok(table)
    }

    /// Refuse a `program` input at `[agent] command` element 0 that is a node script, because
    /// nothing grants the agent node's reads.
    fn refuse_node_agent(&self, table: &toml::Table) -> Result<(), String> {
        let Some(head) = table
            .get("agent")
            .and_then(|agent| agent.get("command"))
            .and_then(|command| command.get(0))
            .and_then(toml::Value::as_str)
        else {
            return Ok(());
        };
        match self.programs.iter().find(|program| program.value == head) {
            Some(program)
                if crate::program::runs_node(
                    &canonical(Path::new(head)).unwrap_or_else(|| PathBuf::from(head)),
                ) =>
            {
                Err(format!(
                    "`{}` = {head:?} is a node script, which the box cannot start",
                    program.name
                ))
            }
            _ => Ok(()),
        }
    }

    /// Refuse a program that an input names under a write grant of the run.
    fn refuse_under_grants(&self, table: &toml::Table) -> Result<(), String> {
        let grants: Vec<PathBuf> = write_grants(table, self.inputs.home)
            .into_iter()
            .chain(self.storage.values().cloned())
            .collect();
        for program in &self.programs {
            if let Some(grant) = grants
                .iter()
                .find(|grant| lies_under(Path::new(&program.value), grant))
            {
                let option = program
                    .name
                    .strip_prefix("inputs.")
                    .unwrap_or(&program.name);
                return Err(format!(
                    "`{}` = {:?} lies under the write grant {}, which is not allowed because the \
                     agent in the box can rewrite it. Remove the grant, or set `{option}` in your \
                     profile's `[options]` to a program outside it",
                    program.name,
                    program.value,
                    grant.display()
                ));
            }
        }
        Ok(())
    }

    /// The places a copy's source may not reach: the workspace, the run's storage, `~/.strands/box`, each
    /// write grant of `table`, and each path that a secret source protects. Box's own packs pass
    /// when only `~/.strands/box` holds them.
    fn refusals(&self, table: &toml::Table) -> Refusals {
        const BOX_HOME: &str = "the box home";
        let roots: Vec<(PathBuf, String)> = [
            (
                self.inputs.workspace.to_path_buf(),
                "the workspace".to_string(),
            ),
            (
                self.inputs.storage.to_path_buf(),
                "the run's storage".to_string(),
            ),
        ]
        .into_iter()
        .chain(
            crate::host::box_homes(self.inputs.home, self.inputs.box_home)
                .into_iter()
                .map(|box_home| (box_home, BOX_HOME.to_string())),
        )
        .chain(
            write_grants(table, self.inputs.home)
                .into_iter()
                .map(|grant| (grant, "a write grant".to_string())),
        )
        .collect();
        let others = Refusals {
            home: self.inputs.home.to_path_buf(),
            roots: roots
                .iter()
                .filter(|(_, what)| what != BOX_HOME)
                .cloned()
                .collect(),
            shipped: None,
            protected: Vec::new(),
        };
        let shipped = self
            .inputs
            .packs
            .filter(|packs| others.reach(packs).is_none())
            .map(Path::to_path_buf);
        Refusals {
            home: self.inputs.home.to_path_buf(),
            roots,
            shipped,
            protected: self.credentials.protected(self.inputs.home),
        }
    }

    /// Each `[[storage.files]]` row of each tool in `rows`, resolved and checked: the copies into
    /// the tool's own storage, and the links.
    fn tool_files(
        &mut self,
        rows: &[(String, toml::Value)],
        refusals: &Refusals,
    ) -> Result<(Vec<StorageFile>, Vec<StorageLink>), String> {
        let mut copies: Vec<StorageFile> = Vec::new();
        for (tool, rows) in rows {
            let rows = rows.as_array().expect("a list of rows");
            self.tool = Some(tool.clone());
            let files = self.files_in(rows, refusals, Some(tool));
            self.tool = None;
            copies.extend(files?);
        }
        let links = self.storage_links(rows, refusals)?;
        for file in &copies {
            if let Some(link) = links.iter().find(|link| {
                link.target.starts_with(&file.target) || file.target.starts_with(&link.target)
            }) {
                return Err(format!(
                    "`{} target` and `{} target` overlap; a copy and a link cannot share a \
                     target or lie one inside the other",
                    file.at, link.at
                ));
            }
        }
        Ok((copies, links))
    }

    /// Each link row, `mode = "link"` or `"link-children"`, of each tool's `[[storage.files]]` in
    /// `rows`, resolved and checked.
    fn storage_links(
        &mut self,
        rows: &[(String, toml::Value)],
        refusals: &Refusals,
    ) -> Result<Vec<StorageLink>, String> {
        let mut links: Vec<StorageLink> = Vec::new();
        for (tool, rows) in rows {
            let rows = rows.as_array().expect("a list of rows");
            let directories = self.tool_storage.get(tool).cloned().unwrap_or_default();
            for (index, row) in rows.iter().enumerate() {
                let at = format!("tool.{tool}.storage.files[{index}]");
                let row = row
                    .as_table()
                    .ok_or_else(|| format!("`{at}` is not a `[[storage.files]]` row"))?;
                let children = match row.get("mode").and_then(toml::Value::as_str) {
                    Some("link") => false,
                    Some("link-children") => true,
                    _ => continue,
                };
                if let Some(key) = row
                    .keys()
                    .find(|key| !matches!(key.as_str(), "source" | "target" | "mode"))
                {
                    return Err(format!(
                        "`{at}` holds the key `{key}`; a link row holds `source`, `target`, \
                         and `mode`"
                    ));
                }
                let raw = string_field(row, "source", &at)?
                    .ok_or_else(|| format!("`{at}` needs `source`"))?;
                self.tool = Some(tool.clone());
                let source = self.text(&raw, &format!("{at} source"), true);
                self.tool = None;
                let source = source?;
                let source = match source.strip_prefix("~/") {
                    Some(rest) => self.inputs.home.join(rest),
                    None => PathBuf::from(source),
                };
                if !source.is_absolute() {
                    return Err(format!("`{at} source` is not a full path"));
                }
                let relative = string_field(row, "target", &at)?
                    .ok_or_else(|| format!("`{at}` needs `target`"))?;
                let names = Path::new(&relative);
                let mut parts = names.components();
                let root = match parts.next() {
                    Some(std::path::Component::Normal(first))
                        if !has_placeholder(&relative)
                            && parts.clone().next().is_some()
                            && parts
                                .all(|part| matches!(part, std::path::Component::Normal(_))) =>
                    {
                        first
                            .to_str()
                            .and_then(|first| directories.get(first))
                            .cloned()
                            .ok_or_else(|| {
                                format!(
                                    "`{at} target` = {relative:?} does not start with one of \
                                     the tool's `[storage] directories`"
                                )
                            })?
                    }
                    _ => {
                        return Err(format!(
                            "`{at} target` = {relative:?} is not a tool storage directory and \
                             one or more names below it, such as \"rustup/toolchains\""
                        ));
                    }
                };
                if let Some(reason) = refusals
                    .reach(&source)
                    .or_else(|| refusals.protects(&source))
                {
                    return Err(format!(
                        "`{at} source`: {reason}; box links nothing from there"
                    ));
                }
                let target = root
                    .parent()
                    .expect("a tool storage directory has a parent")
                    .join(names);
                if let Some(other) = links.iter().find(|link| {
                    link.target.starts_with(&target) || target.starts_with(&link.target)
                }) {
                    return Err(format!(
                        "two link rows link {} and {}, and a row cannot link at the target of \
                         another or inside it",
                        target.display(),
                        other.target.display()
                    ));
                }
                links.push(StorageLink {
                    source,
                    target,
                    root,
                    children,
                    at,
                });
            }
        }
        Ok(links)
    }

    /// Each `[[storage.hooks]]` row, resolved, with `import` set by its `when`. A row whose `when`
    /// is false still removes the hooks of its copy.
    fn hook_imports(
        &mut self,
        rows: &[toml::Value],
        files: &[StorageFile],
        refusals: &Refusals,
    ) -> Result<Vec<HookImport>, String> {
        let mut imports: Vec<HookImport> = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            let at = format!("storage.hooks[{index}]");
            let row = row
                .as_table()
                .ok_or_else(|| format!("`{at}` is not a `[[storage.hooks]]` row"))?;
            if let Some(key) = row.keys().find(|key| !HOOK_KEYS.contains(&key.as_str())) {
                return Err(format!(
                    "`{at}` holds the unknown key `{key}`; a row holds `source`, `target`, \
                     `kind`, `when`, `key`, `keep-above`, `only`, `command`, `args`, `keep`, \
                     `drop`, `set`, and `disable-key`"
                ));
            }
            match string_field(row, "kind", &at)?.as_deref() {
                Some("json") => {}
                Some(other) => {
                    return Err(format!(
                        "`{at} kind = {other:?}` is not \"json\"; `kind` is the format of the \
                         file, and `key`, `command`, and `set` state where its hooks are"
                    ));
                }
                None => return Err(format!("`{at}` needs `kind = \"json\"`")),
            }
            let layout = self.hook_layout(row, &at)?;
            let import = match row.get("when") {
                Some(when) => self.when(when, &format!("{at} when"))?,
                None => true,
            };
            let raw = string_field(row, "source", &at)?
                .ok_or_else(|| format!("`{at}` needs `source`"))?;
            let (source, refused) = self.import_source(&raw, &format!("{at} source"), refusals)?;
            if refused.is_none() && !source.is_absolute() {
                return Err(format!("`{at} source` is not a full path"));
            }
            let relative = string_field(row, "target", &at)?
                .ok_or_else(|| format!("`{at}` needs `target`"))?;
            let (target, relative) = self.target(&relative, &at)?;
            if let Some(file) = files.iter().find(|file| {
                file.target != target
                    && (file.target.starts_with(&target) || target.starts_with(&file.target))
            }) {
                return Err(format!(
                    "`{at} target` overlaps `{}`; a hooks target is a file of its own or the \
                     same file",
                    file.at
                ));
            }
            if imports.iter().any(|other| other.target == target) {
                return Err(format!("`{at} target` is the target of another hooks row"));
            }
            imports.push(HookImport {
                source,
                refused,
                target,
                relative,
                at,
                import,
                ..layout
            });
        }
        Ok(imports)
    }

    /// Where a `[[storage.hooks]]` row finds each hook, and what an imported hook holds.
    fn hook_layout(&mut self, row: &toml::Table, at: &str) -> Result<HookImport, String> {
        let needed = |key: &str| row.get(key).ok_or_else(|| format!("`{at}` needs `{key}`"));
        let key = self.key_path(needed("key")?, &format!("{at} key"))?;
        if key.first().is_some_and(|step| step == EVERY)
            || key.last().is_none_or(|step| step != EVERY)
        {
            return Err(format!(
                "`{at} key` starts with a top-level key and ends with \"{EVERY}\", such as \
                 [\"hooks\", \"{EVERY}\"]"
            ));
        }
        let keep_above = match row.get("keep-above") {
            None => Vec::new(),
            Some(toml::Value::Array(keys)) => keys
                .iter()
                .map(|key| {
                    key.as_str()
                        .filter(|key| !key.is_empty())
                        .map(str::to_string)
                })
                .collect::<Option<_>>()
                .ok_or_else(|| {
                    format!("`{at} keep-above` is a list of keys, such as [\"name\"]")
                })?,
            Some(_) => {
                return Err(format!(
                    "`{at} keep-above` is a list of keys, such as [\"name\"]"
                ));
            }
        };
        if let Some(step) = keep_above.iter().find(|kept| key[1..].contains(kept)) {
            return Err(format!(
                "`{at} keep-above` names `{step}`, which is a key of `{at} key`"
            ));
        }
        let only = match row.get("only") {
            None => None,
            Some(toml::Value::Table(only)) => {
                let here = format!("{at} only");
                if let Some(key) = only
                    .keys()
                    .find(|key| !matches!(key.as_str(), "key" | "equals"))
                {
                    return Err(format!(
                        "`{here}` holds the unknown key `{key}`; it holds only `key` and `equals`"
                    ));
                }
                let keys = only
                    .get("key")
                    .ok_or_else(|| format!("`{here}` needs `key`"))?;
                let equals = string_field(only, "equals", &here)?
                    .ok_or_else(|| format!("`{here}` needs `equals`"))?;
                Some((self.key_path(keys, &format!("{here} key"))?, equals))
            }
            Some(_) => return Err(format!("`{at} only` is a `{{ key, equals }}` table")),
        };
        let command = self.key_path(needed("command")?, &format!("{at} command"))?;
        let args = match row.get("args") {
            None => None,
            Some(keys) => Some(self.key_path(keys, &format!("{at} args"))?),
        };
        let mut keep = Vec::new();
        match row.get("keep") {
            None => {}
            Some(toml::Value::Array(paths)) => {
                for (place, keys) in paths.iter().enumerate() {
                    keep.push(self.key_path(keys, &format!("{at} keep[{place}]"))?);
                }
            }
            Some(_) => {
                return Err(format!(
                    "`{at} keep` is a list of key lists, such as [[\"timeout\"]]"
                ));
            }
        }
        let mut drop = Vec::new();
        match row.get("drop") {
            None => {}
            Some(toml::Value::Array(entries)) => {
                for (place, entry) in entries.iter().enumerate() {
                    let here = format!("{at} drop[{place}]");
                    let toml::Value::Table(entry) = entry else {
                        drop.push(HookDrop {
                            key: self.key_path(entry, &here)?,
                            equals: None,
                        });
                        continue;
                    };
                    if let Some(key) = entry
                        .keys()
                        .find(|key| !matches!(key.as_str(), "key" | "equals"))
                    {
                        return Err(format!(
                            "`{here}` holds the unknown key `{key}`; it holds only `key` and \
                             `equals`"
                        ));
                    }
                    let keys = entry
                        .get("key")
                        .ok_or_else(|| format!("`{here}` needs `key`"))?;
                    let equals = string_field(entry, "equals", &here)?
                        .ok_or_else(|| format!("`{here}` needs `equals`"))?;
                    drop.push(HookDrop {
                        key: self.key_path(keys, &format!("{here} key"))?,
                        equals: Some(equals),
                    });
                }
            }
            Some(_) => {
                return Err(format!(
                    "`{at} drop` is a list of key lists, such as [[\"note\"]], or of \
                     `{{ key, equals }}` tables"
                ));
            }
        }
        let rows = match needed("set")? {
            toml::Value::Array(rows) if !rows.is_empty() => rows,
            _ => {
                return Err(format!(
                    "`{at} set` is a list of one or more `[[storage.hooks.set]]` rows"
                ));
            }
        };
        let mut set: Vec<HookSetting> = Vec::new();
        for (place, setting) in rows.iter().enumerate() {
            let here = format!("{at} set[{place}]");
            let setting = setting
                .as_table()
                .ok_or_else(|| format!("`{here}` is not a `[[storage.hooks.set]]` row"))?;
            if let Some(key) = setting
                .keys()
                .find(|key| !matches!(key.as_str(), "key" | "value"))
            {
                return Err(format!(
                    "`{here}` holds the unknown key `{key}`; a row holds `key` and `value`"
                ));
            }
            let keys = setting
                .get("key")
                .ok_or_else(|| format!("`{here}` needs `key`"))?;
            let key = self.key_path(keys, &format!("{here} key"))?;
            let value = setting
                .get("value")
                .ok_or_else(|| format!("`{here}` needs `value`"))?;
            let value = self.hook_value(value, &format!("{here} value"))?;
            set.push(HookSetting { key, value });
        }
        if set
            .iter()
            .map(|setting| setting.value.scripts())
            .sum::<usize>()
            != 1
        {
            return Err(format!(
                "`{at} set` holds `${{{{ {SCRIPT} }}}}` once, where the script's real path goes"
            ));
        }
        let named = |name: &str, paths: &[KeyPath]| -> Vec<(String, KeyPath)> {
            paths
                .iter()
                .enumerate()
                .map(|(place, path)| (format!("{name}[{place}]"), path.clone()))
                .collect()
        };
        let read: Vec<(String, KeyPath)> = [("command".to_string(), command.clone())]
            .into_iter()
            .chain(args.clone().map(|args| ("args".to_string(), args)))
            .collect();
        let written: Vec<(String, KeyPath)> = set
            .iter()
            .enumerate()
            .map(|(place, setting)| (format!("set[{place}] key"), setting.key.clone()))
            .collect();
        let kept = named("keep", &keep);
        let dropped = named(
            "drop",
            &drop
                .iter()
                .map(|entry| entry.key.clone())
                .collect::<Vec<_>>(),
        );
        let fields: Vec<&(String, KeyPath)> = read.iter().chain(&kept).chain(&dropped).collect();
        let outputs: Vec<&(String, KeyPath)> = kept.iter().chain(&written).collect();
        for group in [fields, outputs] {
            for (index, (name, path)) in group.iter().enumerate() {
                if let Some((other, _)) = group[..index]
                    .iter()
                    .find(|(_, earlier)| earlier.starts_with(path) || path.starts_with(earlier))
                {
                    return Err(format!(
                        "`{at} {other}` and `{at} {name}` both name {}; each names a field that \
                         no other holds",
                        shown(path)
                    ));
                }
            }
        }
        let disable_key = string_field(row, "disable-key", at)?;
        if disable_key.as_ref().is_some_and(String::is_empty) {
            return Err(format!("`{at} disable-key` is empty"));
        }
        if disable_key.as_ref() == key.first() {
            return Err(format!(
                "`{at} disable-key` is the first key of `{at} key`; it names a key of its own"
            ));
        }
        Ok(HookImport {
            key,
            keep_above,
            only,
            command,
            args,
            keep,
            drop,
            set,
            disable_key,
            ..HookImport::default()
        })
    }

    /// The value of a `[[storage.hooks.set]]` row: a string, a number, a boolean, or a list of
    /// those, where `${{ script }}` in a string is the script's real path and no other
    /// placeholder is valid.
    fn hook_value(&self, value: &toml::Value, at: &str) -> Result<HookValue, String> {
        match value {
            toml::Value::String(text) => {
                let mut parts = Vec::new();
                let mut part = String::new();
                for piece in pieces(text).map_err(|reason| format!("`{at}`: {reason}"))? {
                    match piece {
                        Piece::Name(name) if name == SCRIPT => {
                            parts.push(std::mem::take(&mut part));
                        }
                        Piece::Text(literal) => part.push_str(&literal),
                        Piece::Name(name) => {
                            return Err(format!(
                                "`{at}` holds `${{{{ {name} }}}}`; a hook's `set` value holds \
                                 text and `${{{{ {SCRIPT} }}}}` only"
                            ));
                        }
                    }
                }
                parts.push(part);
                Ok(HookValue::Text(parts))
            }
            toml::Value::Float(number) if !number.is_finite() => Err(not_a_set_value(at)),
            toml::Value::Integer(_) | toml::Value::Float(_) | toml::Value::Boolean(_) => {
                Ok(HookValue::Fixed(value.clone()))
            }
            toml::Value::Array(items) => items
                .iter()
                .enumerate()
                .map(|(index, item)| self.hook_value(item, &format!("{at}[{index}]")))
                .collect::<Result<_, _>>()
                .map(HookValue::List),
            toml::Value::Table(_) | toml::Value::Datetime(_) => Err(not_a_set_value(at)),
        }
    }

    /// Each `[[storage.files]]` row of the agent whose `when` holds, resolved and checked.
    fn files(
        &mut self,
        rows: &[toml::Value],
        refusals: &Refusals,
    ) -> Result<Vec<StorageFile>, String> {
        self.files_in(rows, refusals, None)
    }

    /// Each copy row of a `[[storage.files]]` whose `when` holds, resolved and checked: the
    /// agent's rows, or with `tool` that tool's rows, which copy into its own storage. A tool's
    /// link rows are left to [`Self::storage_links`].
    fn files_in(
        &mut self,
        rows: &[toml::Value],
        refusals: &Refusals,
        tool: Option<&str>,
    ) -> Result<Vec<StorageFile>, String> {
        let mut files: Vec<StorageFile> = Vec::new();
        let mut gates: Vec<Option<String>> = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            let at = match tool {
                None => format!("storage.files[{index}]"),
                Some(tool) => format!("tool.{tool}.storage.files[{index}]"),
            };
            let row = row
                .as_table()
                .ok_or_else(|| format!("`{at}` is not a `[[storage.files]]` row"))?;
            if tool.is_some()
                && matches!(
                    row.get("mode").and_then(toml::Value::as_str),
                    Some("link" | "link-children")
                )
            {
                continue;
            }
            if let Some(key) = row.keys().find(|key| {
                !matches!(
                    key.as_str(),
                    "source"
                        | "target"
                        | "optional"
                        | "when"
                        | "kind"
                        | "keep"
                        | "set"
                        | "fill"
                        | "sync"
                        | "mode"
                )
            }) {
                return Err(format!(
                    "`{at}` holds the unknown key `{key}`; a row holds `source`, `target`, \
                     `optional`, `when`, `kind`, `keep`, `set`, `fill`, `sync`, and `mode`"
                ));
            }
            match row.get("mode") {
                None if tool.is_some() => {
                    return Err(format!(
                        "`{at}` needs `mode`: a tool's row says `mode = \"copy\"`, \
                         `mode = \"link\"`, or `mode = \"link-children\"`"
                    ));
                }
                None => {}
                Some(toml::Value::String(mode)) if mode == "copy" => {}
                Some(toml::Value::String(mode)) if mode == "link" || mode == "link-children" => {
                    return Err(format!(
                        "`{at} mode = {mode:?}` works only in a tool's storage; the agent's rows \
                         copy"
                    ));
                }
                Some(_) => {
                    return Err(format!(
                        "`{at} mode` is \"copy\", \"link\", or \"link-children\""
                    ));
                }
            }
            if let Some(when) = row.get("when")
                && !self.when(when, &format!("{at} when"))?
            {
                continue;
            }
            let optional = match row.get("optional") {
                None => false,
                Some(toml::Value::Boolean(flag)) => *flag,
                Some(_) => return Err(format!("`{at} optional` is not true or false")),
            };
            let sync = match row.get("sync") {
                None => false,
                Some(toml::Value::Boolean(flag)) => *flag,
                Some(_) => return Err(format!("`{at} sync` is not true or false")),
            };
            let raw = string_field(row, "source", &at)?
                .ok_or_else(|| format!("`{at}` needs `source`"))?;
            let (source, refused) = self.import_source(&raw, &format!("{at} source"), refusals)?;
            if source.as_os_str().is_empty() {
                return Err(format!("`{at} source` is empty"));
            }
            let relative = string_field(row, "target", &at)?
                .ok_or_else(|| format!("`{at}` needs `target`"))?;
            let (target, relative) = self.target_in(&relative, &at, tool)?;
            if let Some(reason) = &refused {
                if !optional {
                    return Err(format!("`{at} source`: {reason}"));
                }
            } else {
                refusals
                    .check(&source)
                    .map_err(|reason| format!("`{at} source`: {reason}"))?;
            }
            let edit = self.edit(row, &at)?;
            if sync && edit.is_some() {
                return Err(format!(
                    "`{at} sync = true` works only on a row without `kind`, `keep`, `set`, or \
                     `fill` for now"
                ));
            }
            let gate = row
                .get("when")
                .and_then(|when| when.get("variable"))
                .and_then(toml::Value::as_str)
                .and_then(|variable| variable.strip_prefix("inputs."))
                .map(str::to_string);
            if let Some((other, other_gate)) = files.iter().zip(&gates).find(|(file, _)| {
                file.target.starts_with(&target) || target.starts_with(&file.target)
            }) {
                let remedy = match (other_gate, &gate) {
                    (Some(input), _) => format!(
                        "set `{input} = false` under `[options]` to turn off the copy to {:?}",
                        other.relative
                    ),
                    (None, Some(input)) => format!(
                        "set `{input} = false` under `[options]` to turn off the copy to \
                         {relative:?}"
                    ),
                    (None, None) => "remove one of the rows".to_string(),
                };
                return Err(format!(
                    "two `[[storage.files]]` rows copy to {relative:?} and {:?}, and a row \
                     cannot copy to the target of another or inside it; {remedy}",
                    other.relative
                ));
            }
            gates.push(gate);
            if let Some(reason) = refused {
                self.skipped
                    .insert(target.clone(), (source.clone(), reason));
            }
            files.push(StorageFile {
                source,
                target,
                relative,
                optional,
                at,
                edit,
                sync,
            });
        }
        Ok(files)
    }

    /// Resolve an import path, retaining a refusal of its environment-derived root.
    fn import_source(
        &mut self,
        raw: &str,
        at: &str,
        refusals: &Refusals,
    ) -> Result<(PathBuf, Option<String>), String> {
        let source = self.substitute(raw, at, true)?;
        let parts = pieces(raw)?;
        let input = match parts.as_slice() {
            [Piece::Name(name), Piece::Text(suffix), ..] if suffix.starts_with('/') => {
                name.strip_prefix("inputs.").and_then(|name| {
                    self.read
                        .iter()
                        .find(|input| input.name == name && input.source.starts_with("env:"))
                })
            }
            _ => None,
        };
        let refused = input.and_then(|input| {
            refusals
                .check_root(Path::new(&input.value))
                .err()
                .map(|reason| format!("{}: {reason}; import skipped", input.source))
        });
        if refused.is_none() {
            check_path(&source, at)?;
        } else if Path::new(raw)
            .components()
            .any(|part| part == Component::ParentDir)
        {
            return Err(format!("`{at}` = {raw:?} holds `..`"));
        }
        let source = match source.strip_prefix("~/") {
            Some(rest) => self.inputs.home.join(rest),
            None => PathBuf::from(source),
        };
        Ok((source, refused))
    }

    /// The `kind`, `keep`, and `set` of a `[[storage.files]]` row, resolved, or `None` when it has
    /// none of them.
    fn edit(&mut self, row: &toml::Table, at: &str) -> Result<Option<Edit>, String> {
        let kind = string_field(row, "kind", at)?;
        let edits = row.contains_key("keep")
            || row.contains_key("set")
            || row
                .get("fill")
                .is_some_and(|fill| fill != &toml::Value::Boolean(false));
        let kind = match (kind, edits) {
            (None, false) => return Ok(None),
            (Some(_), false) => {
                return Err(format!(
                    "`{at} kind` applies only with `keep` or `set`; a whole copy needs no kind"
                ));
            }
            (None, true) => {
                return Err(format!(
                    "`{at}` needs `kind`, \"json\" or \"toml\", for `keep` and `set`"
                ));
            }
            (Some(kind), true) => mcp::Format::named(&kind)
                .ok_or_else(|| format!("`{at} kind = {kind:?}` is not \"json\" or \"toml\""))?,
        };
        let keep = match row.get("keep") {
            None => None,
            Some(toml::Value::Array(paths)) if !paths.is_empty() => {
                let mut keep = Vec::new();
                for (place, keys) in paths.iter().enumerate() {
                    let here = format!("{at} keep[{place}]");
                    keep.push(self.key_path(keys, &here)?);
                }
                Some(keep)
            }
            Some(_) => {
                return Err(format!(
                    "`{at} keep` is a list of one or more key lists, such as [[\"model\"]]"
                ));
            }
        };
        let set = match row.get("set") {
            None => Vec::new(),
            Some(toml::Value::Array(rows)) if !rows.is_empty() => {
                let mut set: Vec<Setting> = Vec::new();
                let mut places: Vec<usize> = Vec::new();
                for (place, setting) in rows.iter().enumerate() {
                    let here = format!("{at} set[{place}]");
                    let setting = setting
                        .as_table()
                        .ok_or_else(|| format!("`{here}` is not a `[[storage.files.set]]` row"))?;
                    if let Some(key) = setting
                        .keys()
                        .find(|key| !matches!(key.as_str(), "key" | "value" | "when"))
                    {
                        return Err(format!(
                            "`{here}` holds the unknown key `{key}`; a row holds `key`, `value`, \
                             and `when`"
                        ));
                    }
                    if let Some(when) = setting.get("when")
                        && !self.when(when, &format!("{here} when"))?
                    {
                        continue;
                    }
                    let keys = setting
                        .get("key")
                        .ok_or_else(|| format!("`{here}` needs `key`"))?;
                    let key = self.key_path(keys, &format!("{here} key"))?;
                    let value = setting
                        .get("value")
                        .ok_or_else(|| format!("`{here}` needs `value`"))?;
                    let value = self.set_value(value, &format!("{here} value"))?;
                    if let Some((other, earlier)) = places.iter().zip(&set).find(|(_, earlier)| {
                        earlier.key.starts_with(&key) || key.starts_with(&earlier.key)
                    }) {
                        return Err(format!(
                            "`{at} set[{other}]` and `{here}` both set {}; each row sets one \
                             value that no other row holds",
                            shown(if key.len() < earlier.key.len() {
                                &key
                            } else {
                                &earlier.key
                            })
                        ));
                    }
                    places.push(place);
                    set.push(Setting { key, value });
                }
                set
            }
            Some(_) => {
                return Err(format!(
                    "`{at} set` is a list of one or more `[[storage.files.set]]` rows"
                ));
            }
        };
        let fill = match row.get("fill") {
            None => false,
            Some(toml::Value::Boolean(flag)) => *flag,
            Some(_) => return Err(format!("`{at} fill` is not true or false")),
        };
        if fill {
            if keep.is_none() {
                return Err(format!(
                    "`{at} fill` needs `keep`, the values that each run adds when the copy lacks them"
                ));
            }
            if !set.is_empty() {
                return Err(format!(
                    "`{at}` holds `fill` and `set`; a row that fills its copy sets no value"
                ));
            }
        }
        Ok(Some(Edit {
            kind,
            keep,
            set,
            fill,
        }))
    }

    /// A list of one or more keys, each a template field.
    fn key_path(&mut self, keys: &toml::Value, at: &str) -> Result<KeyPath, String> {
        let keys = match keys {
            toml::Value::Array(keys) if !keys.is_empty() => keys,
            _ => {
                return Err(format!(
                    "`{at}` is a list of one or more keys, such as [\"shellPath\"]"
                ));
            }
        };
        let mut path = Vec::new();
        for (place, key) in keys.iter().enumerate() {
            let key = key
                .as_str()
                .ok_or_else(|| format!("`{at}[{place}]` is not a string"))?;
            path.push(self.text(key, &format!("{at}[{place}]"), false)?);
        }
        Ok(path)
    }

    /// Each `[[mcp-servers]]` row whose `when` holds, resolved, with the reason when its file lies
    /// where a box can write or in a path that a secret source protects.
    fn mcp_sources(
        &mut self,
        rows: &[toml::Value],
        refusals: &Refusals,
    ) -> Result<Vec<mcp::Source>, String> {
        let mut sources: Vec<mcp::Source> = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            let at = format!("mcp-servers[{index}]");
            let written = mcp_row(row, &at)?;
            let active = match written.when {
                Some(when) => self.when(when, &format!("{at} when"))?,
                None => true,
            };
            let target = written
                .target
                .map(|(path, key)| -> Result<_, String> {
                    let (path, _) = self.target(&path, &at)?;
                    let mut keys = Vec::new();
                    for (place, part) in key.iter().enumerate() {
                        let part = self.text(part, &format!("{at} target-key[{place}]"), false)?;
                        if part.is_empty() {
                            return Err(format!("`{at} target-key[{place}]` is empty"));
                        }
                        keys.push(part);
                    }
                    Ok(crate::mcp_config::Target {
                        path,
                        key: keys,
                        kind: written.kind,
                    })
                })
                .transpose()?;
            if !active && target.is_none() {
                continue;
            }
            if let Some(target) = &target
                && sources
                    .iter()
                    .filter_map(|source| source.target.as_ref())
                    .any(|other| {
                        let beside = other.path == target.path
                            && other.kind == target.kind
                            && !other.key.starts_with(&target.key)
                            && !target.key.starts_with(&other.key);
                        other != target
                            && !beside
                            && (other.path.starts_with(&target.path)
                                || target.path.starts_with(&other.path))
                    })
            {
                return Err(format!(
                    "`{at} target` overlaps another MCP target with a different format or key"
                ));
            }
            if !active {
                sources.push(mcp::Source {
                    target,
                    active,
                    file: PathBuf::new(),
                    kind: written.kind,
                    key: Vec::new(),
                    env_var_locations: written.env_var_locations,
                    env_var_syntax: written.env_var_syntax,
                    refused: None,
                });
                continue;
            }
            let (file, refused) =
                self.import_source(&written.file, &format!("{at} file"), refusals)?;
            let mut keys = Vec::new();
            for (place, key) in written.keys.iter().enumerate() {
                keys.push(self.text(key, &format!("{at} key[{place}]"), false)?);
            }
            let refused = refused.or_else(|| {
                refusals
                    .reach(&file)
                    .or_else(|| refusals.protects(&file))
                    .map(|reason| format!("{reason}; box reads no MCP configuration from there"))
            });
            sources.push(mcp::Source {
                target,
                active,
                file,
                kind: written.kind,
                key: keys,
                env_var_locations: written.env_var_locations,
                env_var_syntax: written.env_var_syntax,
                refused,
            });
        }
        Ok(sources)
    }

    /// The path of a row's `target`: a declared storage directory, then one or more names.
    /// The storage path of `relative`, with each placeholder filled in, and that path relative to
    /// the storage root.
    /// A placeholder fills at most one name, never the storage directory.
    fn target(&mut self, relative: &str, at: &str) -> Result<(PathBuf, String), String> {
        self.target_in(relative, at, None)
    }

    /// [`Self::target`] in the agent's storage, or with `tool` in that tool's own storage. The
    /// path as filled in is relative to the storage root, so the agent's starts with `agent` and
    /// a tool's with `tool/<tool>`.
    fn target_in(
        &mut self,
        relative: &str,
        at: &str,
        tool: Option<&str>,
    ) -> Result<(PathBuf, String), String> {
        let written = relative;
        let relative = if has_placeholder(relative) {
            if relative.split('/').next().is_some_and(has_placeholder) {
                return Err(format!(
                    "`{at} target = {relative:?}` starts with a placeholder; it starts with a \
                     storage directory"
                ));
            }
            self.text(relative, &format!("{at} target"), false)?
        } else {
            relative.to_string()
        };
        let relative = relative.as_str();
        let parts: Vec<&str> = relative.split('/').collect();
        if written.split('/').count() != parts.len() {
            return Err(format!(
                "`{at} target = {written:?}` fills a placeholder with more than one name"
            ));
        }
        if parts.len() < 2 || parts.iter().any(|part| !is_one_name(part)) {
            return Err(format!(
                "`{at} target = {relative:?}` is not a storage directory and a path below it, \
                 such as \"config/notes.md\""
            ));
        }
        let (directory, section, shown) = match tool {
            None => (
                self.storage.get(parts[0]),
                "storage".to_string(),
                format!("{AGENT_STORAGE}/{relative}"),
            ),
            Some(tool) => (
                self.tool_storage
                    .get(tool)
                    .and_then(|directories| directories.get(parts[0])),
                format!("tool.{tool}.storage"),
                format!("{TOOL_STORAGE}/{tool}/{relative}"),
            ),
        };
        let directory = directory.ok_or_else(|| {
            format!(
                "`{at} target = {relative:?}` starts with `{}`, which `[{section}] directories` \
                 does not name",
                parts[0]
            )
        })?;
        Ok((
            parts[1..]
                .iter()
                .fold(directory.clone(), |path, part| path.join(part)),
            shown,
        ))
    }

    /// Refuse `value` in the workspace, the run's storage, or `~/.strands/box`, as written or real.
    fn refuse_writable_root(&self, name: &str, value: &str, refusal: &str) -> Result<(), String> {
        match self.writable_root(Path::new(value)) {
            Some(what) => Err(format!(
                "`inputs.{name}` = {value:?} lies in {what}, which a box can write; {refusal}"
            )),
            None => Ok(()),
        }
    }

    /// The place a box can write that `path` lies in, if any.
    fn writable_root(&self, path: &Path) -> Option<&'static str> {
        self.writable().root(path)
    }

    /// The places a box can write on every run.
    fn writable(&self) -> crate::program::Writable<'_> {
        crate::program::Writable {
            workspace: self.inputs.workspace,
            storage: self.inputs.storage,
            home: self.inputs.home,
            box_home: self.inputs.box_home,
        }
    }

    fn walk(&mut self, value: &mut toml::Value, at: &mut Vec<String>) -> Result<(), String> {
        let here = at.join(".");
        self.tool = (at.len() >= 2 && at[0] == "tool").then(|| at[1].clone());
        match value {
            toml::Value::String(text) => {
                if !has_placeholder(text) {
                    *text = self.text(text, &here, false)?;
                    return Ok(());
                }
                if !takes_template(at, self.telemetry_kind.as_deref()) {
                    return Err(format!(
                        "`{here}` is literal and holds no placeholder; placeholders go in \
                         `command`, `env`, filesystem lists, `destinations`, a route's backend \
                         `url` and `auth.aws.region`, a telemetry target's `project`, `region`, `log_group`, and \
                         `log_stream`, and the `destination` of a telemetry target that is not \
                         `file`"
                    ));
                }
                let path_field = is_command(at)
                    && (is_command_head(at)
                        || matches!(pieces(text).ok().as_deref(), Some([Piece::Name(first), ..]) if self.is_path_name(first)));
                self.routing = is_destination(at);
                self.url_reach = if is_backend_url(at) {
                    Some("a route's backend url")
                } else if is_backend_aws_region(at) {
                    Some("a route's backend auth.aws.region")
                } else if is_telemetry_destination(at) {
                    Some("a telemetry target's `destination`")
                } else {
                    None
                };
                self.header_reach =
                    is_telemetry_project(at).then_some("a telemetry target's `project`");
                self.commanding = is_command(at);
                self.command_head = is_command_head(at);
                self.field = if at.first().is_some_and(|key| key == AGENT_ARGS) {
                    AGENT_ARGS
                } else {
                    "command"
                };
                let result = self.text(text, &here, path_field);
                self.routing = false;
                self.url_reach = None;
                self.header_reach = None;
                self.commanding = false;
                self.command_head = false;
                *text = result?;
            }
            toml::Value::Array(items) if is_filesystem_list(at) => {
                let resolved = at[0] == "tool" && self.roots.contains_key(&at[1]);
                let deny = at.last().is_some_and(|list| list == "deny");
                if resolved && deny {
                    refuse_star_in_deny(items, &here)?;
                }
                let tool = (resolved && !deny).then(|| at[1].clone());
                let read_file = at.last().is_some_and(|list| list == "read_file");
                let mut kept = Vec::new();
                for (index, item) in items.iter().enumerate() {
                    let at = format!("{here}[{index}]");
                    for path in self.entry(item, &at, tool.as_deref(), read_file)? {
                        let path = toml::Value::String(path);
                        if !kept.contains(&path) {
                            kept.push(path);
                        }
                    }
                }
                if read_file {
                    let targets: Vec<_> = kept
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .map(Path::new)
                        .filter(|path| path.is_symlink())
                        .filter_map(canonical)
                        .collect();
                    kept.retain(|entry| {
                        !targets
                            .iter()
                            .any(|target| Some(target.as_path()) == entry.as_str().map(Path::new))
                    });
                }
                *items = kept;
            }
            toml::Value::Array(items) => {
                // A `{ value, when }` element is its `value` when the `when` holds.
                let mut kept = Vec::new();
                for item in items.drain(..) {
                    if let toml::Value::Table(child) = &item
                        && child.contains_key("when")
                    {
                        let mut child = match item {
                            toml::Value::Table(table) => table,
                            _ => unreachable!(),
                        };
                        let when = child.remove("when").expect("a when");
                        if !self.when(&when, &format!("{here} when"))? {
                            continue;
                        }
                        if child.len() == 1
                            && let Some(value) = child.remove("value")
                        {
                            kept.push(value);
                            continue;
                        }
                        kept.push(toml::Value::Table(child));
                    } else {
                        kept.push(item);
                    }
                }
                if at.as_slice() == ["agent", "ingress"] {
                    replace_pack_ingress(&mut kept);
                }
                *items = kept;
                for (index, item) in items.iter_mut().enumerate() {
                    at.push(index.to_string());
                    self.walk(item, at)?;
                    at.pop();
                }
            }
            toml::Value::Table(table) => {
                if let Some(key) = table.keys().find(|key| key.contains(OPEN)) {
                    return Err(format!(
                        "`{here}` has the key {key:?}; a key holds no placeholder"
                    ));
                }
                let mut off = Vec::new();
                let mut unwrap = Vec::new();
                for (key, item) in table.iter_mut() {
                    let Some(child) = item.as_table_mut() else {
                        continue;
                    };
                    let Some(when) = child.remove("when") else {
                        continue;
                    };
                    if !self.when(&when, &format!("{here}.{key} when"))? {
                        off.push(key.clone());
                        continue;
                    }
                    // `KEY = { value, when }` is its `value` when the `when` holds.
                    if child.len() == 1
                        && let Some(value) = child.remove("value")
                    {
                        unwrap.push((key.clone(), value));
                    }
                }
                for key in off {
                    table.remove(&key);
                }
                for (key, value) in unwrap {
                    table.insert(key, value);
                }
                let hosted: Vec<(String, toml::Value)> = table
                    .iter()
                    .filter_map(|(key, item)| {
                        let child = item.as_table().filter(|child| child.len() == 1)?;
                        Some((key.clone(), child.get("from")?.clone()))
                    })
                    .collect();
                for (key, from) in hosted {
                    match self.host_variable(&from, &format!("{here}.{key}"), at)? {
                        Some(value) => table.insert(key, toml::Value::String(value)),
                        None => table.remove(&key),
                    };
                }
                if is_telemetry_target(at) {
                    self.telemetry_kind = table
                        .get("kind")
                        .and_then(toml::Value::as_str)
                        .map(str::to_string);
                }
                for (key, item) in table.iter_mut() {
                    at.push(key.clone());
                    self.walk(item, at)?;
                    at.pop();
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The value of the host variable that an `env` entry `{ from = "env:<NAME>" }` names, escaped
    /// so that it stays literal, or `None` when the host does not set it.
    fn host_variable(
        &mut self,
        from: &toml::Value,
        here: &str,
        at: &[String],
    ) -> Result<Option<String>, String> {
        let mut place = at.to_vec();
        place.push(String::new());
        if !is_env_value(&place) {
            return Err(format!(
                "`{here}` holds `from`; only an `env` variable of `[agent]`, a tool, or an MCP \
                 server takes its value from the host"
            ));
        }
        let variable = from
            .as_str()
            .and_then(|from| from.strip_prefix("env:"))
            .filter(|name| {
                name.chars().next().is_some_and(|c| !c.is_ascii_digit())
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
            .ok_or_else(|| {
                format!(
                    "`{here} from` is not \"env:<NAME>\" with a name of letters, digits, and `_`"
                )
            })?;
        if let Some(holder) = self.credentials.holder(variable) {
            return Err(format!(
                "`{here}` would give the workload the host's `{variable}`, which {holder}"
            ));
        }
        let Some(value) = self.sources.env(variable) else {
            return Ok(None);
        };
        self.read.push(Input {
            name: here.to_string(),
            value: value.clone(),
            source: format!("env:{variable}"),
        });
        Ok(Some(value.replace("${{", "$${{")))
    }

    /// One filesystem list entry as the paths it resolves to: none when the entry does not apply,
    /// and, in the table of `tool`, none when its path is absent and one for each match of a `*`.
    fn entry(
        &mut self,
        item: &toml::Value,
        at: &str,
        tool: Option<&str>,
        read_file: bool,
    ) -> Result<Vec<String>, String> {
        let (raw, optional, when) = match item {
            toml::Value::String(text) => (text.clone(), false, None),
            toml::Value::Table(table) => {
                if let Some(key) = table
                    .keys()
                    .find(|key| !matches!(key.as_str(), "path" | "optional" | "when"))
                {
                    return Err(format!("`{at}` holds the unknown key `{key}`"));
                }
                let path = string_field(table, "path", at)?
                    .ok_or_else(|| format!("`{at}` needs `path`"))?;
                let optional = match table.get("optional") {
                    None => false,
                    Some(toml::Value::Boolean(flag)) => *flag,
                    Some(_) => return Err(format!("`{at} optional` is not true or false")),
                };
                let when = table.get("when").cloned();
                (path, optional, when)
            }
            _ => return Err(format!("`{at}` is not a path or an entry table")),
        };
        if let Some(when) = &when
            && !self.when(when, &format!("{at} when"))?
        {
            return Ok(Vec::new());
        }
        self.globbing = tool.is_some();
        let path = self.text(&raw, at, true);
        self.globbing = false;
        let path = path?;
        let expanded = match path.strip_prefix("~/") {
            Some(rest) => self.inputs.home.join(rest),
            None => PathBuf::from(&path),
        };
        let Some(tool) = tool else {
            if optional && std::fs::metadata(&expanded).is_err() {
                return Ok(Vec::new());
            }
            if std::fs::symlink_metadata(&expanded).is_err() {
                return Ok(vec![path]);
            }
            return self
                .grant(&path, &expanded, at, read_file)
                .map(|found| vec![found]);
        };
        if self.states.contains(&expanded) {
            return Ok(vec![path]);
        }
        let matches = matches(&expanded);
        if matches.is_empty() {
            self.dropped
                .push((tool.to_string(), path.replace(WILDCARD, "*")));
        }
        matches
            .iter()
            .map(|found| self.grant(&path.replace(WILDCARD, "*"), found, at, read_file))
            .collect()
    }

    /// The real grant path, with a `read_file` leaf link kept in its real parent folder.
    fn grant(
        &self,
        path: &str,
        expanded: &Path,
        at: &str,
        read_file: bool,
    ) -> Result<String, String> {
        let found = canonical(expanded).unwrap_or_else(|| expanded.to_path_buf());
        let spelling = if read_file && found.is_file() {
            expanded
                .parent()
                .and_then(canonical)
                .zip(expanded.file_name())
                .map(|(parent, name)| parent.join(name))
                .unwrap_or_else(|| found.clone())
        } else {
            found.clone()
        };
        for root in [self.inputs.workspace, self.inputs.storage] {
            if (expanded.starts_with(root) && found != expanded)
                || (spelling.starts_with(root) && found != spelling)
            {
                return Err(format!(
                    "`{at}` = {path:?} resolves through a link to {}, inside {}, which the box \
                     can write; name a path with no link in it",
                    found.display(),
                    root.display()
                ));
            }
        }
        if spelling != found {
            crate::mcp::check_links(
                &spelling,
                &found,
                &format!("`{at}`"),
                self.inputs.home,
                &[
                    self.inputs.workspace.to_path_buf(),
                    self.inputs.storage.to_path_buf(),
                ],
            )?;
        }
        utf8(&spelling).map_err(|error| error.to_string())
    }

    /// A `[[storage.files.set]]` value: a string with its placeholders filled in, a number, a
    /// boolean, or a list of those.
    fn set_value(&mut self, value: &toml::Value, at: &str) -> Result<toml::Value, String> {
        match value {
            toml::Value::String(text) => Ok(toml::Value::String(self.text(text, at, false)?)),
            toml::Value::Float(number) if !number.is_finite() => Err(not_a_set_value(at)),
            toml::Value::Integer(_) | toml::Value::Float(_) | toml::Value::Boolean(_) => {
                Ok(value.clone())
            }
            toml::Value::Array(items) => items
                .iter()
                .enumerate()
                .map(|(index, item)| self.set_value(item, &format!("{at}[{index}]")))
                .collect::<Result<_, _>>()
                .map(toml::Value::Array),
            toml::Value::Table(_) | toml::Value::Datetime(_) => Err(not_a_set_value(at)),
        }
    }

    /// `text` with each placeholder filled in, checked as a path when `path` is set.
    fn text(&mut self, text: &str, at: &str, path: bool) -> Result<String, String> {
        let out = self.substitute(text, at, path)?;
        if path {
            check_path(&out, at)?;
        }
        Ok(out)
    }

    /// Fill placeholders, keeping each later path placeholder within one component.
    fn substitute(&mut self, text: &str, at: &str, path: bool) -> Result<String, String> {
        let parts = pieces(text).map_err(|reason| format!("`{at}`: {reason}"))?;
        if path
            && parts.iter().any(|part| matches!(part, Piece::Name(_)))
            && !matches!(parts.first(), Some(Piece::Name(_)))
        {
            return Err(format!(
                "`{at}` = {text:?}: in a path, a placeholder comes first"
            ));
        }
        let mut out = String::new();
        for (index, part) in parts.into_iter().enumerate() {
            match part {
                Piece::Text(literal) if path && self.globbing => {
                    out.push_str(&literal.replace('*', &WILDCARD.to_string()));
                }
                Piece::Text(literal) => out.push_str(&literal),
                Piece::Name(name) => {
                    let value = self
                        .name(&name)
                        .map_err(|reason| format!("`{at}`: {reason}"))?;
                    if path
                        && index > 0
                        && (value.contains('/') || matches!(value.as_str(), "" | "." | ".."))
                    {
                        return Err(format!(
                            "`{at}`: `{name}` = {value:?} is not one path component"
                        ));
                    }
                    out.push_str(&value);
                }
            }
        }
        Ok(out)
    }

    fn name(&mut self, name: &str) -> Result<String, String> {
        let path_text = |path: &Path| utf8(path).map_err(|error| error.to_string());
        let (space, rest) = name.split_once('.').unwrap_or((name, ""));
        match (space, rest) {
            ("workspace", rest) => workspace_value(self.inputs.workspace, rest),
            ("home", "") => path_text(self.inputs.home),
            ("cache", "") => {
                let tool = self
                    .tool
                    .as_ref()
                    .ok_or("`cache` is valid only in a tool table")?;
                let root = self
                    .inputs
                    .tool_cache
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| self.inputs.workspace.join(".cache"));
                let cache = root.join(tool);
                path_text(&cache)
            }
            ("profile", "") => path_text(self.inputs.profile),
            ("profile", "file") => path_text(self.inputs.profile_file),
            ("box", "") => path_text(self.inputs.box_dir),
            ("storage", directory) if !directory.is_empty() => {
                let own = self
                    .tool
                    .as_ref()
                    .and_then(|tool| self.tool_storage.get(tool))
                    .and_then(|directories| directories.get(directory));
                if let Some(path) = own {
                    return path_text(path);
                }
                let path = self.storage.get(directory).ok_or_else(|| {
                    format!("`storage.{directory}` is not in `[storage] directories`")
                })?;
                path_text(path)
            }
            ("inputs", input) if !input.is_empty() => self.input(input),
            ("tool", rest) if tool_root(rest).is_some() => {
                let (tool, steps) = tool_root(rest).expect("a tool root");
                let root = self.roots.get(tool).ok_or_else(|| {
                    format!("`tool.{tool}.root` names no `[tool.{tool}]` with a `program` that this host has")
                })?;
                path_text(&climb(root, steps, "root")?)
            }
            ("macos", "sdk_root") => self.under_developer_dir(name, SDK_ROOTS, ""),
            ("macos", "toolchain") => self.under_developer_dir(name, TOOLCHAINS, "cc"),
            ("macos", "developer_dir") => self.developer_dir(),
            ("pack", "") => Err("`pack` was not bound to a profile folder".into()),
            ("root", steps) => {
                let root = self.agent_root()?;
                path_text(&climb(&root, steps, "root")?)
            }
            _ => Err(format!(
                "`{name}` is not a name; use workspace, workspace.dashed, home, pack, profile, profile.file, box, \
                 storage.<dir>, inputs.<name>, root, tool.<name>.root, macos.developer_dir, \
                 macos.sdk_root, or macos.toolchain"
            )),
        }
    }

    /// The folder that holds the real file of the program that `[agent] command` runs.
    fn agent_root(&mut self) -> Result<PathBuf, String> {
        if let Some(root) = &self.agent_root {
            return Ok(root.clone());
        }
        let head = self.agent_head.take().ok_or(
            "`[agent] command` element 0 names the program that `root` comes from, so it cannot \
             name `root`, and `[agent]` needs a `command`",
        )?;
        let saved = (
            self.routing,
            self.url_reach,
            self.header_reach,
            self.commanding,
            self.command_head,
            self.field,
        );
        (
            self.routing,
            self.url_reach,
            self.header_reach,
            self.commanding,
            self.command_head,
            self.field,
        ) = (false, None, None, true, true, "command");
        let program = self.text(&head, "agent.command.0", true);
        (
            self.routing,
            self.url_reach,
            self.header_reach,
            self.commanding,
            self.command_head,
            self.field,
        ) = saved;
        self.agent_head = Some(head);
        let program = program?;
        if !Path::new(&program).is_absolute() {
            return Err(format!(
                "`root` needs `[agent] command` element 0 to be an absolute path, not {program:?}"
            ));
        }
        let real = canonical(Path::new(&program)).unwrap_or_else(|| PathBuf::from(&program));
        let root = crate::tool::root(&real);
        self.agent_root = Some(root.clone());
        Ok(root)
    }

    /// The Apple developer folder that `/usr/bin/xcode-select -p` reports, asked for once.
    fn developer_dir(&mut self) -> Result<String, String> {
        if self.inputs.os != "macos" {
            return Err(format!(
                "`{DEVELOPER_DIR}` is valid only under `when = \"macos\"`"
            ));
        }
        let found = match &self.developer_dir {
            Some(found) => found.clone(),
            None => {
                let found = self.sources.developer_dir();
                if let Ok(value) = &found {
                    self.read.push(Input {
                        name: DEVELOPER_DIR.to_string(),
                        value: value.clone(),
                        source: XCODE_SELECT.to_string(),
                    });
                }
                self.developer_dir = Some(found.clone());
                found
            }
        };
        found.map_err(|reason| {
            if let Some(tool) = self.tool.clone() {
                self.failed = Some((tool, format!("{XCODE_SELECT} {reason}")));
            }
            format!("`{DEVELOPER_DIR}`: {XCODE_SELECT} {reason}")
        })
    }

    /// The first of `candidates` under the developer folder that holds `marker`.
    fn under_developer_dir(
        &mut self,
        name: &str,
        candidates: &[&str],
        marker: &str,
    ) -> Result<String, String> {
        let folder = self.developer_dir()?;
        let found = candidates
            .iter()
            .map(|candidate| Path::new(&folder).join(candidate))
            .find(|candidate| {
                if marker.is_empty() {
                    candidate.is_dir()
                } else {
                    self.candidate(&candidate.join(marker)).is_ok()
                }
            })
            .and_then(|candidate| canonical(&candidate));
        let Some(found) = found else {
            let reason = format!(
                "`{name}`: the developer folder {folder} holds none of {}",
                candidates.join(", ")
            );
            if let Some(tool) = self.tool.clone() {
                self.failed = Some((tool, reason.clone()));
            }
            return Err(reason);
        };
        let value = utf8(&found).map_err(|error| error.to_string())?;
        if !self.read.iter().any(|input| input.name == name) {
            self.read.push(Input {
                name: name.to_string(),
                value: value.clone(),
                source: DEVELOPER_DIR.to_string(),
            });
        }
        Ok(value)
    }

    /// Whether the placeholder `name` holds a path.
    fn is_path_name(&self, name: &str) -> bool {
        let (space, rest) = name.split_once('.').unwrap_or((name, ""));
        match space {
            "workspace" => rest != "dashed",
            "home" | "profile" | "box" | "cache" => rest.is_empty(),
            "storage" => !rest.is_empty(),
            "tool" => tool_root(rest).is_some(),
            "root" => true,
            "macos" => is_macos_name(rest),
            "inputs" => self
                .declarations
                .get(rest)
                .is_some_and(|declaration| declaration.kind == "program"),
            _ => false,
        }
    }

    /// Whether a `when` holds: a string, or a `{ variable, equals }` table.
    fn when(&mut self, when: &toml::Value, at: &str) -> Result<bool, String> {
        match when {
            toml::Value::String(text) => self.when_string(text, at),
            toml::Value::Table(table) => self.when_table(table, at),
            _ => Err(format!(
                "`{at}` is not a when; use a string or `{{ variable, equals }}`"
            )),
        }
    }

    /// Whether a string `when` holds: an OS name, or a placeholder for a `bool` input.
    fn when_string(&mut self, when: &str, at: &str) -> Result<bool, String> {
        if matches!(when, "macos" | "linux") {
            return Ok(when == self.inputs.os);
        }
        if !has_placeholder(when) {
            return Err(format!(
                "`{at} = {when:?}`; use macos, linux, or a placeholder for a bool input"
            ));
        }
        match self.text(when, at, false)?.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(format!("`{at}` is {other:?}, not true or false")),
        }
    }

    /// Whether a `{ variable, equals }` `when` holds: the name `variable` resolves to `equals`.
    fn when_table(&mut self, table: &toml::Table, at: &str) -> Result<bool, String> {
        if let Some(key) = table
            .keys()
            .find(|key| !matches!(key.as_str(), "variable" | "equals"))
        {
            return Err(format!(
                "`{at}` holds the unknown key `{key}`; a when-table holds only `variable` and \
                 `equals`"
            ));
        }
        let variable = string_field(table, "variable", at)?
            .ok_or_else(|| format!("`{at}` needs `variable`"))?;
        let equals =
            string_field(table, "equals", at)?.ok_or_else(|| format!("`{at}` needs `equals`"))?;
        let value = self
            .name(&variable)
            .map_err(|reason| format!("`{at} variable`: {reason}"))?;
        Ok(value == equals)
    }

    fn input(&mut self, name: &str) -> Result<String, String> {
        let key = format!("inputs.{name}");
        let declaration = self
            .declarations
            .get(name)
            .cloned()
            .ok_or_else(|| format!("`{key}` is not an input that a pack declares"))?;
        let bounded = !declaration.patterns.is_empty()
            || !declaration.values.is_empty()
            || declaration.kind == "bool";
        if self.routing && !bounded {
            return Err(format!(
                "`{key}` reaches a route's destinations, so `[inputs.{name}]` needs `pattern` \
                 or `values`"
            ));
        }
        if let Some(reach) = self.url_reach
            && !bounded
        {
            return Err(format!(
                "`{key}` reaches {reach}, so `[inputs.{name}]` needs `pattern` or `values`"
            ));
        }
        if self.commanding && !bounded && !(self.command_head && declaration.kind == "program") {
            return Err(format!(
                "`{key}` reaches `{}`, so `[inputs.{name}]` needs `pattern` or `values`",
                self.field
            ));
        }
        if let Some(value) = self.cache.get(&key).cloned() {
            check_header_value(
                name,
                self.header_reach,
                &value,
                self.values.contains_key(name),
            )?;
            return Ok(value);
        }
        if self.active.contains(&key) {
            return Err(format!("`{key}` depends on itself"));
        }
        self.active.push(key.clone());
        let (routing, url_reach, header_reach, commanding, head) = (
            self.routing,
            self.url_reach,
            self.header_reach,
            self.commanding,
            self.command_head,
        );
        self.routing = false;
        self.url_reach = None;
        self.header_reach = None;
        self.commanding = false;
        self.command_head = false;
        let resolved = self.value_of(name, &declaration);
        self.routing = routing;
        self.url_reach = url_reach;
        self.header_reach = header_reach;
        self.commanding = commanding;
        self.command_head = head;
        self.active.pop();
        let (mut value, source, written) = resolved?;
        check_value(name, &declaration, &value)?;
        check_header_value(
            name,
            self.header_reach,
            &value,
            self.values.contains_key(name),
        )?;
        if declaration.kind == "program" {
            self.check_program(name, &value)?;
            if !declaration.searches.is_empty() && source != "search" {
                value = self
                    .candidate(Path::new(&value))
                    .map_err(|why| format!("`inputs.{name}` = {value:?} is {why}"))?;
            }
            for path in std::iter::once(&value).chain((written != value).then_some(&written)) {
                self.programs.push(HostProgram {
                    name: format!("inputs.{name}"),
                    value: path.clone(),
                });
            }
        }
        self.read.push(Input {
            name: name.to_string(),
            value: value.clone(),
            source,
        });
        self.cache.insert(key, value.clone());
        Ok(value)
    }

    /// The value of an input: the profile's, else its `from` source, else its default.
    fn value_of(
        &mut self,
        name: &str,
        declaration: &Declaration,
    ) -> Result<(String, String, String), String> {
        if let Some(value) = self.values.get(name) {
            return Ok((value.clone(), "your profile".to_string(), value.clone()));
        }
        fn distinct<T: Ord>(items: &[(String, T)]) -> usize {
            let mut seen: Vec<&T> = items.iter().map(|(_, value)| value).collect();
            seen.sort();
            seen.dedup();
            seen.len()
        }
        fn disagree<T: std::fmt::Display>(name: &str, what: &str, items: &[(String, T)]) -> String {
            format!(
                "the packs that declare `inputs.{name}` give different {what}s ({}); set \
                 `{name}` in your profile's `[options]`",
                items
                    .iter()
                    .map(|(pack, value)| format!("{pack}: {:?}", value.to_string()))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        if distinct(&declaration.froms) > 1 {
            return Err(disagree(name, "source", &declaration.froms));
        }
        let mut unread = None;
        if let Some((_, HostSource { from, key })) = declaration.froms.first()
            && let Some(variable) = from.strip_prefix("env:")
        {
            if let Some(holder) = self.credentials.holder(variable) {
                return Err(format!(
                    "`inputs.{name}` would give the workload the host's `{variable}`, which \
                     {holder}"
                ));
            }
            let value = self.sources.env(variable).filter(|value| !value.is_empty());
            match (key, value) {
                (None, Some(value)) => return Ok((value.clone(), from.clone(), value)),
                (None, None) => {}
                (Some(key), Some(list)) => match list_value(&list, key).map_err(|why| {
                    format!("`inputs.{name}` reads `{key}` from `{variable}`, {why}")
                })? {
                    Some(value) => return Ok((value.clone(), from.clone(), value)),
                    None => unread = Some(format!("`{variable}` holds no value for `{key}`")),
                },
                (Some(key), None) => {
                    unread = Some(format!(
                        "`{variable}` is not set or is empty, so it holds no value for `{key}`"
                    ));
                }
            }
        }
        if distinct(&declaration.searches) > 1 {
            return Err(disagree(name, "search list", &declaration.searches));
        }
        if let Some((_, search)) = declaration.searches.first() {
            if let Some((pack, _)) = declaration.defaults.first() {
                return Err(format!(
                    "`inputs.{name}` has a `search` in {} and a `default` in {pack}; set `{name}` \
                     in your profile's `[options]`",
                    declaration.searches[0].0
                ));
            }
            let (value, written) = self.find(name, search)?;
            return Ok((value, "search".to_string(), written));
        }
        if distinct(&declaration.defaults) > 1 {
            return Err(disagree(name, "default", &declaration.defaults));
        }
        let Some((_, default)) = declaration.defaults.first().cloned() else {
            let why = unread.map(|why| format!(": {why}")).unwrap_or_default();
            return Err(format!(
                "`inputs.{name}` has no value{why}; set `{name}` in your profile's `[options]`"
            ));
        };
        let value = self.text(&default, &format!("[inputs.{name}] default"), false)?;
        Ok((value.clone(), "default".to_string(), value))
    }

    /// The real file of the first `program` in the folders of `search` that the box can run.
    fn find(&mut self, name: &str, search: &Search) -> Result<(String, String), String> {
        let at = format!("[inputs.{name}] search");
        let mut passed = Vec::new();
        for folder in &search.folders {
            let folders = self.folders(folder, &at)?;
            for candidate in crate::program::candidates(folders, &search.program) {
                match self.candidate(&candidate) {
                    Ok(real) => {
                        let written = utf8(&candidate).map_err(|error| error.to_string())?;
                        return Ok((real, written));
                    }
                    Err(why) => passed.push(format!("{} ({why})", candidate.display())),
                }
            }
        }
        self.absent = true;
        let mut reason = format!(
            "no `{}` that the box can run in the folders `{at}` names",
            search.program
        );
        if !passed.is_empty() {
            reason.push_str(&format!("; passed over {}", passed.join(", ")));
        }
        reason.push_str(&format!(
            ". Install it, or set `{name}` in your profile's `[options]`"
        ));
        Err(reason)
    }

    /// The folders that one `search` entry names, in the order `search` tries them.
    fn folders(&mut self, folder: &Folder, at: &str) -> Result<Vec<PathBuf>, String> {
        match folder {
            Folder::Env(variable) => {
                if let Some(holder) = self.credentials.holder(variable) {
                    return Err(format!(
                        "`{at}` would give the workload the host's `{variable}`, which {holder}"
                    ));
                }
                Ok(self
                    .sources
                    .env(variable)
                    .map(|value| {
                        std::env::split_paths(&value)
                            .filter(|path| path.is_absolute())
                            .collect()
                    })
                    .unwrap_or_default())
            }
            Folder::Path(text) => {
                let globbing = std::mem::replace(&mut self.globbing, true);
                let expanded = self.text(text, at, true);
                self.globbing = globbing;
                let expanded = crate::host::expand_home(self.inputs.home, Path::new(&expanded?));
                if !expanded.to_string_lossy().contains(WILDCARD) {
                    return Ok(vec![expanded]);
                }
                let mut found = matches(&expanded);
                found.sort_by(|a, b| newest(b).cmp(&newest(a)));
                Ok(found)
            }
        }
    }

    /// The real file of `candidate`, or why the box cannot run it.
    fn candidate(&self, candidate: &Path) -> Result<String, String> {
        use crate::program::{self, Refused};
        let checked =
            program::check(candidate, &self.writable()).map_err(|refused| match refused {
                Refused::Planted { what, .. } => format!("in {what}, which a box can write"),
                Refused::Dangling => "a link to nothing".to_string(),
                Refused::NotExecutable => "not an executable file".to_string(),
            })?;
        if program::runs_node(&checked.real) {
            return Err("a node script, which the box cannot start".into());
        }
        utf8(&checked.real).map_err(|error| error.to_string())
    }

    /// Refuse a program that is not an absolute executable file outside where a box can write.
    fn check_program(&self, name: &str, value: &str) -> Result<(), String> {
        let program = Path::new(value);
        if !program.is_absolute() {
            return Err(format!(
                "`inputs.{name}` = {value:?} is not an absolute path"
            ));
        }
        if !is_executable_file(program) {
            return Err(format!(
                "`inputs.{name}` = {value:?} is not an executable file"
            ));
        }
        self.refuse_writable_root(name, value, "box runs no program from there")
    }
}

/// Each existing path that `pattern` names, where a `WILDCARD` matches any run of characters in one
/// component, in name order.
fn matches(pattern: &Path) -> Vec<PathBuf> {
    let mut found = vec![PathBuf::new()];
    for component in pattern.components() {
        let part = component.as_os_str().to_string_lossy();
        if !part.contains(WILDCARD) {
            found = found.into_iter().map(|path| path.join(&*part)).collect();
            continue;
        }
        let pieces: Vec<&str> = part.split(WILDCARD).collect();
        found = found
            .into_iter()
            .flat_map(|directory| {
                let mut names: Vec<String> = std::fs::read_dir(&directory)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .filter(|name| fits(name, &pieces))
                    .collect();
                names.sort();
                names.into_iter().map(move |name| directory.join(name))
            })
            .collect();
    }
    found
        .into_iter()
        .filter(|path| std::fs::symlink_metadata(path).is_ok())
        .collect()
}

/// The tool and the steps of a `tool.<name>.root` name, from the part after `tool.`.
fn tool_root(rest: &str) -> Option<(&str, &str)> {
    let (tool, after) = rest.split_once('.')?;
    match after.strip_prefix("root")? {
        "" => Some((tool, "")),
        steps => steps.strip_prefix('.').map(|steps| (tool, steps)),
    }
}

/// The SDK folders under a developer folder, Xcode's first.
const SDK_ROOTS: &[&str] = &[
    "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
    "SDKs/MacOSX.sdk",
];

/// The folders under a developer folder that can hold the compiler driver `cc`, Xcode's first.
const TOOLCHAINS: &[&str] = &["Toolchains/XcodeDefault.xctoolchain/usr/bin", "usr/bin"];

/// Whether `rest` is a built-in name in the `macos` space.
fn is_macos_name(rest: &str) -> bool {
    matches!(rest, "developer_dir" | "sdk_root" | "toolchain")
}

/// The key that sorts `search` matches: the numbers in the path, left to right, then the path.
fn newest(path: &Path) -> (Vec<u64>, &Path) {
    let numbers = path
        .to_string_lossy()
        .split(|character: char| !character.is_ascii_digit())
        .filter_map(|part| part.parse().ok())
        .collect();
    (numbers, path)
}

/// Whether `name` is `pieces` joined by any runs of characters.
pub fn fits(name: &str, pieces: &[&str]) -> bool {
    let (Some(first), Some(last)) = (pieces.first(), pieces.last()) else {
        return false;
    };
    if pieces.len() < 2 || !name.starts_with(first) || !name.ends_with(last) {
        return false;
    }
    let Some(mut rest) = name.get(first.len()..name.len().saturating_sub(last.len())) else {
        return false;
    };
    if first.len() + last.len() > name.len() {
        return false;
    }
    for piece in &pieces[1..pieces.len() - 1] {
        match rest.find(piece) {
            Some(at) => rest = &rest[at + piece.len()..],
            None => return false,
        }
    }
    true
}

/// Refuse a literal `*` in a `deny` entry of a tool table, because Box Core matches no pattern.
fn refuse_star_in_deny(items: &[toml::Value], here: &str) -> Result<(), String> {
    for (index, item) in items.iter().enumerate() {
        let raw = match item {
            toml::Value::String(text) => Some(text.as_str()),
            toml::Value::Table(table) => table.get("path").and_then(toml::Value::as_str),
            _ => None,
        };
        let starred = raw.is_some_and(|raw| {
            pieces(raw)
                .unwrap_or_default()
                .iter()
                .any(|piece| matches!(piece, Piece::Text(text) if text.contains('*')))
        });
        if starred {
            return Err(format!(
                "`{here}[{index}]` holds `*`; a `deny` entry names one path, because Box Core \
                 matches no pattern"
            ));
        }
    }
    Ok(())
}

/// The built-in name of the Apple developer folder.
pub(crate) const DEVELOPER_DIR: &str = "macos.developer_dir";

/// The host program that reports the Apple developer folder, as an operator reads it.
const XCODE_SELECT: &str = "xcode-select -p";

/// Refuse `macos.developer_dir` in a value that no `when = "macos"` governs.
fn refuse_unguarded_developer_dir(
    value: &toml::Value,
    guarded: bool,
    at: &mut Vec<String>,
) -> Result<(), String> {
    match value {
        toml::Value::String(text) if !guarded => {
            let named =
                pieces(text)
                    .unwrap_or_default()
                    .into_iter()
                    .find_map(|piece| match piece {
                        Piece::Name(name)
                            if name.strip_prefix("macos.").is_some_and(is_macos_name) =>
                        {
                            Some(name)
                        }
                        _ => None,
                    });
            if let Some(name) = named {
                return Err(format!(
                    "`{}` names `{name}`, which is valid only under `when = \"macos\"`",
                    at.join(".")
                ));
            }
            Ok(())
        }
        toml::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                at.push(index.to_string());
                refuse_unguarded_developer_dir(item, guarded, at)?;
                at.pop();
            }
            Ok(())
        }
        toml::Value::Table(table) => {
            let guarded =
                guarded || table.get("when").and_then(toml::Value::as_str) == Some("macos");
            for (key, item) in table {
                at.push(key.clone());
                refuse_unguarded_developer_dir(item, guarded, at)?;
                at.pop();
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn is_filesystem_list(at: &[String]) -> bool {
    match at {
        [filesystem, list] => {
            filesystem == PROFILE_FILESYSTEM && PROFILE_LISTS.contains(&list.as_str())
        }
        [process, filesystem, list] if process == "agent" => {
            filesystem == "filesystem" && FILESYSTEM_LISTS.contains(&list.as_str())
        }
        [section, _, filesystem, list] if section == "tool" || section == "mcp" => {
            filesystem == "filesystem" && FILESYSTEM_LISTS.contains(&list.as_str())
        }
        _ => false,
    }
}

/// Whether `at` is an element of a process's `command`, or of `agent-args`, which fills one.
fn is_command(at: &[String]) -> bool {
    match at {
        [args, _] if args == AGENT_ARGS => true,
        [process, command, _] if process == "agent" => command == "command",
        [section, _, command, _]
            if section == "tool" || section == "mcp" || section == SECRET_SOURCE =>
        {
            command == "command"
        }
        _ => false,
    }
}

/// Whether `at` is the program of a process's `command`. An `agent-args` element never is.
fn is_command_head(at: &[String]) -> bool {
    is_command(at)
        && at.first().is_some_and(|key| key != AGENT_ARGS)
        && at.last().is_some_and(|index| index == "0")
}

fn is_destination(at: &[String]) -> bool {
    matches!(at, [section, _, field, _] if (section == "egress" || section == "mcp") && field == "destinations")
}

/// Whether `at` is the `url` of a `[[egress.<name>.backends]]` or a `[[mcp.<name>.backends]]`.
fn is_backend_url(at: &[String]) -> bool {
    matches!(at, [section, _, backends, _, field] if (section == "egress" || section == "mcp") && backends == "backends" && field == "url")
}

/// The plain settings of a `[telemetry.<label>]` target.
const TELEMETRY_SETTINGS: &[&str] = &[
    "destination",
    "project",
    "region",
    "log_group",
    "log_stream",
];

/// The `kind` of a telemetry target whose `destination` is a literal file path, not a URL.
const FILE_TELEMETRY_KIND: &str = "file";

/// Whether `at` is a `[telemetry.<label>]` target.
fn is_telemetry_target(at: &[String]) -> bool {
    matches!(at, [section, _] if section == "telemetry")
}

/// Whether `at` is a plain setting of a `[telemetry.<label>]` target.
fn is_telemetry_setting(at: &[String]) -> bool {
    matches!(at, [section, _, field] if section == "telemetry" && TELEMETRY_SETTINGS.contains(&field.as_str()))
}

/// Whether `at` is the `destination` of a `[telemetry.<label>]` target.
fn is_telemetry_destination(at: &[String]) -> bool {
    matches!(at, [section, _, field] if section == "telemetry" && field == "destination")
}

/// Whether `at` is the `project` of a `[telemetry.<label>]` target.
fn is_telemetry_project(at: &[String]) -> bool {
    matches!(at, [section, _, field] if section == "telemetry" && field == "project")
}

/// Refuse a value of `inputs.<name>` for `reach` that holds a control character, or that starts or
/// ends with white space when the profile did not write it.
fn check_header_value(
    name: &str,
    reach: Option<&str>,
    value: &str,
    from_profile: bool,
) -> Result<(), String> {
    let Some(reach) = reach else {
        return Ok(());
    };
    if value.contains(char::is_control) {
        return Err(format!(
            "`inputs.{name}` = {value:?} fills {reach}, so it cannot hold a control character"
        ));
    }
    if !from_profile && value.trim() != value {
        return Err(format!(
            "`inputs.{name}` = {value:?} fills {reach}, so it cannot start or end with white space"
        ));
    }
    Ok(())
}

/// Whether `at` is the `auth.aws.region` of a `[[egress.<name>.backends]]` or a
/// `[[mcp.<name>.backends]]`: the region an `aws://` backend auth signs for. A deployed service
/// runs in one region, which it sets in the environment that runs `box`.
fn is_backend_aws_region(at: &[String]) -> bool {
    matches!(at, [section, _, backends, _, auth, aws, field] if (section == "egress" || section == "mcp") && backends == "backends" && auth == "auth" && aws == "aws" && field == "region")
}

/// Whether the string at `at`, in a telemetry target of `telemetry_kind`, may hold a placeholder.
/// Every other field is literal.
fn takes_template(at: &[String], telemetry_kind: Option<&str>) -> bool {
    is_command(at)
        || is_destination(at)
        || is_backend_url(at)
        || is_backend_aws_region(at)
        || (is_telemetry_setting(at)
            && !(is_telemetry_destination(at) && telemetry_kind == Some(FILE_TELEMETRY_KIND)))
        || is_filesystem_list(&at[..at.len().saturating_sub(1)])
        || at.last().is_some_and(|key| key == "when")
        || is_env_value(at)
}

/// Whether `at` is one variable of the `env` table of `[agent]`, a `[tool.<name>]`, or an
/// `[mcp.<name>]`.
fn is_env_value(at: &[String]) -> bool {
    let env = |rest: &[String]| matches!(rest, [env, _] if env == "env");
    match at {
        [process, rest @ ..] if process == "agent" => env(rest),
        [section, _, rest @ ..] if section == "tool" || section == "mcp" => env(rest),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dashed_workspace_writes_one_dash_for_each_utf16_unit_as_claude_code_does() {
        for (path, name) in [
            ("/Users/me/src/my-app", "-Users-me-src-my-app"),
            ("/a/my.app_1", "-a-my-app-1"),
            ("/a/éapp", "-a--app"),
            ("/a/🚀app", "-a---app"),
        ] {
            assert_eq!(dashed(path), name, "{path}");
        }
    }

    #[test]
    fn a_workspace_parent_step_moves_to_the_folder_above() {
        let workspace = Path::new("/Users/me/src/my-app");
        for (rest, value) in [
            ("", "/Users/me/src/my-app"),
            ("parent", "/Users/me/src"),
            ("parent.parent", "/Users/me"),
            ("dashed", "-Users-me-src-my-app"),
        ] {
            assert_eq!(workspace_value(workspace, rest), Ok(value.into()), "{rest}");
        }
    }

    #[test]
    fn a_workspace_parent_step_at_the_top_stays_at_the_top() {
        assert_eq!(
            workspace_value(Path::new("/a"), "parent.parent.parent"),
            Ok("/".into())
        );
        assert_eq!(workspace_value(Path::new("/"), "parent"), Ok("/".into()));
    }

    #[test]
    fn a_workspace_step_other_than_parent_names_workspace() {
        assert_eq!(
            workspace_value(Path::new("/a/b"), "up"),
            Err("`up` is not a step of `workspace`; use `parent`".into())
        );
        assert_eq!(
            workspace_value(Path::new("/a/b"), "parent.up"),
            Err("`up` is not a step of `workspace`; use `parent`".into())
        );
        assert_eq!(
            climb(Path::new("/a/b"), "up", "root"),
            Err("`up` is not a step of `root`; use `parent`".into())
        );
    }

    #[test]
    fn dashed_follows_only_the_workspace_itself() {
        for rest in ["parent.dashed", "dashed.parent", "dashed.dashed"] {
            assert_eq!(
                workspace_value(Path::new("/a/b"), rest),
                Err(format!(
                    "`workspace.{rest}`: `dashed` comes only right after `workspace`, as \
                     `workspace.dashed`"
                )),
                "{rest}"
            );
        }
    }

    #[test]
    fn a_string_splits_into_text_and_names() {
        assert_eq!(
            pieces("a${{ home }}/b").unwrap(),
            vec![
                Piece::Text("a".into()),
                Piece::Name("home".into()),
                Piece::Text("/b".into())
            ]
        );
        assert_eq!(
            pieces("${OTEL}").unwrap(),
            vec![Piece::Text("${OTEL}".into())]
        );
        assert_eq!(
            pieces("x$${{ home }}").unwrap(),
            vec![Piece::Text("x${{ home }}".into())]
        );
        assert!(pieces("${{ home").is_err());
        assert!(pieces("${{ a b }}").is_err());
    }

    #[test]
    fn binding_keeps_other_placeholders_and_escapes() {
        assert_eq!(
            bind("${{ pack }}/x ${{ home }} $${{ y }}", "pack", "/p").unwrap(),
            "/p/x ${{ home }} $${{ y }}"
        );
    }

    #[test]
    fn a_later_layer_wins_a_scalar_and_lists_join() {
        let mut base: toml::Table = toml::from_str("a = 1\nl = [\"x\"]\n[t]\nk = \"old\"").unwrap();
        merge_table(
            &mut base,
            toml::from_str("a = 2\nl = [\"x\", \"y\"]\n[t]\nk = \"new\"").unwrap(),
            &mut Vec::new(),
        );
        assert_eq!(base["a"].as_integer(), Some(2));
        assert_eq!(base["l"].as_array().unwrap().len(), 2);
        let mut agent: toml::Table = toml::from_str(
            "[agent]\ncommand = [\"a\", \"--set\"]\n[agent.filesystem]\nread = [\"/x\"]",
        )
        .unwrap();
        merge_table(
            &mut agent,
            toml::from_str("[agent]\ncommand = [\"b\", \"--set\", \"--set\"]\n[agent.filesystem]\nread = [\"/y\"]")
                .unwrap(),
            &mut Vec::new(),
        );
        assert_eq!(agent["agent"]["command"].as_array().unwrap().len(), 3);
        assert_eq!(
            agent["agent"]["filesystem"]["read"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(base["t"]["k"].as_str(), Some("new"));
    }

    fn declaration(text: &str) -> toml::Table {
        toml::from_str(text).expect("TOML")
    }

    #[test]
    fn two_declarations_of_one_input_keep_every_constraint() {
        let mut declarations = BTreeMap::new();
        declare(
            &mut declarations,
            "tool.program",
            "@box/a",
            &declaration("type = \"program\""),
        )
        .unwrap();
        declare(
            &mut declarations,
            "tool.program",
            "@box/b",
            &declaration("type = \"program\"\npattern = \"/.*\""),
        )
        .unwrap();
        declare(
            &mut declarations,
            "tool.program",
            "@box/c",
            &declaration("type = \"program\"\nvalues = [\"/a\"]"),
        )
        .unwrap();
        let found = &declarations["tool.program"];
        assert_eq!(found.patterns, ["/.*"]);
        assert_eq!(found.values, [vec!["/a".to_string()]]);
        assert_eq!(found.packs, ["@box/a", "@box/b", "@box/c"]);
        let reason = declare(
            &mut declarations,
            "tool.program",
            "@box/d",
            &declaration("type = \"string\""),
        )
        .expect_err("a second type");
        assert!(reason.contains("only with one type"), "{reason}");
        assert!(reason.contains("@box/d"), "{reason}");
    }

    #[test]
    fn each_pack_that_declares_an_input_adds_its_warning_once() {
        let mut declarations = BTreeMap::new();
        for (pack, text) in [
            (
                "@box/a",
                "type = \"bool\"\nwarning = \"Runs host servers.\"",
            ),
            ("@box/b", "type = \"bool\""),
            (
                "@box/c",
                "type = \"bool\"\nwarning = \"Runs host servers.\"",
            ),
            (
                "@box/d",
                "type = \"bool\"\nwarning = \"Reads every project.\"",
            ),
        ] {
            declare(&mut declarations, "agent.import", pack, &declaration(text)).unwrap();
        }
        assert_eq!(
            declarations["agent.import"].warnings(),
            ["Runs host servers.", "Reads every project."]
        );
    }

    #[test]
    fn a_declaration_refuses_a_bad_type_source_or_pattern() {
        for (text, why) in [
            ("type = \"number\"", "use string, bool, or program"),
            ("from = \"setup\"", "use env:<NAME>"),
            ("from = \"file:/etc/hosts\"", "use env:<NAME>"),
            ("pattern = \"(\"", "`[inputs.x] pattern` is invalid"),
            ("default = 1", "is not a string or true or false"),
            ("values = [1]", "is not a list of strings"),
            (
                "pattern = \"${{ home }}\"",
                "is literal and holds no placeholder",
            ),
            (
                "warning = \"${{ home }}\"",
                "is literal and holds no placeholder",
            ),
            ("warning = true", "`[inputs.x] warning` is not a string"),
            (
                "from = \"env:X\"\nwarning = \"w\"",
                "a warning goes on an input that the operator answers",
            ),
            (
                "type = \"program\"\nprogram = \"x\"\nwarning = \"w\"",
                "a warning goes on an input that the operator answers",
            ),
        ] {
            let reason =
                declare(&mut BTreeMap::new(), "x", "@box/a", &declaration(text)).expect_err(text);
            assert!(reason.contains(why), "{text}: {reason}");
        }
    }

    #[test]
    fn a_key_needs_from_and_names_one_literal_key_of_a_list() {
        for (text, why) in [
            (
                "key = \"group\"",
                "`[inputs.x] key` names a key of the `from` variable, so it needs `from`",
            ),
            (
                "from = \"env:X\"\nkey = 1",
                "`[inputs.x] key` is not a string",
            ),
            (
                "from = \"env:X\"\nkey = \"${{ home }}\"",
                "`[inputs.x] key` is literal and holds no placeholder",
            ),
            (
                "from = \"env:X\"\nkey = \"\"",
                "is not one key of a `key=value` list",
            ),
            (
                "from = \"env:X\"\nkey = \" group\"",
                "is not one key of a `key=value` list",
            ),
            (
                "from = \"env:X\"\nkey = \"a,b\"",
                "is not one key of a `key=value` list",
            ),
            (
                "from = \"env:X\"\nkey = \"a=b\"",
                "is not one key of a `key=value` list",
            ),
        ] {
            let reason =
                declare(&mut BTreeMap::new(), "x", "@box/a", &declaration(text)).expect_err(text);
            assert!(reason.contains(why), "{text}: {reason}");
        }
        declare(
            &mut BTreeMap::new(),
            "x",
            "@box/a",
            &declaration("from = \"env:X\"\nkey = \"x-aws-log-group\""),
        )
        .expect("a key of a list");
    }

    #[test]
    fn a_list_value_is_the_one_value_of_its_key_percent_decoded() {
        let list = "x-log-group=/aws/rt-DEFAULT, x-log-stream = otel-rt-logs ,token=a=b,\
                    empty=,bare,,service.name=my%20agent%2C%C3%A9";
        for (key, value) in [
            ("x-log-group", Some("/aws/rt-DEFAULT")),
            ("x-log-stream", Some("otel-rt-logs")),
            ("token", Some("a=b")),
            ("service.name", Some("my agent,\u{e9}")),
            ("empty", None),
            ("bare", None),
            ("missing", None),
        ] {
            assert_eq!(list_value(list, key).expect(key).as_deref(), value, "{key}");
        }
    }

    #[test]
    fn a_list_value_refuses_a_key_given_twice_or_a_bad_escape() {
        assert_eq!(
            list_value("a=1,b=2,a=1", "a"),
            Err("which holds it twice".to_string())
        );
        for list in ["a=%", "a=%2", "a=%zz", "a=%+1", "a=%ff", "a=x%00y"] {
            let reason = list_value(list, "a").expect_err(list);
            assert!(
                reason.contains("not percent-encoded UTF-8 text"),
                "{list}: {reason}"
            );
        }
    }

    #[test]
    fn a_filled_telemetry_project_holds_no_control_character_or_outer_white_space() {
        let reach = Some("a telemetry target's `project`");
        for value in [
            "Customer Support Bot",
            "team/a?b#c%d\\e;f",
            ".",
            "..",
            "\u{e9}quipe",
        ] {
            check_header_value("x", reach, value, false).expect(value);
        }
        for value in [
            "a\nb", "a\rb", "a\tb", "a\0b", "a\u{1b}b", "a\u{7f}b", "a\u{85}b",
        ] {
            for from_profile in [false, true] {
                let reason = check_header_value("x", reach, value, from_profile).expect_err(value);
                assert!(
                    reason.contains("so it cannot hold a control character"),
                    "{value:?}: {reason}"
                );
            }
        }
        for value in [" a", "a ", "\u{a0}a", "a\u{3000}"] {
            let reason = check_header_value("x", reach, value, false).expect_err(value);
            assert!(
                reason.contains("so it cannot start or end with white space"),
                "{value:?}: {reason}"
            );
            check_header_value("x", reach, value, true).expect("a value that the profile wrote");
        }
        check_header_value("x", None, "a\nb", false).expect("a field that is not a project");
    }

    #[test]
    fn a_version_floor_is_greater_or_equal_to_a_version() {
        assert_eq!(floor(">=22").unwrap(), vec![22]);
        assert_eq!(floor(">=0.2.0").unwrap(), vec![0, 2, 0]);
        assert!(floor("22").is_err());
    }

    /// A folder of packs, and the operator's own profile beside it.
    struct Shelf {
        _root: tempfile::TempDir,
        root: PathBuf,
    }

    impl Shelf {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("a temporary root");
            let root = directory.path().canonicalize().expect("a canonical root");
            Self {
                _root: directory,
                root,
            }
        }

        /// Write the pack `@box/<name>`, with a header.
        fn share(&self, name: &str, text: &str) {
            let folder = self.root.join("packs").join(name);
            std::fs::create_dir_all(&folder).expect("a folder");
            std::fs::write(
                folder.join(PACK_FILE),
                format!(
                    "[pack]\nname = \"@box/{name}\"\nversion = 1\n{}{text}",
                    crate::lang::test_kind_line(text)
                ),
            )
            .expect("a pack");
        }

        fn own(&self, name: &str, text: &str) {
            let folder = self.root.join("operator").join(name);
            std::fs::create_dir_all(&folder).expect("a folder");
            std::fs::write(
                folder.join(PACK_FILE),
                format!("[pack]\nname = \"{name}\"\nversion = 1\nkind = \"support\"\n{text}"),
            )
            .expect("a pack");
        }

        /// Write the pack `@acme/<name>` in the collection `@acme`, with a header.
        fn collect(&self, name: &str, text: &str) {
            let folder = self.root.join("acme/packs").join(name);
            std::fs::create_dir_all(&folder).expect("a folder");
            std::fs::write(
                folder.join(PACK_FILE),
                format!("[pack]\nname = \"@acme/{name}\"\nversion = 1\nkind = \"support\"\n{text}"),
            )
            .expect("a pack");
        }

        fn lookup(&self) -> Lookup {
            Lookup {
                vendored: Some(self.root.join("packs")),
                operator: self.root.join("operator"),
                collections: vec![Collection {
                    scope: "acme".to_string(),
                    root: self.root.join("acme"),
                }],
                version: "0.1.0",
            }
        }

        fn chain(&self, text: &str) -> Result<Vec<Layer>, Error> {
            let lookup = self.lookup();
            chain(
                &toml::from_str(text).expect("TOML"),
                text,
                &self.root.join("mine").join("profile.toml"),
                None,
                &lookup,
            )
        }
    }

    fn reason(error: Error) -> String {
        match error {
            Error::Profile { reason, .. } => reason,
            other => panic!("a profile refusal, not {other:?}"),
        }
    }

    impl Shelf {
        /// Write the pack `@box/<name>` as `text` alone.
        fn share_raw(&self, name: &str, text: &str) {
            let folder = self.root.join("packs").join(name);
            std::fs::create_dir_all(&folder).expect("a folder");
            std::fs::write(folder.join(PACK_FILE), text).expect("a pack");
        }

        /// The reason that the profile that names only `@box/<name>` is refused.
        fn kind_refusal(&self, name: &str) -> String {
            reason(
                self.chain(&format!("packs = [\"@box/{name}\"]"))
                    .err()
                    .unwrap_or_else(|| panic!("@box/{name} is refused")),
            )
        }
    }

    /// A `[pack]` header for `@box/<name>` of the kind `kind`.
    fn header(name: &str, kind: &str) -> String {
        format!("[pack]\nname = \"@box/{name}\"\nversion = 1\nkind = {kind:?}\n")
    }

    #[test]
    fn a_pack_without_a_kind_is_refused_with_the_kind_to_write() {
        let shelf = Shelf::new();
        shelf.share("claude", "[run]\ncommand = [\"/bin/claude\"]");
        let bare = |name: &str| format!("[pack]\nname = \"@box/{name}\"\nversion = 1\n");
        for (name, body) in [
            (
                "t",
                "[inputs.t.path]\ntype = \"program\"\nprogram = \"t\"\n\
                   search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.t.path }}\"]",
            ),
            ("a", "[run]\ncommand = [\"/bin/a\"]"),
            ("s", ""),
            ("team", "extend = [\"@box/claude\"]"),
        ] {
            shelf.share_raw(name, &format!("{}{body}", bare(name)));
            let why = shelf.kind_refusal(name);
            assert!(
                why.contains("`[pack]` needs `kind`: \"agent\", \"tool\", or \"support\""),
                "{name}: {why}"
            );
        }
    }

    #[test]
    fn a_pack_starts_with_its_header_and_states_its_kind_first() {
        let shelf = Shelf::new();
        for (name, text, wanted) in [
            (
                "env",
                "[env]\nA = \"1\"\n[pack]\nname = \"@box/env\"\nversion = 1\nkind = \"agent\"\n\
                 [run]\ncommand = [\"/bin/a\"]",
                "a pack starts with `[pack]`, and this one starts with `[env]`",
            ),
            (
                "rows",
                "# A comment comes first.\n[[mcp-servers]]\nfile = \"/x\"\nkind = \"json\"\n\
                 key = [\"s\"]\n[pack]\nname = \"@box/rows\"\nversion = 1\nkind = \"support\"",
                "a pack starts with `[pack]`, and this one starts with `[[mcp-servers]]`",
            ),
            (
                "nokind",
                "[pack]\nname = \"@box/nokind\"\nversoin = 1\n[env]\nA = \"1\"",
                "`[pack]` needs `kind`: \"agent\", \"tool\", or \"support\"",
            ),
            (
                "emptyrun",
                "[pack]\nname = \"@box/emptyrun\"\nversion = 1\nkind = \"support\"\n[run]",
                "a support pack holds no `[run]`",
            ),
            (
                "rowsrun",
                "[pack]\nname = \"@box/rowsrun\"\nversion = 1\nkind = \"agent\"\n[[run]]\n\
                 command = [\"/bin/a\"]",
                "`run` is a table",
            ),
        ] {
            shelf.share_raw(name, text);
            let why = shelf.kind_refusal(name);
            assert!(why.contains(wanted), "{name}: {why}");
        }
    }

    #[test]
    fn a_kind_that_the_pack_contradicts_is_refused() {
        let shelf = Shelf::new();
        for (text, wanted) in [
            (
                format!("{}[run]\ncommand = [\"/bin/p\"]", header("p", "support")),
                "a support pack holds no `[run]`; only an agent pack or a tool pack runs a program",
            ),
            (
                format!("{}[env]\nA = \"1\"", header("p", "support")),
                "a support pack holds no `[env]`; only an agent pack or a tool pack runs a program",
            ),
            (
                header("p", "tool"),
                "a tool pack needs `[run] command`, the program it runs",
            ),
            (
                format!("{}[run]\nprogram = \"p\"", header("p", "tool")),
                "the `[run]` of a tool pack holds the unknown key `program`",
            ),
            (
                format!("{}[run]\nprogram = \"p\"", header("p", "agent")),
                "the `[run]` of an agent pack holds the unknown key `program`",
            ),
            (
                header("p", "agent"),
                "`[pack] kind = \"agent\"`, but neither this pack nor a pack it extends holds \
                 `[run] command`",
            ),
            (
                header("p", "provider"),
                "`[pack] kind` is \"agent\", \"tool\", or \"support\"",
            ),
            (
                "[pack]\nname = \"@box/p\"\nversion = 1\nkind = 1\n".to_string(),
                "`[pack] kind` is \"agent\", \"tool\", or \"support\"",
            ),
        ] {
            shelf.share_raw("p", &text);
            let why = shelf.kind_refusal("p");
            assert!(why.contains(wanted), "{text}: {why}");
        }
        for (name, text) in [
            (
                "t",
                format!(
                    "{}[inputs.t.path]\ntype = \"program\"\nprogram = \"t\"\n\
                         search = [{{ env = \"PATH\" }}]\n[run]\n\
                         command = [\"${{{{ inputs.t.path }}}}\"]",
                    header("t", "tool")
                ),
            ),
            (
                "a",
                format!("{}[run]\ncommand = [\"/bin/a\"]", header("a", "agent")),
            ),
            (
                "s",
                format!("{}[agent.env]\nS = \"1\"", header("s", "support")),
            ),
        ] {
            shelf.share_raw(name, &text);
            shelf
                .chain(&format!("packs = [\"@box/{name}\"]"))
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
    }

    #[test]
    fn a_pack_that_extends_an_agent_pack_is_an_agent_pack() {
        let shelf = Shelf::new();
        shelf.share("claude", "[run]\ncommand = [\"/bin/claude\"]");
        shelf.share_raw(
            "x",
            &format!("{}extend = [\"@box/claude\"]", header("x", "support")),
        );
        let why = shelf.kind_refusal("x");
        assert!(
            why.contains(
                "`[pack] kind = \"support\"`, but the pack extends the agent pack @box/claude; \
                 write kind = \"agent\""
            ),
            "{why}"
        );
        shelf.share_raw(
            "x",
            &format!(
                "{}extend = [\"@box/claude\"]\n[inputs.x.path]\ntype = \"program\"\n\
                 program = \"x\"\nsearch = [{{ env = \"PATH\" }}]\n[run]\n\
                 command = [\"${{{{ inputs.x.path }}}}\"]",
                header("x", "tool")
            ),
        );
        let why = shelf.kind_refusal("x");
        assert!(
            why.contains(
                "a tool pack cannot extend the agent pack @box/claude; remove it from \
                 `extend`, or write the tool in a `[tool.<name>]` table of an agent pack"
            ),
            "{why}"
        );
        shelf.share_raw(
            "team",
            &format!("{}extend = [\"@box/claude\"]", header("team", "agent")),
        );
        shelf
            .chain("packs = [\"@box/team\"]")
            .expect("a pack that adds to an agent");
    }

    #[test]
    fn a_tool_pack_extends_tool_and_support_packs_and_a_support_pack_only_support_packs() {
        let shelf = Shelf::new();
        shelf.share(
            "node",
            "kind = \"tool\"\n[inputs.node.path]\ntype = \"program\"\n\
                             program = \"node\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                             command = [\"${{ inputs.node.path }}\"]",
        );
        shelf.share(
            "route",
            "[egress.github]\ndestinations = [\"api.github.com\"]\nsecret.ref = \"env://GH_TOKEN\"",
        );
        shelf.share_raw(
            "npm",
            &format!(
                "{}extend = [\"@box/node\"]\n[inputs.npm.path]\ntype = \"program\"\n\
                 program = \"npm\"\nsearch = [{{ env = \"PATH\" }}]\n[run]\n\
                 command = [\"${{{{ inputs.npm.path }}}}\"]",
                header("npm", "tool")
            ),
        );
        shelf
            .chain("packs = [\"@box/npm\"]")
            .expect("a tool pack on a tool pack");
        shelf.share_raw(
            "gh",
            &format!(
                "{}extend = [\"@box/route\"]\n[inputs.gh.path]\ntype = \"program\"\n\
                 program = \"gh\"\nsearch = [{{ env = \"PATH\" }}]\n[run]\n\
                 command = [\"${{{{ inputs.gh.path }}}}\"]",
                header("gh", "tool")
            ),
        );
        let layers = shelf
            .chain("packs = [\"@box/gh\"]\n[agent]\ncommand = [\"/bin/x\"]")
            .expect("a tool pack on a support pack");
        let merged = merge(&layers).expect("a merge");
        assert_eq!(
            merged.table["egress"]["github"]["secret"]["ref"].as_str(),
            Some("env://GH_TOKEN"),
            "the support pack's route reaches the profile"
        );
        assert!(
            merged.table["tool"].get("gh").is_some(),
            "{:?}",
            merged.table
        );
        shelf.share_raw(
            "kit",
            &format!(
                "{}extend = [\"@box/node\", \"@box/route\"]",
                header("kit", "support")
            ),
        );
        let why = reason(
            shelf
                .chain("packs = [\"@box/kit\"]")
                .expect_err("a support pack on a tool pack"),
        );
        assert!(
            why.contains("a support pack extends only support packs, and @box/node is a tool pack"),
            "{why}"
        );
    }

    #[test]
    fn a_profile_runs_one_agent() {
        let shelf = Shelf::new();
        shelf.share("claude", "[run]\ncommand = [\"/bin/claude\"]");
        shelf.share("kiro", "[run]\ncommand = [\"/bin/kiro\"]");
        for (name, text) in [
            ("team", "extend = [\"@box/claude\"]\n[env]\nTEAM = \"1\""),
            ("other", "extend = [\"@box/claude\"]\n[env]\nOTHER = \"1\""),
            (
                "wrap",
                "extend = [\"@box/claude\"]\n[run]\ncommand = [\"/bin/wrap\"]",
            ),
            ("both", "extend = [\"@box/claude\", \"@box/kiro\"]"),
            (
                "deep",
                "extend = [\"@box/team\"]\n[run]\ncommand = [\"/bin/deep\"]",
            ),
            ("combined", "extend = [\"@box/team\", \"@box/other\"]"),
        ] {
            shelf.share_raw(name, &format!("{}{text}", header(name, "agent")));
        }
        let merged = |packs: &str| {
            let layers = shelf
                .chain(&format!(
                    "packs = [{packs}]\n[agent]\ncommand = [\"/bin/mine\"]"
                ))
                .unwrap_or_else(|error| panic!("{packs}: {error}"));
            merge(&layers)
        };
        for packs in [
            "\"@box/claude\"",
            "\"@box/team\"",
            "\"@box/team\", \"@box/claude\"",
            "\"@box/wrap\"",
            "\"@box/deep\", \"@box/claude\"",
            "\"@box/combined\"",
            "\"@box/combined\", \"@box/team\", \"@box/other\"",
        ] {
            merged(packs).unwrap_or_else(|error| panic!("{packs}: {error}"));
        }
        for packs in ["\"@box/claude\", \"@box/kiro\"", "\"@box/both\""] {
            let why = reason(merged(packs).err().expect("two agents"));
            assert!(
                why.contains(
                    "the profile has two agent packs, @box/claude and @box/kiro; keep one"
                ),
                "{packs}: {why}"
            );
        }
        for (packs, first, second) in [
            ("\"@box/team\", \"@box/other\"", "@box/team", "@box/other"),
            ("\"@box/deep\", \"@box/other\"", "@box/deep", "@box/other"),
        ] {
            let why = reason(merged(packs).err().expect("two heads"));
            assert!(
                why.contains(&format!(
                    "the profile has two agent packs, {first} and {second}; keep one, or name a \
                     pack that extends both"
                )),
                "{packs}: {why}"
            );
        }
    }

    #[test]
    fn an_extends_cycle_is_refused() {
        let shelf = Shelf::new();
        shelf.share("a", "extend = [\"@box/b\"]");
        shelf.share("b", "extend = [\"@box/a\"]");
        shelf.share("c", "extend = [\"@box/c\"]");
        for text in ["packs = [\"@box/a\"]", "packs = [\"@box/c\"]"] {
            let reason = reason(shelf.chain(text).expect_err("a cycle"));
            assert!(
                reason.contains("which imports this pack"),
                "{text}: {reason}"
            );
        }
    }

    #[test]
    fn an_engine_floor_is_checked_against_the_version_of_the_lookup() {
        let shelf = Shelf::new();
        let text = "packs = [\"@box/p\"]";
        for (floor, refused) in [(">=7.2.0", false), (">=7.2.1", true)] {
            shelf.share_raw(
                "p",
                &format!(
                    "[pack]\nname = \"@box/p\"\nversion = 1\nkind = \"support\"\nengine = \"{floor}\"\n"
                ),
            );
            let lookup = Lookup {
                vendored: Some(shelf.root.join("packs")),
                operator: shelf.root.join("operator"),
                collections: Vec::new(),
                version: "7.2.0",
            };
            let chained = chain(
                &toml::from_str(text).expect("TOML"),
                text,
                &shelf.root.join("mine/profile.toml"),
                None,
                &lookup,
            );
            match chained {
                Ok(_) => assert!(!refused, "{floor} is refused for box 7.2.0"),
                Err(error) => {
                    let reason = reason(error);
                    assert!(refused, "{floor}: {reason}");
                    assert!(
                        reason.contains("and this is box 7.2.0"),
                        "{floor}: {reason}"
                    );
                }
            }
        }
    }

    fn engine_outcome(version: &str, floor: &str) -> Result<(), String> {
        let shelf = Shelf::new();
        let text = "packs = [\"@box/p\"]";
        shelf.share_raw(
            "p",
            &format!(
                "[pack]\nname = \"@box/p\"\nversion = 1\nkind = \"support\"\nengine = \"{floor}\"\n"
            ),
        );
        let lookup = Lookup {
            vendored: Some(shelf.root.join("packs")),
            operator: shelf.root.join("operator"),
            collections: Vec::new(),
            version: Box::leak(version.to_owned().into_boxed_str()),
        };
        chain(
            &toml::from_str(text).expect("TOML"),
            text,
            &shelf.root.join("mine/profile.toml"),
            None,
            &lookup,
        )
        .map(|_| ())
        .map_err(reason)
    }

    #[test]
    fn a_preview_version_counts_as_its_release_for_an_engine_floor() {
        for (version, floor, refused) in [
            ("0.3.0-linux-preview.1", ">=0.1.0", false),
            ("0.3.0-linux-preview.1", ">=0.3.0", false),
            ("0.3.0-linux-preview.1", ">=0.3.1", true),
            ("0.3.0-linux-preview.1", ">=0.4.0", true),
            ("7.2.0-linux-preview.1", ">=7.2.0", false),
            ("7.2.0-linux-preview.1", ">=7.2.1", true),
            ("v0.3.0-linux-preview.2", ">=0.3.0", false),
        ] {
            let outcome = engine_outcome(version, floor);
            assert_eq!(
                outcome.is_err(),
                refused,
                "box {version} against {floor}: {outcome:?}"
            );
        }
    }

    #[test]
    fn a_malformed_box_version_is_refused_and_named() {
        for version in [
            "",
            "linux-preview",
            "0-linux-preview",
            "0.x.0",
            "0.x.0-linux-preview.1",
            "-linux-preview.1",
            "0.3.0+build.5",
        ] {
            let reason = engine_outcome(version, ">=0.1.0").expect_err("a malformed version");
            assert!(
                reason.contains("needs box >=0.1.0")
                    && reason.contains(&format!("this is box {version}")),
                "{version:?}: {reason}"
            );
        }
    }

    #[test]
    fn a_malformed_engine_floor_is_refused_and_named() {
        for floor in [
            ">=",
            ">=abc",
            ">=0.x.0",
            ">=0.3.0-linux-preview.1",
            ">=0.3.0+build.5",
            "0.3.0",
            "^0.3.0",
        ] {
            let reason = engine_outcome("0.3.0", floor).expect_err("a malformed floor");
            assert!(reason.contains("is not `>=X.Y.Z`"), "{floor}: {reason}");
        }
    }

    #[test]
    fn a_pack_that_two_packs_extend_merges_once() {
        let shelf = Shelf::new();
        shelf.share("a", "[agent.filesystem]\nread = [\"${{ pack }}\"]");
        shelf.share("b", "extend = [\"@box/a\"]");
        shelf.share("c", "extend = [\"@box/a\"]");
        let layers = shelf
            .chain("packs = [\"@box/b\", \"@box/c\"]")
            .expect("a chain");
        let names: Vec<&str> = layers.iter().map(|layer| layer.name.as_str()).collect();
        assert_eq!(names, ["@box/a", "@box/b", "@box/c", "the profile"]);
        let merged = merge(&layers).expect("a merge");
        assert!(merged.policy.is_empty(), "{}", merged.policy);
        let folder = shelf.root.join("packs/a").display().to_string();
        assert_eq!(
            merged.table["agent"]["filesystem"]["read"]
                .as_array()
                .expect("a list"),
            &vec![toml::Value::String(folder)],
            "`pack` is the folder of the file that holds it"
        );
        for key in ["packs", EXTEND, "pack"] {
            assert!(!merged.table.contains_key(key), "{key}");
        }
    }

    #[test]
    fn a_profile_command_replaces_an_inherited_programs_settings_and_grammar() {
        let shelf = Shelf::new();
        shelf.share(
            "greet",
            "kind = \"tool\"\n[inputs.greet.path]\ntype = \"program\"\n\
             program = \"greet\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
             command = [\"${{ inputs.greet.path }}\"]\nhelpers = [\"helper\"]\n\
             hosts = [\"example.com\"]\n[env]\nOLD_SETTING = \"yes\"\n\
             [filesystem]\nread = [\"${{ tool.greet.root }}\"]",
        );
        shelf.grammar("greet", &grammar("greet", "greet"));
        let profile = "packs = [\"@box/greet\"]\n[tool.greet]\n\
                       command = [\"/opt/bin/greet\", \"status\"]\n\
                       [tool.greet.env]\nNEW_SETTING = \"yes\"\n\
                       [tool.greet.filesystem]\nread = [\"/data\"]";
        let merged = merge(&shelf.chain(profile).expect("a chain"));
        assert!(
            merged.is_ok(),
            "the profile replaces the tool and its grammar"
        );
        let merged = merged.expect("a merge");
        assert_eq!(
            merged.table["tool"]["greet"],
            toml::Value::Table(toml::toml! {
                command = ["/opt/bin/greet", "status"]
                [env]
                NEW_SETTING = "yes"
                [filesystem]
                read = ["/data"]
            })
        );
        assert!(merged.grammars.is_empty(), "{:?}", merged.grammars);
        assert!(merged.tool_packs.is_empty(), "{:?}", merged.tool_packs);
    }

    #[test]
    fn tool_replacement_requires_a_profile_command_without_an_explicit_program() {
        let shelf = Shelf::new();
        shelf.share(
            "base",
            "[tool.greet]\nprogram = \"greet\"\n[tool.greet.env]\nINHERITED = \"yes\"",
        );
        for text in [
            "packs = [\"@box/base\"]\n[tool.greet]\nprogram = \"greet\"\ncommand = [\"/bin/greet\"]",
            "packs = [\"@box/base\", \"@box/manual\"]",
        ] {
            shelf.share("manual", "[tool.greet]\ncommand = [\"/bin/greet\"]");
            let merged = merge(&shelf.chain(text).expect("a chain")).expect("a merge");
            assert_eq!(
                merged.table["tool"]["greet"]["program"].as_str(),
                Some("greet")
            );
            assert!(merged.table["tool"]["greet"].get("command").is_some());
            assert_eq!(
                merged.table["tool"]["greet"]["env"]["INHERITED"].as_str(),
                Some("yes")
            );
        }
        let merged = merge(
            &shelf
                .chain("packs = [\"@box/base\"]\n[tool.greet.env]\nSETTING = \"yes\"")
                .expect("a chain"),
        )
        .expect("a merge");
        assert_eq!(
            merged.table["tool"]["greet"]["program"].as_str(),
            Some("greet")
        );
        assert_eq!(
            merged.table["tool"]["greet"]["env"]["SETTING"].as_str(),
            Some("yes")
        );
        shelf.share(
            "manual",
            "[tool.greet]\ncommand = [\"/bin/greet\"]\n[tool.greet.env]\nSETTING = \"yes\"",
        );
        let merged = merge(
            &shelf
                .chain("packs = [\"@box/manual\"]\n[tool.greet]\ncommand = [\"/opt/bin/greet\"]")
                .expect("a chain"),
        )
        .expect("a merge");
        assert_eq!(
            merged.table["tool"]["greet"]["env"]["SETTING"].as_str(),
            Some("yes")
        );
    }

    #[test]
    fn an_operator_command_replaces_shipped_tool_settings_and_grammar_in_either_order() {
        let shelf = Shelf::new();
        shelf.share(
            "greet",
            "kind = \"tool\"\n[inputs.greet.path]\ntype = \"program\"\n\
             program = \"greet\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
             command = [\"${{ inputs.greet.path }}\"]\nhelpers = [\"helper\"]\n\
             hosts = [\"example.com\"]\n[filesystem]\nread = [\"${{ tool.greet.root }}\"]",
        );
        shelf.grammar("greet", &grammar("greet", "greet"));
        shelf.share(
            "settings",
            &format!(
                "[tool.greet.env]\nSHIPPED = \"yes\"\n[agent.env]\nKEEP = \"yes\"\n\
                 [tool.keep]\nprogram = \"keep\"\n[tool.keep.grammar]\n{}",
                grammar("keep", "keep")
                    .replace("[shell.status]", "[tool.keep.grammar.shell.status]")
            ),
        );
        shelf.own(
            "manual",
            "[tool.greet]\ncommand = [\"/opt/bin/greet\"]\n[tool.greet.env]\nOWN = \"yes\"",
        );
        for packs in [
            "[\"manual\", \"@box/greet\", \"@box/settings\"]",
            "[\"@box/settings\", \"@box/greet\", \"manual\"]",
        ] {
            let merged = merge(&shelf.chain(&format!("packs = {packs}")).expect("a chain"));
            assert!(
                merged.is_ok(),
                "the operator command replaces the shipped grammar"
            );
            let merged = merged.expect("a merge");
            assert_eq!(
                merged.table["tool"]["greet"],
                toml::Value::Table(toml::toml! {
                    command = ["/opt/bin/greet"]
                    [env]
                    OWN = "yes"
                }),
                "{packs}"
            );
            assert_eq!(merged.table["agent"]["env"]["KEEP"].as_str(), Some("yes"));
            assert_eq!(
                merged.table["tool"].get("keep"),
                Some(&toml::Value::Table(toml::toml! { program = "keep" }))
            );
            assert_eq!(
                merged.grammars,
                BTreeMap::from([(
                    "keep".to_string(),
                    toml::from_str(&grammar("keep", "keep")).expect("a grammar"),
                )])
            );
            assert_eq!(
                merged.tool_packs,
                BTreeMap::from([("keep".to_string(), "@box/settings".to_string())])
            );
        }
    }

    #[test]
    fn operator_commands_leave_other_operator_packs_and_nonconflicting_shipped_settings_alone() {
        let shelf = Shelf::new();
        shelf.own("manual", "[tool.greet]\ncommand = [\"/opt/bin/greet\"]");
        shelf.share("settings", "[tool.greet.env]\nSHIPPED = \"yes\"");
        let merged = merge(
            &shelf
                .chain("packs = [\"manual\", \"@box/settings\"]")
                .expect("a chain"),
        )
        .expect("a merge");
        assert_eq!(
            merged.table["tool"]["greet"]["env"]["SHIPPED"].as_str(),
            Some("yes")
        );

        shelf.own(
            "configured",
            &format!(
                "[tool.greet]\nprogram = \"other\"\n[tool.greet.env]\nKEEP = \"yes\"\n\
                 [tool.greet.grammar]\n{}",
                grammar("greet", "other")
                    .replace("[shell.status]", "[tool.greet.grammar.shell.status]")
            ),
        );
        let merged = merge(
            &shelf
                .chain("packs = [\"manual\", \"@box/settings\", \"configured\"]")
                .expect("a chain"),
        )
        .expect("a merge");
        assert_eq!(
            merged.table["tool"]["greet"]["env"]
                .get("SHIPPED")
                .and_then(toml::Value::as_str),
            Some("yes")
        );
        shelf.share("base", "[tool.greet]\nprogram = \"greet\"");
        for packs in [
            "[\"manual\", \"@box/base\", \"configured\"]",
            "[\"configured\", \"@box/base\", \"manual\"]",
        ] {
            let merged = merge(&shelf.chain(&format!("packs = {packs}")).expect("a chain"))
                .expect("a merge");
            assert_eq!(
                merged.table["tool"]["greet"]["program"].as_str(),
                Some("other")
            );
            assert!(merged.table["tool"]["greet"].get("command").is_some());
            assert_eq!(
                merged.table["tool"]["greet"]["env"]["KEEP"].as_str(),
                Some("yes")
            );
            assert_eq!(
                merged.grammars.get("greet"),
                Some(&toml::from_str(&grammar("greet", "other")).expect("a grammar"))
            );
        }
        shelf.own(
            "both",
            "[tool.greet]\nprogram = \"greet\"\ncommand = [\"/opt/bin/greet\"]",
        );
        let merged = merge(
            &shelf
                .chain("packs = [\"@box/base\", \"@box/settings\", \"both\"]")
                .expect("a chain"),
        )
        .expect("a merge");
        assert_eq!(
            merged.table["tool"]["greet"]["env"]["SHIPPED"].as_str(),
            Some("yes")
        );
        assert!(merged.table["tool"]["greet"].get("program").is_some());
        assert!(merged.table["tool"]["greet"].get("command").is_some());
    }

    #[test]
    fn two_packs_cannot_declare_one_route() {
        let shelf = Shelf::new();
        shelf.share(
            "b",
            "[egress.model]\ndestinations = [\"b.example.com\"]\nsecret.ref = \"env://B\"",
        );
        shelf.share(
            "c",
            "[egress.model]\ndestinations = [\"c.example.com\"]\nsecret.ref = \"env://C\"",
        );
        let layers = shelf
            .chain("packs = [\"@box/b\", \"@box/c\"]")
            .expect("a chain");
        let error = merge(&layers).err().expect("one route from two packs");
        assert!(
            matches!(&error, Error::Profile { path, .. } if path.ends_with("mine/profile.toml")),
            "the refusal names the profile: {error}"
        );
        let reason = reason(error);
        assert!(
            reason.contains(
                "`[egress.model]` is declared by both @box/b and @box/c, and two packs cannot \
                 declare one route"
            ),
            "{reason}"
        );
        let layers = shelf
            .chain("packs = [\"@box/b\"]\n[egress.model.secret]\nref = \"aws://dev\"")
            .expect("a chain");
        let merged = merge(&layers).expect("the operator's own profile changes a route");
        assert_eq!(
            merged.table["egress"]["model"]["secret"]["ref"].as_str(),
            Some("aws://dev")
        );
        assert_eq!(
            merged.table["egress"]["model"]["destinations"][0].as_str(),
            Some("b.example.com")
        );
    }

    #[test]
    fn two_packs_cannot_read_one_key() {
        let shelf = Shelf::new();
        shelf.share(
            "model",
            "[egress.model]\ndestinations = [\"api.example.com\"]\nsecret.ref = \"env://KEY\"\n\
             [egress.console]\ndestinations = [\"console.example.com\"]\n\
             secret.ref = \"env://KEY\"",
        );
        shelf.share(
            "collector",
            "[egress.collector]\ndestinations = [\"collector.example.com\"]\n\
             secret.ref = \"env://KEY\"",
        );
        let layers = shelf
            .chain("packs = [\"@box/model\", \"@box/collector\"]")
            .expect("a chain");
        let refused = reason(merge(&layers).err().expect("one key from two packs"));
        assert!(
            refused.contains(
                "`[egress.collector]` in @box/collector reads env://KEY, which \
                 `[egress.console]` in @box/model reads, and two packs cannot read one key"
            ),
            "{refused}"
        );
        for (pack, collector) in [
            (
                "wrapped-route",
                "[egress.collector]\nwhen = \"linux\"\nvalue = { destinations = \
                 [\"collector.example.com\"], secret = { ref = \"env://KEY\" } }",
            ),
            (
                "wrapped-ref",
                "[egress.collector]\ndestinations = [\"collector.example.com\"]\n\
                 secret.ref = { value = \"env://KEY\", when = \"linux\" }",
            ),
        ] {
            shelf.share(pack, collector);
            let layers = shelf
                .chain(&format!("packs = [\"@box/model\", \"@box/{pack}\"]"))
                .expect("a chain");
            let refused = reason(merge(&layers).err().expect("a key under a `when`"));
            assert!(
                refused.contains(&format!(
                    "`[egress.collector]` in @box/{pack} reads env://KEY, which \
                     `[egress.console]` in @box/model reads"
                )),
                "{pack}: {refused}"
            );
        }
        let layers = shelf.chain("packs = [\"@box/model\"]").expect("a chain");
        merge(&layers).expect("one pack reads one key from two routes");
        let layers = shelf
            .chain(
                "packs = [\"@box/model\"]\n[egress.mine]\ndestinations = [\"mine.example.com\"]\n\
                 secret.ref = \"env://KEY\"",
            )
            .expect("a chain");
        let merged = merge(&layers).expect("the operator's own profile reads a pack's key");
        assert_eq!(
            merged.table["egress"]["mine"]["secret"]["ref"].as_str(),
            Some("env://KEY")
        );
    }

    #[test]
    fn a_later_command_replaces_the_whole_command() {
        let mut base: toml::Table =
            toml::from_str("[agent]\ncommand = [\"/a\", \"--x\", \"--y\"]").expect("TOML");
        merge_table(
            &mut base,
            toml::from_str("[agent]\ncommand = [\"/b\", \"--x\"]").expect("TOML"),
            &mut Vec::new(),
        );
        assert_eq!(
            base["agent"]["command"],
            toml::Value::Array(vec!["/b".into(), "--x".into()])
        );
    }

    #[test]
    fn a_native_filesystem_experiment_in_a_profile_is_optional_and_boolean() {
        let shelf = Shelf::new();
        let absent = merge(&shelf.chain("").expect("a profile")).expect("a merge");
        assert!(!absent.table.contains_key("experimental-features"));
        for enabled in [true, false] {
            let text = format!("[experimental-features]\nnative-filesystem-policy = {enabled}");
            let merged = merge(&shelf.chain(&text).expect("a profile")).expect("a merge");
            assert_eq!(
                merged.table["experimental-features"]["native-filesystem-policy"].as_bool(),
                Some(enabled)
            );
        }
    }

    fn assert_native_pack_refusal(error: Error, shelf: &Shelf, name: &str, field: &str) {
        let Error::Profile { path, line, reason } = error else {
            panic!("a pack refusal, not {error:?}");
        };
        assert_eq!(path, shelf.root.join("packs").join(name).join(PACK_FILE));
        assert!(
            line.is_some(),
            "the offending field has a source line: {reason}"
        );
        assert!(reason.contains(field), "{reason}");
        assert!(reason.contains("profile.toml"), "{reason}");
    }

    #[test]
    fn native_policy_is_profile_only_for_every_pack_kind() {
        let shelf = Shelf::new();
        for body in [
            String::new(),
            "[run]\ncommand = [\"/bin/agent\"]\n".to_string(),
            test_tool_pack("native", ""),
        ] {
            for selection in [
                "[experimental-features]",
                "[experimental-features]\nnative-filesystem-policy = true",
                "[experimental-features]\nnative-filesystem-policy = false",
                "[experimental-features]\nnative-filesystem-policy = { value = false, when = \"macos\" }",
                "[experimental-features]\nwhen = \"macos\"\nnative-filesystem-policy = true",
                "[experimental-features]\ntool-grammars = true",
            ] {
                shelf.share("native", &format!("{body}\n{selection}"));
                let error = shelf
                    .chain("packs = [\"@box/native\"]")
                    .expect_err(selection);
                assert_native_pack_refusal(error, &shelf, "native", "experimental-features");
            }
        }
    }

    #[test]
    fn native_policy_is_profile_only_in_a_pack_run() {
        let shelf = Shelf::new();
        for selection in [
            "native-filesystem-policy = true",
            "native-filesystem-policy = false",
            "native-filesystem-policy = { value = true, when = \"macos\" }",
            "when = \"macos\"\nnative-filesystem-policy = false",
        ] {
            for body in [
                format!("[run]\ncommand = [\"/bin/agent\"]\n{selection}"),
                test_tool_pack("native", selection),
            ] {
                shelf.share("native", &body);
                let error = shelf.chain("packs = [\"@box/native\"]").expect_err(&body);
                assert_native_pack_refusal(error, &shelf, "native", "run.native-filesystem-policy");
            }
        }
    }

    #[test]
    fn native_policy_is_profile_only_in_named_pack_processes() {
        let shelf = Shelf::new();
        for (body, section) in [
            ("", "agent"),
            ("", "tool.git"),
            ("[run]\ncommand = [\"/bin/agent\"]\n", "tool.git"),
        ] {
            for selection in [
                "native-filesystem-policy = true",
                "native-filesystem-policy = false",
                "native-filesystem-policy = { value = false, when = \"macos\" }",
                "when = \"macos\"\nnative-filesystem-policy = true",
            ] {
                let text = format!("{body}[{section}]\ncommand = [\"/bin/program\"]\n{selection}");
                shelf.share("native", &text);
                let error = shelf.chain("packs = [\"@box/native\"]").expect_err(&text);
                assert_native_pack_refusal(
                    error,
                    &shelf,
                    "native",
                    &format!("{section}.native-filesystem-policy"),
                );
            }
        }
    }

    #[test]
    fn native_policy_is_profile_only_in_wrapped_tool_collections() {
        let shelf = Shelf::new();
        for body in ["", "[run]\ncommand = [\"/bin/agent\"]\n"] {
            for when in ["linux", "macos"] {
                for process_when in [None, Some("linux"), Some("macos")] {
                    let (process, field) = match process_when {
                        None => (String::new(), "tool.value.command.native-filesystem-policy"),
                        Some(when) => (
                            format!("when = {when:?}\n[tool.value.command.value]\n"),
                            "tool.value.command.value.native-filesystem-policy",
                        ),
                    };
                    for selected in [true, false] {
                        let selection = format!("native-filesystem-policy = {selected}");
                        let text = format!(
                            "{body}[tool]\nwhen = {when:?}\n[tool.value.command]\n{process}\
                             command = [\"/usr/bin/true\"]\n{selection}"
                        );
                        shelf.share("native", &text);
                        let error = shelf.chain("packs = [\"@box/native\"]").expect_err(&text);
                        let Error::Profile { line, .. } = &error else {
                            panic!("a pack refusal, not {error:?}");
                        };
                        let source = std::fs::read_to_string(
                            shelf.root.join("packs/native").join(PACK_FILE),
                        )
                        .expect("the pack source");
                        assert_eq!(
                            *line,
                            source
                                .lines()
                                .position(|line| line == selection)
                                .map(|i| i + 1),
                            "the refusal names the original field line: {text}"
                        );
                        assert_native_pack_refusal(error, &shelf, "native", field);
                    }
                }
            }
        }
    }

    #[test]
    fn native_policy_is_profile_only_in_inherited_wrapped_tool_collections() {
        let shelf = Shelf::new();
        shelf.share("wrapper", "extend = [\"@box/native\"]");
        for when in ["linux", "macos"] {
            for selected in [true, false] {
                shelf.share(
                    "native",
                    &format!(
                        "[tool]\nwhen = {when:?}\n[tool.value.command]\n\
                         command = [\"/usr/bin/true\"]\nnative-filesystem-policy = {selected}"
                    ),
                );
                let profile = format!(
                    "packs = [\"@box/wrapper\"]\n[experimental-features]\n\
                     native-filesystem-policy = true\n[tool.command]\n\
                     native-filesystem-policy = {}",
                    !selected
                );
                let error = shelf
                    .chain(&profile)
                    .expect_err("the profile cannot mask a wrapped pack selection");
                assert_native_pack_refusal(
                    error,
                    &shelf,
                    "native",
                    "tool.value.command.native-filesystem-policy",
                );
            }
        }
    }

    #[test]
    fn native_free_wrapped_tool_collections_remain_valid() {
        let shelf = Shelf::new();
        for when in ["linux", "macos"] {
            for process in [
                String::new(),
                "when = \"linux\"\n[tool.value.command.value]\n".to_string(),
            ] {
                let env = if process.is_empty() {
                    "tool.value.command.env"
                } else {
                    "tool.value.command.value.env"
                };
                let text = format!(
                    "[tool]\nwhen = {when:?}\n[tool.value.command]\n{process}\
                     command = [\"/usr/bin/true\"]\n[{env}]\n\
                     native-filesystem-policy = \"an environment value\""
                );
                shelf.share("native", &text);
                let layers = shelf
                    .chain("packs = [\"@box/native\"]")
                    .expect("a wrapper with no native policy selection");
                let merged = merge(&layers).expect("a wrapped tool collection");
                assert_eq!(merged.table["tool"]["when"].as_str(), Some(when));
            }
        }
    }

    #[test]
    fn native_policy_is_profile_only_in_top_level_pack_value_tables() {
        let shelf = Shelf::new();
        for body in [
            "[run]\ncommand = [\"/bin/agent\"]\n".to_string(),
            test_tool_pack("native", ""),
        ] {
            for selected in [true, false] {
                shelf.share(
                    "native",
                    &format!(
                        "{body}\n[native-filesystem-policy]\nvalue = {selected}\nwhen = \"macos\""
                    ),
                );
                let error = shelf
                    .chain("packs = [\"@box/native\"]")
                    .expect_err("a pack value table");
                assert_native_pack_refusal(error, &shelf, "native", "native-filesystem-policy");
            }
        }
    }

    #[test]
    fn native_policy_is_profile_only_through_extensions_and_profile_overrides() {
        let shelf = Shelf::new();
        shelf.share("wrapper", "extend = [\"@box/native\"]");
        for selection in [
            "[experimental-features]\nnative-filesystem-policy = true",
            "[agent]\nnative-filesystem-policy = false",
            "[tool.git]\nnative-filesystem-policy = { value = true, when = \"macos\" }",
        ] {
            shelf.share("native", selection);
            let error = shelf.chain(
                "packs = [\"@box/wrapper\"]\n[experimental-features]\nnative-filesystem-policy = false\n\
                 [agent]\nnative-filesystem-policy = true\n[tool.git]\nnative-filesystem-policy = false"
            ).expect_err("the profile cannot mask a pack's selection");
            let field = if selection.starts_with("[experimental-features]") {
                "experimental-features"
            } else {
                "native-filesystem-policy"
            };
            assert_native_pack_refusal(error, &shelf, "native", field);
        }
    }

    #[test]
    fn the_native_filesystem_experiment_refuses_unknown_keys_and_non_booleans() {
        let shelf = Shelf::new();
        let why = reason(
            shelf
                .chain("experimental-features = true")
                .expect_err("a scalar experiment table"),
        );
        assert!(
            why.contains("`[experimental-features]` is a table"),
            "{why}"
        );
        for (text, wanted) in [
            (
                "[experimental-features]\nnative-filesystem-policy = 1",
                "`experimental-features.native-filesystem-policy` is `true` or `false`",
            ),
            (
                "[experimental-features]\nnative-filesystem-policy = \"true\"",
                "`experimental-features.native-filesystem-policy` is `true` or `false`",
            ),
            (
                "[experimental-features]\nnative-filesystem-policy = { value = 1, when = \"linux\" }",
                "`experimental-features.native-filesystem-policy` is `true` or `false`",
            ),
            (
                "[experimental-features]\nnative-filesystem-policy = { value = \"true\", when = \"macos\" }",
                "`experimental-features.native-filesystem-policy` is `true` or `false`",
            ),
            (
                "[experimental-features]\nnative-filesystem-policy = { value = true }",
                "`experimental-features.native-filesystem-policy` is `true` or `false`",
            ),
            (
                "[experimental-features]\nwhen = \"linux\"\nnative-filesystem-policy = 1",
                "`experimental-features.native-filesystem-policy` is `true` or `false`",
            ),
            (
                "[experimental-features]\nnative-filesytem-policy = true",
                "did you mean `native-filesystem-policy`?",
            ),
            (
                "[experimental-features]\ntool-grammars = true",
                "unknown key `tool-grammars`",
            ),
            (
                "[experimental-features]\nsecret-sources = true",
                "unknown key `secret-sources`",
            ),
        ] {
            let why = reason(shelf.chain(text).expect_err(text));
            assert!(why.contains(wanted), "{text}: {why}");
        }
    }

    #[test]
    fn native_filesystem_policy_selections_stay_with_their_profile_processes() {
        let shelf = Shelf::new();
        shelf.share(
            "agent",
            "[run]\ncommand = [\"/bin/agent\"]\n\
                              [tool.custom]\ncommand = [\"/bin/custom\"]\n\
                              [tool.inherited]\ncommand = [\"/bin/inherited\"]",
        );
        for selected in [true, false] {
            let profile = format!(
                "packs = [\"@box/agent\"]\n[experimental-features]\nnative-filesystem-policy = true\n\
                 [agent]\nnative-filesystem-policy = {selected}\n\
                 [tool.custom]\nnative-filesystem-policy = {}\n\
                 [mcp.local]\ntype = \"stdio\"\ncommand = [\"/bin/server\"]\n\
                 native-filesystem-policy = {}",
                !selected, !selected
            );
            let merged = merge(&shelf.chain(&profile).expect("a profile")).expect("a merge");
            assert_eq!(
                merged.table["agent"]["native-filesystem-policy"].as_bool(),
                Some(selected)
            );
            assert_eq!(
                merged.table["tool"]["custom"]["native-filesystem-policy"].as_bool(),
                Some(!selected)
            );
            assert_eq!(
                merged.table["mcp"]["local"]["native-filesystem-policy"].as_bool(),
                Some(!selected)
            );
            assert!(
                merged.table["tool"]["inherited"]
                    .get("native-filesystem-policy")
                    .is_none()
            );
            assert_eq!(
                merged.table["experimental-features"]["native-filesystem-policy"].as_bool(),
                Some(true)
            );
        }
    }

    #[test]
    fn a_profile_selects_native_filesystem_policy_for_a_packed_tool() {
        let shelf = Shelf::new();
        shelf.share("git", &test_tool_pack("git", ""));
        let packed =
            merge(&shelf.chain("packs = [\"@box/git\"]").expect("a profile")).expect("a merge");
        assert!(
            packed.table["tool"]["git"]
                .get("native-filesystem-policy")
                .is_none()
        );
        let text = "packs = [\"@box/git\"]\n[experimental-features]\nnative-filesystem-policy = true\n\
                    [tool.git]\nnative-filesystem-policy = true";
        let merged = merge(&shelf.chain(text).expect("a profile")).expect("a merge");
        assert_eq!(
            merged.table["tool"]["git"]["native-filesystem-policy"].as_bool(),
            Some(true)
        );
        assert_eq!(
            merged.table["experimental-features"]["native-filesystem-policy"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn a_top_level_native_filesystem_policy_selection_names_global_and_process_tables() {
        let shelf = Shelf::new();
        let why = reason(
            shelf
                .chain("native-filesystem-policy = true")
                .expect_err("a misplaced selection"),
        );
        for wanted in [
            "`[experimental-features]`",
            "select it for every process",
            "`[agent]`",
            "`[tool.<name>]`",
            "override one process",
        ] {
            assert!(why.contains(wanted), "{why}");
        }
    }

    #[test]
    fn misspelled_native_filesystem_policy_selections_name_the_correct_key() {
        let shelf = Shelf::new();
        for section in ["agent", "tool.custom"] {
            let text = format!("[{section}]\nnative-filesytem-policy = true");
            let why = reason(shelf.chain(&text).expect_err("a misspelled selection"));
            assert!(
                why.contains("did you mean `native-filesystem-policy`?"),
                "{section}: {why}"
            );
        }
    }

    fn tool_pack_refusal(shelf: &Shelf, name: &str, text: &str) -> String {
        shelf.share(name, text);
        reason(
            shelf
                .chain(&format!("packs = [\"@box/{name}\"]"))
                .expect_err(text),
        )
    }

    #[test]
    fn a_tool_pack_is_the_inside_of_the_tool_table_its_name_ends_with() {
        let shelf = Shelf::new();
        shelf.share(
            "git",
            "kind = \"tool\"\n[inputs.git.path]\ntype = \"program\"\nprogram = \"git\"\n\
             search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.git.path }}\"]\n\
             helpers = [\"cc\"]\nhosts = [\"example.com\"]\nwhen = \"macos\"\n[inputs.x]\n\
             default = \"1\"\n[env]\nA = \"1\"\n[filesystem]\nexec = [\"/x\"]\ndeny = [\"/y\"]",
        );
        let merged =
            merge(&shelf.chain("packs = [\"@box/git\"]").expect("a chain")).expect("a merge");
        let git = merged.table["tool"]["git"].as_table().expect("[tool.git]");
        let keys: Vec<&str> = git.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["env", "filesystem", "helpers", "hosts", "program", "when"]
        );
        assert_eq!(git["filesystem"]["exec"][0].as_str(), Some("/x"));
        assert_eq!(git["filesystem"]["deny"][0].as_str(), Some("/y"));
        let top: Vec<&str> = merged.table.keys().map(String::as_str).collect();
        assert_eq!(top, ["tool"]);
        assert!(
            merged.declarations.contains_key("x"),
            "inputs stay at the top"
        );
        assert_eq!(
            merged.tool_packs,
            BTreeMap::from([("git".to_string(), "@box/git".to_string())])
        );
    }

    #[test]
    fn root_in_a_tool_pack_becomes_the_root_of_its_tool() {
        let shelf = Shelf::new();
        shelf.share(
            "git",
            "kind = \"tool\"\n[inputs.git.path]\ntype = \"program\"\nprogram = \"git\"\n\
             search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.git.path }}\"]\n[env]\n\
             A = \"${{ root }}/x\"\nB = \"$${{ root }}\"\nC = \"${{ tool.git.root }}\"",
        );
        let merged =
            merge(&shelf.chain("packs = [\"@box/git\"]").expect("a chain")).expect("a merge");
        let env = &merged.table["tool"]["git"]["env"];
        assert_eq!(env["A"].as_str(), Some("${{ tool.git.root }}/x"));
        assert_eq!(
            env["B"].as_str(),
            Some("$${{ root }}"),
            "an escape stays literal"
        );
        assert_eq!(env["C"].as_str(), Some("${{ tool.git.root }}"));
    }

    #[test]
    fn a_tool_pack_name_ends_in_a_tool_name() {
        let reason = tool_pack_refusal(&Shelf::new(), "g.it", &test_tool_pack("git", ""));
        assert!(
            reason.contains("writes `[tool.g.it]`") && reason.contains("letters, digits"),
            "{reason}"
        );
    }

    #[test]
    fn a_tool_pack_holds_no_command_and_no_workspace() {
        let shelf = Shelf::new();
        let reason = tool_pack_refusal(
            &shelf,
            "a",
            &test_tool_pack("a", "").replace("path }}\"]", "path }}\", \"--flag\"]"),
        );
        assert!(
            reason.contains(
                "a tool pack's `[run] command` is its program input alone, such as \
                 `command = [\"${{ inputs.git.path }}\"]`"
            ),
            "{reason}"
        );
        shelf.share_raw(
            "b",
            &format!(
                "workspace = \"/w\"\n{}[inputs.b.path]\ntype = \"program\"\nprogram = \"b\"\n\
                 search = [{{ env = \"PATH\" }}]\n[run]\ncommand = [\"${{{{ inputs.b.path }}}}\"]",
                header("b", "tool")
            ),
        );
        let reason = shelf.kind_refusal("b");
        assert!(
            reason.contains(
                "a tool pack holds no `workspace`, because `box run` sets it for each run"
            ),
            "{reason}"
        );
    }

    #[test]
    fn an_agent_pack_writes_its_agents_keys_at_its_top() {
        let shelf = Shelf::new();
        shelf.share(
            "agent",
            "[run]\ncommand = [\"/bin/a\"]\ndependency = [\"egress.model\"]\nwhen = \"macos\"\n\
             [env]\nA = \"1\"\n[filesystem]\nread = [\"/r\"]\n[storage]\n\
             directories = [\"config\"]",
        );
        let merged =
            merge(&shelf.chain("packs = [\"@box/agent\"]").expect("a chain")).expect("a merge");
        let agent = merged.table["agent"].as_table().expect("[agent]");
        let keys: Vec<&str> = agent.keys().map(String::as_str).collect();
        assert_eq!(keys, ["command", "dependency", "env", "filesystem", "when"]);
        assert_eq!(agent["command"][0].as_str(), Some("/bin/a"));
        assert_eq!(agent["dependency"][0].as_str(), Some("egress.model"));
        assert_eq!(agent["env"]["A"].as_str(), Some("1"));
        assert_eq!(agent["filesystem"]["read"][0].as_str(), Some("/r"));
        for key in ["command", "dependency", "env", "filesystem", "when"] {
            assert!(!merged.table.contains_key(key), "{key} moves into [agent]");
        }
    }

    #[test]
    fn an_agent_pack_that_extends_one_adds_to_the_same_agent() {
        let shelf = Shelf::new();
        shelf.share("agent", "[run]\ncommand = [\"/bin/a\"]\n[env]\nA = \"1\"");
        shelf.share_raw(
            "team",
            &format!(
                "{}extend = [\"@box/agent\"]\n[env]\nB = \"2\"",
                header("team", "agent")
            ),
        );
        let merged =
            merge(&shelf.chain("packs = [\"@box/team\"]").expect("a chain")).expect("a merge");
        let env = &merged.table["agent"]["env"];
        assert_eq!(env["A"].as_str(), Some("1"));
        assert_eq!(env["B"].as_str(), Some("2"));
        assert_eq!(merged.table["agent"]["command"][0].as_str(), Some("/bin/a"));
        shelf.share_raw(
            "wrap",
            &format!(
                "{}extend = [\"@box/agent\"]\n[run]\ncommand = [\"/bin/wrap\"]",
                header("wrap", "agent")
            ),
        );
        let merged =
            merge(&shelf.chain("packs = [\"@box/wrap\"]").expect("a chain")).expect("a merge");
        assert_eq!(
            merged.table["agent"]["command"][0].as_str(),
            Some("/bin/wrap"),
            "the extending pack's command wins"
        );
    }

    #[test]
    fn an_agent_pack_holds_no_agent_table() {
        let shelf = Shelf::new();
        for (name, text, at) in [
            (
                "a",
                "[run]\ncommand = [\"/bin/a\"]\n[agent.env]\nA = \"1\"",
                7,
            ),
            ("b", "[agent]\ncommand = [\"/bin/b\"]", 5),
        ] {
            shelf.share_raw(name, &format!("{}{text}", header(name, "agent")));
            let Err(Error::Profile { line, reason, .. }) =
                shelf.chain(&format!("packs = [\"@box/{name}\"]"))
            else {
                panic!("@box/{name} is refused");
            };
            assert_eq!(line, Some(at), "{name}: {reason}");
            assert!(
                reason.contains(
                    "an agent pack holds no `[agent]`; its agent's keys are in `[run]`, `[env]`, \
                     and `[filesystem]`"
                ),
                "{name}: {reason}"
            );
        }
    }

    #[test]
    fn a_support_pack_and_a_profile_name_the_process_of_each_key() {
        let shelf = Shelf::new();
        for key in ["env", "filesystem"] {
            shelf.share_raw(
                key,
                &format!("{}[{key}]\nA = \"1\"", header(key, "support")),
            );
            let reason = shelf.kind_refusal(key);
            assert!(
                reason.contains(&format!(
                    "a support pack holds no `[{key}]`; only an agent pack or a tool pack runs \
                     a program"
                )),
                "{key}: {reason}"
            );
        }
        for (key, text) in [
            ("command", "command = [\"/bin/x\"]"),
            ("env", "[env]\nA = \"1\""),
        ] {
            let reason = reason(shelf.chain(text).expect_err(text));
            assert!(
                reason.contains(&format!(
                    "a profile holds no top-level `{key}`; write it in `[agent]` or in a \
                     `[tool.<name>]` table"
                )),
                "{key}: {reason}"
            );
        }
        let reason = reason(
            shelf
                .chain("[filesystem]\nread = [\"/x\"]")
                .expect_err("a grant for no process"),
        );
        assert!(
            reason.contains(
                "a profile's `[filesystem]` holds only `deny` and `deny_write`, for every \
                 process; write `read` in `[agent.filesystem]` or a `[tool.<name>.filesystem]` \
                 table"
            ),
            "{reason}"
        );
    }

    #[test]
    fn a_tool_finds_its_program_on_path_only() {
        let shelf = Shelf::new();
        let only_path = "`[inputs.git.path]` is the program of the tool, so it finds the program \
                         on `PATH` only: write `search = [{ env = \"PATH\" }]`";
        for (text, wanted) in [
            (
                test_tool_pack("git", "").replace(
                    "search = [{ env = \"PATH\" }]",
                    "search = [{ env = \"PATH\" }, \"/opt/git/bin\"]",
                ),
                only_path.to_string(),
            ),
            (
                test_tool_pack("git", "").replace(
                    "program = \"git\"\n",
                    "program = \"git\"\ndefault = \"/opt/git/bin/git\"\n",
                ),
                format!(
                    "{only_path}. Other folders and a set path are not supported for a tool yet; remove `default`"
                ),
            ),
            (
                test_tool_pack("git", "").replace("type = \"program\"", "type = \"string\""),
                "`[inputs.git.path]` is the program of the tool, so it is `type = \"program\"`"
                    .to_string(),
            ),
            (
                test_tool_pack("git", "").replace("[inputs.git.path]", "[inputs.other.path]"),
                "`[run] command` names `inputs.git.path`, which this pack does not declare"
                    .to_string(),
            ),
            (
                test_tool_pack("git", "[env]\nGIT = \"${{ inputs.git.path }}\""),
                "names `inputs.git.path`, the program of the tool; only `[run] command` names it. \
                 Use `${{ root }}` for the folder of the program"
                    .to_string(),
            ),
            (
                test_tool_pack("git", "").replace("${{ inputs.git.path }}", "/usr/bin/git"),
                "a tool pack's `[run] command` is its program input alone".to_string(),
            ),
            (
                test_tool_pack("git", "")
                    .replace("type = \"program\"", "description = 1\ntype = \"program\""),
                "`[inputs.git.path] description` is not a string".to_string(),
            ),
            (
                test_tool_pack("git", "helpers = [\"${{ inputs.git.path }}\"]"),
                "names `inputs.git.path`, the program of the tool; only `[run] command` names it"
                    .to_string(),
            ),
            (
                test_tool_pack("git", "").replace("{ env = \"PATH\" }", "{ env = \"HOME\" }"),
                only_path.to_string(),
            ),
            (
                test_tool_pack("git", "").replace("[\"${{ inputs.git.path }}\"]", "[]"),
                "a tool pack's `[run] command` is its program input alone".to_string(),
            ),
            (
                test_tool_pack("git", "").replace("program = \"git\"\n", ""),
                "`[inputs.git.path] program` is the name of a program, such as \"git\"".to_string(),
            ),
            (
                test_tool_pack("git", "").replace("program = \"git\"", "program = \"bin/git\""),
                "`[inputs.git.path] program` is the name of a program, such as \"git\"".to_string(),
            ),
        ] {
            let why = tool_pack_refusal(&shelf, "git", &text);
            assert!(why.contains(&wanted), "{text}\n{why}");
        }
        shelf.share("git", &test_tool_pack("git", ""));
        let merged =
            merge(&shelf.chain("packs = [\"@box/git\"]").expect("a chain")).expect("a merge");
        assert_eq!(merged.table["tool"]["git"]["program"].as_str(), Some("git"));
        assert!(
            !merged.declarations.contains_key("git.path"),
            "the program input leaves the pack"
        );
        let why = reason(
            shelf
                .chain("packs = [\"@box/git\"]\n[options]\n\"git.path\" = \"/opt/git/bin/git\"")
                .and_then(|layers| merge(&layers).map(|_| layers))
                .expect_err("a set path"),
        );
        assert!(why.contains(only_path), "{why}");
        shelf.share_raw(
            "also",
            &format!(
                "{}[inputs.git.path]\ntype = \"program\"\nprogram = \"git\"\nsearch = [\"/opt/git/bin\"]",
                header("also", "support")
            ),
        );
        let why = reason(
            shelf
                .chain(
                    "packs = [\"@box/git\", \"@box/also\"]\n[options]\n\"git.path\" = \"/opt/git/bin/git\"",
                )
                .and_then(|layers| merge(&layers).map(|_| layers))
                .expect_err("a second declaration of the program input"),
        );
        assert!(
            why.contains(
                "@box/also declares `inputs.git.path`, the program of the tool pack @box/git; only \
                 its `[run] command` names it. Declare a program input of your own, or use \
                 `${{ tool.git.root }}`"
            ),
            "{why}"
        );
        shelf.share(
            "bare",
            &test_tool_pack("bare", "").replace("search = [{ env = \"PATH\" }]\n", ""),
        );
        let merged = merge(&shelf.chain("packs = [\"@box/bare\"]").expect("a chain"))
            .expect("no search is PATH only");
        assert_eq!(
            merged.table["tool"]["bare"]["program"].as_str(),
            Some("bare")
        );
        shelf.share_raw(
            "mine",
            &format!(
                "{}include = [\"@box/git\"]\n[run]\ncommand = [\"${{{{ inputs.git.path }}}}\"]",
                header("mine", "agent")
            ),
        );
        let why = reason(
            shelf
                .chain("packs = [\"@box/mine\"]")
                .and_then(|layers| merge(&layers).map(|_| layers))
                .expect_err("an agent that names a tool's program input"),
        );
        assert!(
            why.contains(
                "\"${{ inputs.git.path }}\" names `inputs.git.path`, the program of the tool pack \
                 @box/git"
            ),
            "{why}"
        );
    }

    #[test]
    fn a_tool_pack_writes_one_tool() {
        let shelf = Shelf::new();
        for key in ["agent", "egress", "tool", "telemetry"] {
            let reason = tool_pack_refusal(
                &shelf,
                key,
                &test_tool_pack("x", &format!("[{key}]\nx = 1")),
            );
            assert!(
                reason.contains(&format!(
                    "a tool pack writes one tool; put `[{key}]` in another pack"
                )),
                "{key}: {reason}"
            );
        }
        let reason = tool_pack_refusal(
            &shelf,
            "mcp",
            &test_tool_pack("x", "[mcp.x]\nenv.A = \"1\""),
        );
        assert!(
            reason.contains("a tool pack writes one tool; put `[mcp]` in another pack"),
            "{reason}"
        );
    }

    #[test]
    fn the_keys_of_a_tool_pack_belong_only_in_a_tool_pack() {
        let shelf = Shelf::new();
        let why = tool_pack_refusal(
            &shelf,
            "a",
            "[run]\ncommand = [\"/bin/a\"]\nhelpers = [\"cc\"]",
        );
        assert!(
            why.contains("the `[run]` of an agent pack holds the unknown key `helpers`"),
            "{why}"
        );
        let why = tool_pack_refusal(&shelf, "b", "[env]\nA = \"1\"");
        assert!(why.contains("a support pack holds no `[env]`"), "{why}");
        let folder = shelf.root.join("packs/c");
        std::fs::create_dir_all(&folder).expect("a folder");
        std::fs::write(
            folder.join(PACK_FILE),
            "[pack]\nname = \"@box/c\"\nversion = 1\nkind = \"tool\"\nprogram = \"c\"\n",
        )
        .expect("a pack");
        let why = reason(
            shelf
                .chain("packs = [\"@box/c\"]")
                .expect_err("program in [pack]"),
        );
        assert!(
            why.contains("`[pack]` holds the unknown key `program`"),
            "{why}"
        );
        let why = reason(
            shelf
                .chain("program = \"git\"")
                .expect_err("program in a profile"),
        );
        assert!(
            why.contains("a profile holds no top-level `program`"),
            "{why}"
        );
    }

    #[test]
    fn every_shipped_and_corpus_pack_states_a_kind_that_loads() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let lookup = Lookup {
            vendored: Some(root.join("resources/packs")),
            operator: root.join("test-corpus/packs"),
            collections: Vec::new(),
            version: "0.1.0",
        };
        let mut names = Vec::new();
        for (folder, prefix) in [("resources/packs", VENDORED), ("test-corpus/packs", "")] {
            for entry in std::fs::read_dir(root.join(folder)).expect("a pack folder") {
                let entry = entry.expect("an entry");
                if entry.path().join(PACK_FILE).is_file() {
                    let short = entry.file_name().into_string().expect("a name");
                    names.push(format!("{prefix}{short}"));
                }
            }
        }
        assert!(names.len() > 20, "{names:?}");
        for name in names {
            let table = lookup.table(&name).expect("a pack");
            assert!(pack_kind(&table).is_some(), "{name} states no kind");
            if pack_kind(&table) == Some(TOOL_KIND) {
                let short = name.rsplit('/').next().expect("a name");
                assert_eq!(
                    table.get("program").and_then(toml::Value::as_str),
                    Some(short),
                    "{name} loads as the tool {short} that runs the program {short}"
                );
                assert!(table.get("command").is_none(), "{name}");
            }
            let text = format!("packs = [{name:?}]");
            chain(
                &toml::from_str(&text).expect("TOML"),
                &text,
                &root.join("profile.toml"),
                None,
                &lookup,
            )
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
    }

    #[test]
    fn a_shipped_pack_is_named_with_the_box_scope_and_not_as_a_folder() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let lookup = Lookup {
            vendored: Some(root.join("resources/packs")),
            operator: root.join("test-corpus/packs"),
            collections: Vec::new(),
            version: "0.1.0",
        };
        assert_eq!(lookup.full_name("git").as_deref(), Ok("@box/git"));
        lookup.table("@box/git").expect("the shipped pack");
        let error = lookup.table("box/git").expect_err("the old spelling");
        assert!(
            error.contains("\"box/git\" is not a pack name; the pack that box ships is @box/git"),
            "{error}"
        );
        let error = lookup.table("box/nope").expect_err("no shipped pack");
        assert!(
            error.ends_with("\"box/nope\" is not a pack name"),
            "{error}"
        );
        let error = lookup.table("acme/git").expect_err("not the old spelling");
        assert!(
            error.ends_with("\"acme/git\" is not a pack name"),
            "{error}"
        );
    }

    #[test]
    fn a_shipped_tool_pack_is_one_with_a_top_level_program() {
        let shelf = Shelf::new();
        shelf.share(
            "a",
            "kind = \"tool\"\n[inputs.a.path]\ntype = \"program\"\nprogram = \"a\"\n\
                          search = [{ env = \"PATH\" }]\n[run]\n\
                          command = [\"${{ inputs.a.path }}\"]",
        );
        shelf.share("b", "[tool.b]\nprogram = \"b\"");
        shelf.share("c", "[run]\ncommand = [\"/bin/c\"]");
        let lookup = Lookup {
            vendored: Some(shelf.root.join("packs")),
            operator: shelf.root.join("operator"),
            collections: Vec::new(),
            version: "0.1.0",
        };
        assert_eq!(lookup.tool_packs(), ["@box/a"]);
        let table = lookup.table("@box/a").expect("a pack");
        assert_eq!(table["program"].as_str(), Some("a"));
        assert!(
            table.get("inputs").is_none(),
            "the program input leaves the pack"
        );
    }

    #[test]
    fn storage_is_one_folder_per_profile() {
        assert_eq!(
            storage_root(Path::new("/h/.strands/box"), "claude"),
            Path::new("/h/.strands/box/storage/claude/default")
        );
    }

    /// A grammar for `program`, named `name`.
    fn grammar(name: &str, program: &str) -> String {
        format!(
            "format = 1\nversion = 1\nname = {name:?}\nprogram = {program:?}\n\
             [shell.status]\nusage = \"{program} status\"\n"
        )
    }

    impl Shelf {
        /// Write `text` as the `grammar.toml` of the pack `@box/<name>`.
        fn grammar(&self, name: &str, text: &str) {
            std::fs::write(self.root.join("packs").join(name).join(GRAMMAR_FILE), text)
                .expect("a grammar");
        }
    }

    #[test]
    fn a_tool_packs_grammar_stays_apart_from_the_table_that_placeholders_fill() {
        let shelf = Shelf::new();
        shelf.share(
            "greet",
            "kind = \"tool\"\n[inputs.greet.path]\ntype = \"program\"\n\
                              program = \"greet\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                              command = [\"${{ inputs.greet.path }}\"]",
        );
        let text = "format = 1\nversion = 1\nname = \"greet\"\nprogram = \"greet\"\n\
                    [shell.pull]\nusage = \"greet pull ${{ root }}\"\n\
                    options.only = { value = \"required\", when = \"linux\" }\n";
        shelf.grammar("greet", text);
        let layers = shelf.chain("packs = [\"@box/greet\"]").expect("a chain");
        shelf.grammar("greet", "# changed after loading");
        assert_eq!(layers[0].grammar_text.as_deref(), Some(text));
        let merged = merge(&layers).expect("a merge");
        assert!(merged.table["tool"]["greet"].get("grammar").is_none());
        let written: toml::Table = toml::from_str(text).expect("TOML");
        assert_eq!(
            merged.grammars,
            BTreeMap::from([("greet".to_string(), written)])
        );
    }

    #[test]
    fn a_grammar_whose_name_is_not_its_tools_name_is_refused_with_its_pack() {
        let shelf = Shelf::new();
        shelf.share(
            "greet",
            "kind = \"tool\"\n[inputs.greet.path]\ntype = \"program\"\n\
                              program = \"greet\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                              command = [\"${{ inputs.greet.path }}\"]",
        );
        shelf.grammar("greet", &grammar("grot", "greet"));
        let reason = reason(
            merge(&shelf.chain("packs = [\"@box/greet\"]").expect("a chain"))
                .err()
                .expect("a name"),
        );
        assert!(reason.contains("@box/greet"), "{reason}");
        assert!(reason.contains("`name = \"greet\"`"), "{reason}");
    }

    #[test]
    fn a_grammar_whose_program_is_not_its_packs_program_is_refused_with_its_pack() {
        let shelf = Shelf::new();
        shelf.share(
            "greet",
            "kind = \"tool\"\n[inputs.greet.path]\ntype = \"program\"\n\
                              program = \"greet\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                              command = [\"${{ inputs.greet.path }}\"]",
        );
        shelf.grammar("greet", &grammar("greet", "hub"));
        let reason = reason(
            merge(&shelf.chain("packs = [\"@box/greet\"]").expect("a chain"))
                .err()
                .expect("a program"),
        );
        assert!(reason.contains("@box/greet"), "{reason}");
        assert!(
            reason.contains("`program = \"hub\"`") && reason.contains("\"greet\""),
            "{reason}"
        );
    }

    #[test]
    fn a_profile_grammar_on_a_tool_whose_pack_has_one_is_refused_and_never_merged() {
        let shelf = Shelf::new();
        shelf.share(
            "greet",
            "kind = \"tool\"\n[inputs.greet.path]\ntype = \"program\"\n\
                              program = \"greet\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                              command = [\"${{ inputs.greet.path }}\"]",
        );
        shelf.grammar("greet", &grammar("greet", "greet"));
        let profile = format!(
            "packs = [\"@box/greet\"]\n[tool.greet.grammar]\n{}",
            grammar("greet", "greet")
                .replace("[shell.status]", "[tool.greet.grammar.shell.status]")
        );
        let reason = reason(
            merge(&shelf.chain(&profile).expect("a chain"))
                .err()
                .expect("a refused merge"),
        );
        assert!(
            reason.contains("@box/greet") && reason.contains("the profile"),
            "{reason}"
        );
        assert!(reason.contains("merges no grammar"), "{reason}");
    }

    #[test]
    fn two_packs_whose_grammars_share_a_program_are_refused_with_both_packs() {
        let shelf = Shelf::new();
        shelf.share(
            "greet",
            "kind = \"tool\"\n[inputs.greet.path]\ntype = \"program\"\n\
                              program = \"greet\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                              command = [\"${{ inputs.greet.path }}\"]",
        );
        shelf.grammar("greet", &grammar("greet", "greet"));
        shelf.share(
            "other_greet",
            "kind = \"tool\"\n[inputs.greet.path]\ntype = \"program\"\n\
                                    program = \"greet\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                                    command = [\"${{ inputs.greet.path }}\"]",
        );
        shelf.grammar("other_greet", &grammar("other_greet", "greet"));
        let reason = reason(
            merge(
                &shelf
                    .chain("packs = [\"@box/greet\", \"@box/other_greet\"]")
                    .expect("a chain"),
            )
            .err()
            .expect("a shared program"),
        );
        assert!(
            reason.contains("@box/greet") && reason.contains("@box/other_greet"),
            "{reason}"
        );
        assert!(reason.contains("`program = \"greet\"`"), "{reason}");
    }

    #[test]
    fn a_grammar_beside_a_pack_that_is_not_a_tool_pack_is_refused() {
        let shelf = Shelf::new();
        shelf.share("team", "[tool.greet]\nprogram = \"greet\"");
        shelf.grammar("team", &grammar("greet", "greet"));
        let reason = reason(
            shelf
                .chain("packs = [\"@box/team\"]")
                .expect_err("not a tool pack"),
        );
        assert!(reason.contains("@box/team is not a tool pack"), "{reason}");
    }

    #[test]
    fn a_grammar_on_a_tool_whose_name_is_no_policy_namespace_is_refused() {
        let shelf = Shelf::new();
        shelf.share(
            "team-agent",
            "kind = \"tool\"\n[inputs.team-agent.path]\ntype = \"program\"\n\
                                   program = \"team-agent\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                                   command = [\"${{ inputs.team-agent.path }}\"]",
        );
        shelf.grammar("team-agent", &grammar("team-agent", "team-agent"));
        let reason = reason(
            merge(
                &shelf
                    .chain("packs = [\"@box/team-agent\"]")
                    .expect("a chain"),
            )
            .err()
            .expect("a name with a hyphen"),
        );
        assert!(
            reason.contains("`[tool.team-agent]` has a grammar"),
            "{reason}"
        );
    }

    #[test]
    fn a_tool_pack_grammar_in_pack_toml_is_refused() {
        let shelf = Shelf::new();
        shelf.share(
            "greet",
            "kind = \"tool\"\n[inputs.greet.path]\ntype = \"program\"\nprogram = \"greet\"\n\
             search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.greet.path }}\"]\n\
             [grammar]\nname = \"greet\"\nprogram = \"greet\"\nusage = \"${{ root }}\"",
        );
        let reason = reason(
            shelf
                .chain("packs = [\"@box/greet\"]")
                .expect_err("an inline grammar"),
        );
        assert!(
            reason.contains("writes its grammar in grammar.toml"),
            "{reason}"
        );
    }

    #[test]
    fn a_profile_grammar_on_its_own_tool_reaches_the_merge() {
        let shelf = Shelf::new();
        let profile = format!(
            "[tool.greet]\nprogram = \"greet\"\n[tool.greet.grammar]\n{}",
            grammar("greet", "greet")
                .replace("[shell.status]", "[tool.greet.grammar.shell.status]")
        );
        let merged = merge(&shelf.chain(&profile).expect("a chain")).expect("a merge");
        assert!(merged.table["tool"]["greet"].get("grammar").is_none());
        let written: toml::Table = toml::from_str(&grammar("greet", "greet")).expect("TOML");
        assert_eq!(merged.grammars["greet"], written);
    }

    #[test]
    fn a_collection_pack_is_found_only_by_its_scoped_name() {
        let shelf = Shelf::new();
        shelf.share("base", "kind = \"support\"\n");
        shelf.collect("team", "extend = [\"@box/base\"]\n");
        let layers = shelf
            .chain("packs = [\"@acme/team\"]")
            .expect("a collection pack");
        let names: Vec<&str> = layers.iter().map(|layer| layer.name.as_str()).collect();
        assert!(
            names.contains(&"@acme/team") && names.contains(&"@box/base"),
            "{names:?}"
        );
        shelf.own("mine", "extend = [\"@acme/team\"]\n");
        let names: Vec<String> = shelf
            .chain("packs = [\"mine\"]")
            .expect("an extend of a collection pack")
            .into_iter()
            .map(|layer| layer.name)
            .collect();
        assert!(names.contains(&"@acme/team".to_string()), "{names:?}");
        let lookup = shelf.lookup();
        assert_eq!(lookup.full_name("@acme/team"), Ok("@acme/team".to_string()));
        assert_eq!(lookup.spelling("@acme/team"), "@acme/team");
        assert!(!lookup.shadows("@acme/team"));
        let plugin = shelf.root.join("acme/plugins/vault");
        std::fs::create_dir_all(&plugin).expect("a plugin folder");
        std::fs::write(plugin.join(crate::plugin::PLUGIN_FILE), "").expect("a plugin");
        assert_eq!(lookup.plugin_folder("@acme/vault"), Ok(plugin));
        let short = reason(shelf.chain("packs = [\"team\"]").expect_err("a short name"));
        assert!(short.contains("does not exist"), "{short}");
        let unknown = reason(
            shelf
                .chain("packs = [\"@other/team\"]")
                .expect_err("an unknown collection"),
        );
        assert!(
            unknown.contains("names the collection @other") && unknown.contains("external/other"),
            "{unknown}"
        );
        shelf.collect("named", "");
        std::fs::write(
            shelf.root.join("acme/packs/named").join(PACK_FILE),
            "[pack]\nname = \"named\"\nversion = 1\nkind = \"support\"\n",
        )
        .expect("a pack");
        let named = reason(
            shelf
                .chain("packs = [\"@acme/named\"]")
                .expect_err("a short header name"),
        );
        assert!(named.contains("imported as \"@acme/named\""), "{named}");
    }
}
