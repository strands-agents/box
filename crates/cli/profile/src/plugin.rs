//! The plugins that a profile lists: where each one is, the check of its file, and the rules on
//! who declares a secret source and who names a reference that one reads.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::lang::{self, Layer, Lookup, PackLocation, Piece, Refusal};
use crate::locate::unknown_key;

/// The profile key that lists plugins, and the folder beside `packs` that holds them.
pub const PLUGINS: &str = "plugins";

/// The file that holds a plugin.
pub const PLUGIN_FILE: &str = "plugin.toml";

/// The header table of a plugin.
pub const HEADER: &str = "plugin";

/// The table that declares how Box Core reads a secret with a host program.
pub const SECRET_SOURCE: &str = "secret-source";

/// The table of a plugin that names its program and how Box Core reads the program's output.
const RUN: &str = "run";

/// The table of a plugin that names each variable of the operator's shell that its program gets.
const ENV: &str = "env";

/// The table of a plugin that names what the box keeps from the agent, each tool, and each MCP
/// server.
const PROTECT: &str = "protect";

/// The table of a pack that grants paths, which a plugin does not hold.
const FILESYSTEM: &str = "filesystem";

/// The top-level keys of a plugin.
const PLUGIN_KEYS: &[&str] = &[HEADER, "inputs", RUN, ENV, PROTECT];

/// The keys of a plugin's `[plugin]` header.
pub(crate) const HEADER_KEYS: &[&str] = &["name", "version", "kind", "scheme"];

/// The keys of a plugin's `[run]`, which Box Core's table holds under the same names.
const RUN_KEYS: &[&str] = &["command", "output"];

/// The keys of one entry of a plugin's `[env]`.
const ENV_KEYS: &[&str] = &["from"];

/// The keys of a plugin's `[protect]`.
const PROTECT_KEYS: &[&str] = &["env", "paths"];

/// The key of Box Core's table that a plugin's `[protect] paths` fills.
const PROTECTED_PATHS: &str = "deny";

/// The contract between Box Core and the program of a secret source, which `box` writes for a
/// plugin.
const PROTOCOL: &str = "box.secret-source.v1";

/// The values of `[plugin] kind`.
const KINDS: &[&str] = &[SECRET_SOURCE];

impl Lookup {
    /// The folder of the plugin `name`: `@box/<name>` in the `plugins` folder beside the shipped
    /// packs, and any other name in the `plugins` folder beside the operator's packs.
    pub(crate) fn plugin_folder(&self, name: &str) -> Result<PathBuf, String> {
        let (packs, short) = match (name.strip_prefix(lang::VENDORED), self.in_collection(name)) {
            (Some(short), _) => (
                self.vendored
                    .clone()
                    .ok_or("box's own plugins were not found; set BOX_RESOURCES")?,
                short,
            ),
            (None, Some(found)) => {
                let (collection, short) = found?;
                (collection.join(crate::profile::PACKS), short)
            }
            (None, None) => (self.operator.clone(), name),
        };
        if !lang::is_pack_name(short) {
            let shipped = lang::renamed(name).filter(|shipped| self.plugin_folder(shipped).is_ok());
            return Err(match shipped {
                Some(shipped) => {
                    format!("{name:?} is not a plugin name; the plugin that box ships is {shipped}")
                }
                None => format!("{name:?} is not a plugin name"),
            });
        }
        let folder = packs.parent().unwrap_or(&packs).join(PLUGINS).join(short);
        let file = folder.join(PLUGIN_FILE);
        if !file.is_file() {
            return Err(format!(
                "the plugin {name:?} does not exist: {} is missing",
                file.display()
            ));
        }
        Ok(folder)
    }
}

/// The refusal of `key`, `packs`, `extend`, or `include`, when it names the plugin `name`.
pub(crate) fn named_as_pack(lookup: &Lookup, key: &str, name: &str) -> Option<String> {
    lookup.plugin_folder(name).ok()?;
    Some(match key {
        "packs" => format!("`packs` names {name}, which is a plugin; list it in `{PLUGINS}`"),
        _ => format!(
            "`{key}` names the plugin {name}; a pack cannot pull in a plugin, and only a profile \
             lists one, in `{PLUGINS}`"
        ),
    })
}

/// The plugin `name`, which the profile at `profile` lists, read and checked. The layer holds the
/// plugin's source as the `[secret-source.<scheme>]` table that Box Core reads, and no `run` or
/// `env`, which the merge reads as the agent's, and no `protect`.
pub(crate) fn load(name: &str, lookup: &Lookup, profile: &Path) -> Result<Layer, Error> {
    let invalid = |path: &Path, reason: String| Error::Profile {
        path: path.to_path_buf(),
        line: None,
        reason,
    };
    let folder = lookup.plugin_folder(name).map_err(|reason| {
        let reason = match lookup.has_pack(name) {
            true => format!("`{PLUGINS}` names {name}, which is a pack; list it in `packs`"),
            false => reason,
        };
        invalid(profile, reason)
    })?;
    let path = folder.join(PLUGIN_FILE);
    let text = crate::files::read_regular(&path).map_err(|source| Error::Io {
        action: "read",
        path: path.clone(),
        source,
    })?;
    let mut table: toml::Table =
        toml::from_str(&text).map_err(|error| invalid(&path, error.to_string()))?;
    lang::take_requires(&mut table, "plugin", lookup.version)
        .map_err(|refusal| refusal.in_file(&path, &text))?;
    check(&table, &text, name).map_err(|refusal| refusal.in_file(&path, &text))?;
    let table = translated(table, &text);
    let mut layer = Layer {
        name: name.to_string(),
        path,
        location: PackLocation::Other,
        shared: true,
        plugin: true,
        table,
        text,
        grammar_text: None,
        policy: None,
        grammars: BTreeMap::new(),
        program_input: None,
    };
    lang::bind_pack(&mut layer)?;
    Ok(layer)
}

/// Refuse a plugin that does not start with its `[plugin]` header, holds a key other than
/// `[plugin]`, `[inputs]`, `[run]`, `[env]`, and `[protect]`, names no scheme, or reads an input
/// in `[inputs]` that it does not declare, and each `[run]`, `[env]`, or `[protect]` whose shape
/// the translation cannot read. Box Core checks what a source may hold, such as the form of a
/// scheme and of a path, as it does for a source of the profile.
fn check(table: &toml::Table, text: &str, name: &str) -> Result<(), Refusal> {
    let Some(toml::Value::Table(header)) = table.get(HEADER) else {
        return Err(format!(
            "a plugin needs a `[{HEADER}]` header with `name`, `version`, `kind`, and `scheme`"
        )
        .into());
    };
    lang::refuse_header_not_first(text, HEADER, "a plugin")?;
    if table.contains_key(SECRET_SOURCE) {
        return Err(Refusal::at(
            format!(
                "a plugin holds no `[{SECRET_SOURCE}.<scheme>]` table; it names its scheme in \
                 `[{HEADER}] scheme`, its program in `[{RUN}] command`, each variable that the \
                 program gets in `[{ENV}]`, and what the box keeps from the agent in \
                 `[{PROTECT}]`"
            ),
            &[SECRET_SOURCE],
        ));
    }
    if table.contains_key(FILESYSTEM) {
        return Err(Refusal::at(
            format!(
                "a plugin holds no `[{FILESYSTEM}]` table, because a plugin grants nothing; name \
                 each path that the box keeps from the agent in `[{PROTECT}] paths`"
            ),
            &[FILESYSTEM],
        ));
    }
    if let Some(key) = table
        .keys()
        .find(|key| !PLUGIN_KEYS.contains(&key.as_str()))
    {
        return Err(Refusal::at(
            unknown_key("a plugin", key, PLUGIN_KEYS),
            &[key],
        ));
    }
    lang::check_header(header, HEADER, name)?;
    match header.get("kind") {
        None => {
            return Err(Refusal::at(
                format!("`[{HEADER}]` needs `kind`: {SECRET_SOURCE:?}"),
                &[HEADER],
            ));
        }
        Some(toml::Value::String(kind)) if KINDS.contains(&kind.as_str()) => {}
        Some(_) => {
            return Err(Refusal::at(
                format!("`[{HEADER}] kind` is {SECRET_SOURCE:?}"),
                &[HEADER, "kind"],
            ));
        }
    }
    match header.get("scheme") {
        None => {
            return Err(Refusal::at(
                format!(
                    "`[{HEADER}]` needs `scheme`: the scheme of each reference that this plugin \
                     reads, such as \"op\" for `op://`"
                ),
                &[HEADER],
            ));
        }
        Some(toml::Value::String(scheme)) if !scheme.is_empty() => {}
        Some(_) => {
            return Err(Refusal::at(
                format!("`[{HEADER}] scheme` is a string, such as \"op\""),
                &[HEADER, "scheme"],
            ));
        }
    }
    if table.get("inputs").is_some_and(|inputs| !inputs.is_table()) {
        return Err(Refusal::at("`inputs` is a table".into(), &["inputs"]));
    }
    let read = table.get("inputs").map(placeholders).unwrap_or_default();
    if let Some(name) = read.iter().find(|name| names_a_program_folder(name)) {
        return Err(Refusal::at(
            format!(
                "`[inputs]` reads `{name}`, the folder of a program that a pack finds; a plugin's \
                 inputs read no such folder, so no pack chooses the program that it runs"
            ),
            &["inputs"],
        ));
    }
    if let Some(name) = read
        .into_iter()
        .filter_map(|name| name.strip_prefix("inputs.").map(str::to_string))
        .find(|name| !declares(table, name))
    {
        return Err(Refusal::at(
            format!(
                "`[inputs]` reads `inputs.{name}`, which this plugin does not declare; a plugin's \
                 inputs read only the inputs of the plugin, so no pack chooses the program that it \
                 runs"
            ),
            &["inputs"],
        ));
    }
    check_run(table)?;
    check_env(table)?;
    check_protect(table)
}

/// Refuse a plugin with no `[run]`, and a `[run]` that holds a key other than `command` and
/// `output`, whose `command` is not a list of strings that starts with a `program` input of the
/// plugin, or reads the folder of a pack's program or an input that the plugin does not declare,
/// or whose `output` is not a string.
fn check_run(file: &toml::Table) -> Result<(), Refusal> {
    let Some(run) = file.get(RUN) else {
        return Err(Refusal::at(
            format!(
                "a plugin of kind {SECRET_SOURCE:?} needs `[{RUN}]` with `command`: the program \
                 that reads a secret, then its arguments"
            ),
            &[HEADER, "kind"],
        ));
    };
    let Some(run) = run.as_table() else {
        return Err(Refusal::at(format!("`{RUN}` is a table"), &[RUN]));
    };
    if let Some(key) = run.keys().find(|key| !RUN_KEYS.contains(&key.as_str())) {
        return Err(Refusal::at(
            unknown_key(&format!("a plugin's `[{RUN}]`"), key, RUN_KEYS),
            &[RUN, key],
        ));
    }
    let at = [RUN, "command"];
    let command: Option<Vec<&str>> = run
        .get("command")
        .and_then(toml::Value::as_array)
        .and_then(|command| command.iter().map(toml::Value::as_str).collect());
    let Some(command) = command else {
        return Err(Refusal::at(
            format!(
                "`[{RUN}] command` is a list of strings: the program, then its arguments, and \
                 no element takes a `when`"
            ),
            &at,
        ));
    };
    let read: Vec<String> = command
        .iter()
        .flat_map(|element| placeholders(&toml::Value::from(*element)))
        .collect();
    if let Some(name) = read.iter().find(|name| names_a_program_folder(name)) {
        return Err(Refusal::at(
            format!(
                "`[{RUN}] command` reads `{name}`, the folder of a program that a pack finds; a \
                 plugin reads no such folder, so no pack chooses the program that it runs or \
                 what it passes to it"
            ),
            &at,
        ));
    }
    let input = file.get(RUN).and_then(program_input);
    if !input.is_some_and(|name| declares_program(file, &name)) {
        return Err(Refusal::at(
            format!(
                "`[{RUN}] command` element 0 is the program, and a plugin finds it with an \
                 input: write `${{{{ inputs.<name> }}}}` for an input in this plugin's \
                 `[inputs]` with `type = \"program\"`"
            ),
            &at,
        ));
    }
    if let Some(name) = read
        .into_iter()
        .filter_map(|name| name.strip_prefix("inputs.").map(str::to_string))
        .find(|name| !declares(file, name))
    {
        return Err(Refusal::at(
            format!(
                "`[{RUN}] command` reads `inputs.{name}`, which this plugin does not declare; a \
                 plugin reads only its own inputs"
            ),
            &at,
        ));
    }
    match run.get("output") {
        Some(toml::Value::String(_)) | None => Ok(()),
        Some(_) => Err(Refusal::at(
            format!("`[{RUN}] output` is a string, such as \"json\""),
            &[RUN, "output"],
        )),
    }
}

/// Refuse a plugin's `[env]` that is not a table, and each entry whose key is not the name of a
/// variable, or whose value is not `{ from = "env:<the key>" }`.
fn check_env(file: &toml::Table) -> Result<(), Refusal> {
    let Some(env) = file.get(ENV) else {
        return Ok(());
    };
    let Some(env) = env.as_table() else {
        return Err(Refusal::at(format!("`{ENV}` is a table"), &[ENV]));
    };
    for (key, entry) in env {
        let at = [ENV, key.as_str()];
        let is_name = key
            .chars()
            .next()
            .is_some_and(|first| !first.is_ascii_digit())
            && key
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_');
        if !is_name {
            return Err(Refusal::at(
                format!(
                    "`[{ENV}] {key}` is not the name of a variable: a name is letters, digits, \
                     and `_`"
                ),
                &at,
            ));
        }
        let from = format!("env:{key}");
        let Some(entry) = entry.as_table() else {
            return Err(Refusal::at(
                format!(
                    "`[{ENV}] {key}` is `{{ from = {from:?} }}`; a plugin's `[{ENV}]` passes a \
                     variable of your shell to the plugin's program under its own name, and sets \
                     no value"
                ),
                &at,
            ));
        };
        if let Some(other) = entry.keys().find(|key| !ENV_KEYS.contains(&key.as_str())) {
            return Err(Refusal::at(
                format!(
                    "`[{ENV}] {key}` holds `{other}`; an entry of a plugin's `[{ENV}]` holds \
                     only `from`, and `[{PROTECT}] env` names each variable that the box keeps \
                     from the agent"
                ),
                &[ENV, key, other],
            ));
        }
        if entry.get("from").and_then(toml::Value::as_str) != Some(from.as_str()) {
            return Err(Refusal::at(
                format!(
                    "`[{ENV}] {key}` needs `from = {from:?}`; the program gets the variable \
                     under its own name, so `from` repeats the key"
                ),
                &at,
            ));
        }
    }
    Ok(())
}

/// Refuse a plugin's `[protect]` that is not a table or holds a key other than `env` and `paths`,
/// an `env` that is not a list of the keys of the plugin's `[env]`, and each entry of `paths` that
/// is not a string or that holds a placeholder other than a leading `${{ home }}`.
fn check_protect(file: &toml::Table) -> Result<(), Refusal> {
    let Some(protect) = file.get(PROTECT) else {
        return Ok(());
    };
    let Some(protect) = protect.as_table() else {
        return Err(Refusal::at(format!("`{PROTECT}` is a table"), &[PROTECT]));
    };
    if let Some(key) = protect
        .keys()
        .find(|key| !PROTECT_KEYS.contains(&key.as_str()))
    {
        return Err(Refusal::at(
            unknown_key(&format!("a plugin's `[{PROTECT}]`"), key, PROTECT_KEYS),
            &[PROTECT, key],
        ));
    }
    if let Some(names) = protect.get("env") {
        let at = [PROTECT, "env"];
        let Some(names) = names.as_array() else {
            return Err(Refusal::at(
                format!("`[{PROTECT}] env` is a list of the names of variables"),
                &at,
            ));
        };
        for (index, name) in names.iter().enumerate() {
            let Some(name) = name.as_str() else {
                return Err(Refusal::at(
                    format!("`[{PROTECT}] env[{index}]` is the name of a variable, as a string"),
                    &at,
                ));
            };
            let passed = file
                .get(ENV)
                .and_then(toml::Value::as_table)
                .is_some_and(|env| env.contains_key(name));
            if !passed {
                return Err(Refusal::at(
                    format!(
                        "`[{PROTECT}] env` names `{name}`, which this plugin's `[{ENV}]` does \
                         not hold; the box keeps from the agent only a variable that the \
                         plugin's program gets, so add `{name} = {{ from = \"env:{name}\" }}` to \
                         `[{ENV}]`"
                    ),
                    &at,
                ));
            }
        }
    }
    let Some(entries) = protect.get("paths") else {
        return Ok(());
    };
    let at = [PROTECT, "paths"];
    let Some(entries) = entries.as_array() else {
        return Err(Refusal::at(
            format!("`[{PROTECT}] paths` is a list of paths"),
            &at,
        ));
    };
    for (index, entry) in entries.iter().enumerate() {
        let here = format!("`[{PROTECT}] paths[{index}]`");
        let entry = match entry {
            toml::Value::String(entry) => entry,
            toml::Value::Table(_) => {
                return Err(Refusal::at(
                    format!(
                        "{here} is a table; a path of a plugin is a string, and it takes no \
                         `when` or `optional`"
                    ),
                    &at,
                ));
            }
            _ => {
                return Err(Refusal::at(format!("{here} is a path, as a string"), &at));
            }
        };
        if host_path(entry).is_none() {
            return Err(Refusal::at(
                format!(
                    "{here} = {entry:?} holds a placeholder that a path of a plugin does not \
                     take; write `${{{{ home }}}}/...`, `~/...`, or a full path"
                ),
                &at,
            ));
        }
    }
    Ok(())
}

/// `entry` of a plugin's `[protect] paths` with `~` for a leading `${{ home }}`, which is how Box
/// Core names the home in a path that a secret source protects, or `None` when it holds another
/// placeholder, or the escaped text of one.
fn host_path(entry: &str) -> Option<String> {
    let path = match lang::pieces(entry).ok()?.as_slice() {
        [] => String::new(),
        [Piece::Text(path)] => path.clone(),
        [Piece::Name(name)] if name == "home" => "~".to_string(),
        [Piece::Name(name), Piece::Text(rest)] if name == "home" => format!("~{rest}"),
        _ => return None,
    };
    (!path.contains("${{")).then_some(path)
}

/// The plugin `file`, which `check` passed and whose text is `text`, with its `[run]`, `[env]`,
/// and `[protect]` as the one `[secret-source.<scheme>]` table that Box Core reads. A variable of
/// `[env]` that `[protect] env` names is a credential, and each other one is a plain setting. Each
/// pass list keeps the order of `[env]` in the file.
fn translated(mut file: toml::Table, text: &str) -> toml::Table {
    let scheme = file
        .get(HEADER)
        .and_then(|header| header.get("scheme"))
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut source = toml::Table::new();
    source.insert("protocol".into(), PROTOCOL.into());
    if let Some(toml::Value::Table(run)) = file.remove(RUN) {
        source.extend(run);
    }
    let env = match file.remove(ENV) {
        Some(toml::Value::Table(env)) => env,
        _ => toml::Table::new(),
    };
    let protect = file.remove(PROTECT);
    let listed = |key: &str| -> Vec<&str> {
        protect
            .as_ref()
            .and_then(|protect| protect.get(key))
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .collect()
    };
    let credentials = listed("env");
    let (secret, plain): (Vec<String>, Vec<String>) = in_file_order(text, &env)
        .into_iter()
        .partition(|name| credentials.contains(&name.as_str()));
    let paths: Vec<String> = listed("paths").into_iter().filter_map(host_path).collect();
    for (key, entries) in [
        ("pass-env", plain),
        ("pass-secret-env", secret),
        (PROTECTED_PATHS, paths),
    ] {
        if !entries.is_empty() {
            source.insert(key.into(), entries.into());
        }
    }
    let mut sources = toml::Table::new();
    sources.insert(scheme, toml::Value::Table(source));
    file.insert(SECRET_SOURCE.into(), toml::Value::Table(sources));
    file
}

/// The keys of `env`, the `[env]` of the plugin whose text is `text`, in the order of the file.
fn in_file_order(text: &str, env: &toml::Table) -> Vec<String> {
    let mut names: Vec<String> = toml_edit::Document::parse(text)
        .ok()
        .and_then(|document| {
            let written = document.as_item().as_table_like()?.get(ENV)?;
            Some(
                written
                    .as_table_like()?
                    .iter()
                    .map(|(name, _)| name.to_string())
                    .filter(|name| env.contains_key(name))
                    .collect(),
            )
        })
        .unwrap_or_default();
    let rest: Vec<String> = env
        .keys()
        .filter(|name| !names.contains(name))
        .cloned()
        .collect();
    names.extend(rest);
    names
}

/// How a message names the secret source of `scheme` that `owner` declares: a plugin by its
/// name, because its file holds no `[secret-source.<scheme>]` table, and the profile by its table.
pub(crate) fn source_name(scheme: &str, owner: &str) -> String {
    if owner == lang::THE_PROFILE {
        format!("`[{SECRET_SOURCE}.{scheme}]` of the profile")
    } else {
        format!("the plugin {owner}")
    }
}

/// How a message names the list that fills `key`, the `reads` or `deny` of Box Core's table, in
/// the source that `owner` declares: a plugin's `[protect] paths`, and the profile's `reads` or
/// `deny`.
pub(crate) fn list_name(key: &'static str, owner: &str) -> &'static str {
    match (owner == lang::THE_PROFILE, key) {
        (false, PROTECTED_PATHS) => "[protect] paths",
        _ => key,
    }
}

/// How a message names the `command` of the secret source of `scheme`, which `owner` declares.
pub(crate) fn command_name(scheme: &str, owner: Option<&String>) -> String {
    match owner.filter(|owner| owner.as_str() != lang::THE_PROFILE) {
        Some(plugin) => format!("[{RUN}] command of the plugin {plugin}"),
        None => format!("[{SECRET_SOURCE}.{scheme}] command"),
    }
}

/// `reason`, which names a key of the merged table, with each key of a plugin's source named as
/// the plugin's file holds it: `secret-source.<scheme>.command.0` of a scheme in `owners` that a
/// plugin declares becomes `run.command.0` of that plugin. A scheme can hold a `.`, so the scheme
/// of a key is the longest one in `owners` that the key starts with.
pub(crate) fn shown(reason: String, owners: &BTreeMap<String, String>) -> String {
    let table = format!("`{SECRET_SOURCE}.");
    let (mut out, mut rest) = (String::new(), reason.as_str());
    while let Some(start) = rest.find(&table) {
        out.push_str(&rest[..start]);
        let after = &rest[start + table.len()..];
        let source = owners
            .iter()
            .filter(|(scheme, _)| after.starts_with(&format!("{scheme}.")))
            .max_by_key(|(scheme, _)| scheme.len());
        match (source, after.find('`')) {
            (Some((scheme, owner)), Some(end))
                if owner != lang::THE_PROFILE && end > scheme.len() + 1 =>
            {
                let key = file_key(&after[scheme.len() + 1..end]);
                out.push_str(&format!("`{key}` of the plugin {owner}"));
                rest = &after[end + 1..];
            }
            _ => {
                out.push_str(&table);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Whether `reason`, as `shown` writes it, starts with a key of the `command` of the source of
/// `scheme`, which the plugin `plugin` declares, or the profile when there is none.
pub fn names_command(reason: &str, scheme: &str, plugin: Option<&str>) -> bool {
    match plugin {
        None => reason.starts_with(&format!("`{SECRET_SOURCE}.{scheme}.command.")),
        Some(plugin) => reason
            .strip_prefix(&format!("`{RUN}.command."))
            .and_then(|rest| rest.split_once('`'))
            .is_some_and(|(_, after)| after.starts_with(&format!(" of the plugin {plugin}:"))),
    }
}

/// The key of a plugin's file that fills `key` of Box Core's table, such as `run.command.0` for
/// `command.0`.
fn file_key(key: &str) -> String {
    let (first, rest) = match key.split_once('.') {
        Some((first, rest)) => (first, format!(".{rest}")),
        None => (key, String::new()),
    };
    match first {
        "pass-env" | "pass-secret-env" => ENV.to_string(),
        PROTECTED_PATHS => format!("{PROTECT}.paths{rest}"),
        _ => format!("{RUN}.{key}"),
    }
}

/// Refuse a `[secret-source.<scheme>]` of the profile `file` that is not a table, holds a `when`,
/// or reads an input or the folder of a pack's program.
pub(crate) fn check_sources(file: &toml::Table) -> Result<(), Refusal> {
    let Some(sources) = file.get(SECRET_SOURCE) else {
        return Ok(());
    };
    let Some(sources) = sources.as_table() else {
        return Err(Refusal::at(
            format!(
                "`{SECRET_SOURCE}` holds one `[{SECRET_SOURCE}.<scheme>]` table for each scheme"
            ),
            &[SECRET_SOURCE],
        ));
    };
    for (scheme, source) in sources {
        let at = [SECRET_SOURCE, scheme.as_str()];
        if !source.is_table() {
            return Err(Refusal::at(
                format!("`{SECRET_SOURCE}.{scheme}` is a table"),
                &at,
            ));
        }
        if let Some(path) = when_in(source, &mut Vec::new()) {
            return Err(Refusal::at(
                format!(
                    "`[{SECRET_SOURCE}.{scheme}]` holds `when` at `{path}`; a secret source takes \
                     no `when`, so a profile declares the same schemes on every host"
                ),
                &at,
            ));
        }
        if let Some(name) = placeholders(source)
            .into_iter()
            .find(|name| names_a_program_folder(name))
        {
            return Err(Refusal::at(
                format!(
                    "`[{SECRET_SOURCE}.{scheme}]` reads `{name}`, the folder of a program that a \
                     pack finds; a source reads no such folder, so no pack chooses the program \
                     that it runs or what it passes to it"
                ),
                &at,
            ));
        }
        if let Some(name) = placeholders(source)
            .into_iter()
            .find(|name| name.starts_with("inputs."))
        {
            return Err(Refusal::at(
                format!(
                    "`[{SECRET_SOURCE}.{scheme}]` reads `{name}`, an input of a pack or a \
                     plugin; a source in the profile reads no input, so no pack or plugin \
                     chooses the program that it runs or what it passes to it: write each \
                     value of `command` in the profile"
                ),
                &at,
            ));
        }
    }
    Ok(())
}

/// Whether the placeholder `name` is the folder of a program that a pack's input finds: `root`,
/// the agent's, or `tool.<name>.root`, or one of their parents.
fn names_a_program_folder(name: &str) -> bool {
    let is_root = |name: &str| name == "root" || name.starts_with("root.");
    is_root(name)
        || name
            .strip_prefix("tool.")
            .and_then(|rest| rest.split_once('.'))
            .is_some_and(|(_, after)| is_root(after))
}

/// The input that element 0 of the `command` of `source` names, when it is exactly
/// `${{ inputs.<name> }}`.
fn program_input(source: &toml::Value) -> Option<String> {
    let head = source
        .get("command")
        .and_then(toml::Value::as_array)
        .and_then(|command| command.first())
        .and_then(toml::Value::as_str)?;
    match lang::pieces(head).ok()?.as_slice() {
        [Piece::Name(name)] => name.strip_prefix("inputs.").map(str::to_string),
        _ => None,
    }
}

/// The `program` that the plugin `layer` runs for `scheme`, such as `op`.
pub fn program(layer: &Layer, scheme: &str) -> Option<String> {
    let source = layer.table.get(SECRET_SOURCE)?.get(scheme)?;
    declaration(&layer.table, &program_input(source)?)?
        .get("program")?
        .as_str()
        .map(str::to_string)
}

/// The dotted path of the first `when` key in `value`, below `at`.
fn when_in(value: &toml::Value, at: &mut Vec<String>) -> Option<String> {
    let children: Vec<(String, &toml::Value)> = match value {
        toml::Value::Table(table) => table
            .iter()
            .map(|(key, item)| (key.clone(), item))
            .collect(),
        toml::Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| (index.to_string(), item))
            .collect(),
        _ => return None,
    };
    for (key, item) in children {
        at.push(key.clone());
        let found = match (key.as_str(), value) {
            ("when", toml::Value::Table(_)) => Some(at.join(".")),
            _ => when_in(item, at),
        };
        at.pop();
        if found.is_some() {
            return found;
        }
    }
    None
}

/// The declaration of the input `name` in the `[inputs]` of `file`.
fn declaration<'a>(file: &'a toml::Table, name: &str) -> Option<&'a toml::Value> {
    let mut value = file.get("inputs");
    for part in name.split('.') {
        value = value.and_then(|table| table.get(part));
    }
    value
}

/// Whether the `[inputs]` of `file` declare the input `name`.
fn declares(file: &toml::Table, name: &str) -> bool {
    declaration(file, name).is_some_and(|declaration| {
        declaration.as_table().is_some_and(|table| {
            table
                .keys()
                .any(|key| lang::DECLARATION_KEYS.contains(&key.as_str()))
        })
    })
}

/// Whether the `[inputs]` of `file` declare the input `name` with `type = "program"`.
fn declares_program(file: &toml::Table, name: &str) -> bool {
    declaration(file, name)
        .and_then(|declaration| declaration.get("type"))
        .and_then(toml::Value::as_str)
        == Some("program")
}

/// Each placeholder name in the strings of `value`.
fn placeholders(value: &toml::Value) -> Vec<String> {
    match value {
        toml::Value::String(text) => lang::pieces(text)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|piece| match piece {
                Piece::Name(name) => Some(name),
                Piece::Text(_) => None,
            })
            .collect(),
        toml::Value::Array(items) => items.iter().flat_map(placeholders).collect(),
        toml::Value::Table(table) => table.values().flat_map(placeholders).collect(),
        _ => Vec::new(),
    }
}

/// Each input that a plugin declares, with the plugin that declares it first.
pub(crate) fn inputs(layers: &[Layer]) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    for layer in layers.iter().filter(|layer| layer.plugin) {
        for name in declared_inputs(&layer.table) {
            found.entry(name).or_insert_with(|| layer.name.clone());
        }
    }
    found
}

/// Refuse a profile file that runs by its path, named `name`, when its own table declares a
/// `[secret-source.<scheme>]`, when it lists a plugin whose `[inputs]` or source reads
/// `${{ profile }}`, or when it sets in `[options]` an input of a plugin in `layers` that is a
/// `program` input, or that is not a `bool` and lists no `values`.
pub fn refuse_path_profile_programs(
    layers: &[Layer],
    name: &str,
    home: &Path,
    box_home: &Path,
) -> Result<(), Error> {
    let Some(profile) = layers.iter().find(|layer| !layer.shared) else {
        return Ok(());
    };
    let folder = |folder: &str| crate::host::tilde(home, &box_home.join(folder));
    let profiles = format!("{}/{name}/", folder("profiles"));
    if let Some(scheme) = profile
        .table
        .get(SECRET_SOURCE)
        .and_then(toml::Value::as_table)
        .and_then(|sources| sources.keys().next())
    {
        return Err(Refusal::at(
            format!(
                "a profile file that runs by its path declares no `[{SECRET_SOURCE}.{scheme}]`, \
                 because a secret source runs a program on the host, outside the box; put the \
                 source in a plugin in {}/<name>/ and list it in `{PLUGINS}`, or move the \
                 profile to {profiles}",
                folder(PLUGINS)
            ),
            &[SECRET_SOURCE, scheme],
        )
        .in_file(&profile.path, &profile.text));
    }
    for plugin in layers.iter().filter(|layer| layer.plugin) {
        let read = [plugin.table.get("inputs"), plugin.table.get(SECRET_SOURCE)]
            .into_iter()
            .flatten()
            .flat_map(placeholders)
            .find(|name| name == "profile" || name.starts_with("profile."));
        if let Some(placeholder) = read {
            return Err(Refusal::at(
                format!(
                    "the plugin {} reads `${{{{ {placeholder} }}}}`, and a profile file that runs \
                     by its path lists no such plugin, because there it names that file or its folder, so the \
                     file would choose the program that runs outside the box or a file that the \
                     program reads; write a fixed path in the plugin, or move the profile to \
                     {profiles}",
                    plugin.name
                ),
                &[PLUGINS],
            )
            .in_file(&profile.path, &profile.text));
        }
    }
    let mut options = Vec::new();
    if let Some(section) = profile.table.get("options") {
        option_keys(section, &mut Vec::new(), &mut options);
    }
    for at in options {
        let input = at.join(".");
        let Some(plugin) = layers
            .iter()
            .find(|layer| layer.plugin && declares(&layer.table, &input))
        else {
            continue;
        };
        let declared = declaration(&plugin.table, &input);
        let key = |key: &str| declared.and_then(|declared| declared.get(key));
        let at: Vec<&str> = std::iter::once("options")
            .chain(at.iter().map(String::as_str))
            .collect();
        if !declares_program(&plugin.table, &input) {
            let kind = key("type")
                .and_then(toml::Value::as_str)
                .unwrap_or("string");
            if kind == "bool" || key("values").is_some() {
                continue;
            }
            return Err(Refusal::at(
                format!(
                    "`[options] {input}` sets an input of the plugin {} that lists no `values` for \
                     it, and a profile file that runs by its path sets a plugin's input only to a \
                     value that the plugin lists, because the input can name the program that runs \
                     outside the box or what the program reads; move the profile to {profiles}",
                    plugin.name
                ),
                &at,
            )
            .in_file(&profile.path, &profile.text));
        }
        let found = match (key("program").and_then(toml::Value::as_str), key("search")) {
            (Some(program), None) => {
                format!("finds `{program}` on `PATH`, so put the program on `PATH`")
            }
            (Some(program), Some(_)) => format!(
                "finds `{program}` in the folders of its `search`, so put the program in one of them"
            ),
            (None, _) => "names its program in `default`, so use that program".to_string(),
        };
        return Err(Refusal::at(
            format!(
                "`[options] {input}` sets the program of the plugin {}, and a profile file that \
                 runs by its path chooses no program that runs outside the box; the plugin \
                 {found}, or move the profile to {profiles}",
                plugin.name
            ),
            &at,
        )
        .in_file(&profile.path, &profile.text));
    }
    Ok(())
}

/// The keys of each value in `section`, the `[options]` of a profile, as the TOML file nests them.
fn option_keys(section: &toml::Value, at: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match section {
        toml::Value::Table(table) => {
            for (key, item) in table {
                at.push(key.clone());
                option_keys(item, at, out);
                at.pop();
            }
        }
        _ => out.push(at.clone()),
    }
}

/// The full name of each input that `table` declares, or none for a malformed `[inputs]`, which
/// the merge refuses.
fn declared_inputs(table: &toml::Table) -> Vec<String> {
    let mut found = Vec::new();
    match table.get("inputs") {
        Some(section)
            if lang::collect_declarations(section, &mut Vec::new(), &mut found).is_ok() =>
        {
            found.into_iter().map(|(name, _)| name).collect()
        }
        _ => Vec::new(),
    }
}

/// Refuse an input that the pack or plugin `layer` declares in `table` when another plugin of
/// `plugin_inputs` declares it first.
pub(crate) fn refuse_foreign_inputs(
    layer: &Layer,
    table: &toml::Table,
    plugin_inputs: &BTreeMap<String, String>,
) -> Result<(), Refusal> {
    for name in declared_inputs(table) {
        let Some(owner) = plugin_inputs
            .get(&name)
            .filter(|owner| !(layer.plugin && **owner == layer.name))
        else {
            continue;
        };
        let at: Vec<&str> = std::iter::once("inputs").chain(name.split('.')).collect();
        let reason = if layer.plugin {
            format!(
                "the plugin {} declares `inputs.{name}`, an input of the plugin {owner}; an \
                 input belongs to one plugin, so a plugin cannot choose the program that another \
                 plugin runs or what it passes to it; give each plugin inputs of its own",
                layer.name
            )
        } else {
            format!(
                "{} declares `inputs.{name}`, an input of the plugin {owner}; only the plugin \
                 declares its inputs, so a pack cannot choose the program that a plugin runs or \
                 what it passes to it, and the profile sets the input in `[options]`",
                layer.name
            )
        };
        return Err(Refusal::at(reason, &at));
    }
    Ok(())
}

/// Each plugin that `layers` loads, with its `[plugin] version`, in the order of `plugins`.
pub fn versions(layers: &[Layer]) -> Vec<(String, String)> {
    layers
        .iter()
        .filter(|layer| layer.plugin)
        .map(|layer| {
            let version = layer
                .table
                .get(HEADER)
                .and_then(|header| header.get("version"))
                .and_then(toml::Value::as_integer)
                .map(|version| version.to_string())
                .unwrap_or_default();
            (layer.name.clone(), version)
        })
        .collect()
}

/// Each `[secret-source.<scheme>]` of `layers`, in the order of `plugins` and then the profile's
/// own, as `(scheme, the plugin that declares it)`, with `None` for a source of the profile.
pub fn sources(layers: &[Layer]) -> Vec<(String, Option<String>)> {
    layers
        .iter()
        .flat_map(|layer| {
            schemes(layer).map(|scheme| (scheme.clone(), layer.plugin.then(|| layer.name.clone())))
        })
        .collect()
}

/// Each scheme that `layer` declares, when it is a plugin or the profile.
fn schemes(layer: &Layer) -> impl Iterator<Item = &String> {
    layer
        .table
        .get(SECRET_SOURCE)
        .and_then(toml::Value::as_table)
        .filter(|_| layer.plugin || !layer.shared)
        .into_iter()
        .flat_map(toml::Table::keys)
}

/// Each scheme that a plugin or the profile declares, with the name of the file that declares it,
/// refusing two declarations of one scheme.
pub(crate) fn declared(layers: &[Layer]) -> Result<BTreeMap<String, String>, String> {
    let mut owners: BTreeMap<String, String> = BTreeMap::new();
    for layer in layers {
        for scheme in schemes(layer) {
            if let Some(first) = owners.get(scheme) {
                return Err(format!(
                    "the scheme `{scheme}` has two secret sources, {} and {}, and one scheme \
                     has one source; keep one of them",
                    source_name(scheme, first),
                    source_name(scheme, &layer.name)
                ));
            }
            owners.insert(scheme.clone(), layer.name.clone());
        }
    }
    Ok(owners)
}

/// Refuse a reference in a scheme of `declared` that the pack `pack` writes in `table`. The scheme
/// is read after the white space at each end, as Box Core reads a telemetry reference.
pub(crate) fn refuse_pack_references(
    pack: &str,
    table: &toml::Table,
    declared: &BTreeMap<String, String>,
) -> Result<(), Refusal> {
    for (at, key, reference) in references(table) {
        let Some((scheme, owner)) = reference
            .trim()
            .split_once("://")
            .and_then(|(scheme, _)| declared.get_key_value(scheme))
        else {
            continue;
        };
        let at: Vec<&str> = at.iter().map(String::as_str).collect();
        return Err(Refusal::at(
            format!(
                "{pack} writes `{key} = {reference:?}`, a reference in `{scheme}://`, which \
                 {owner} declares; only the profile names a reference that a secret source \
                 reads, so a pack cannot choose which secret the box reads"
            ),
            &at,
        ));
    }
    Ok(())
}

/// Each credential reference in `table`, as `(its key path, its key as written, the reference)`:
/// the `secret` of each egress route, MCP server, and telemetry target, and the `auth` of each
/// backend of a route.
fn references(table: &toml::Table) -> Vec<(Vec<String>, String, String)> {
    let mut found = Vec::new();
    for section in ["egress", "mcp", "telemetry"] {
        let entries = table
            .get(section)
            .map(lang::unwrapped)
            .and_then(toml::Value::as_table);
        for (name, entry) in entries.into_iter().flatten() {
            let entry = lang::unwrapped(entry);
            let owner = format!("[{section}.{name}]");
            let path = |rest: &[&str]| -> Vec<String> {
                [section, name.as_str()]
                    .iter()
                    .chain(rest)
                    .map(|part| (*part).to_string())
                    .collect()
            };
            if let Some((key, reference)) = reference_of(entry.get("secret")) {
                let rest: &[&str] = if key.is_empty() {
                    &["secret"]
                } else {
                    &["secret", "ref"]
                };
                found.push((path(rest), format!("{owner} secret{key}"), reference));
            }
            let backends = entry
                .get("backends")
                .map(lang::unwrapped)
                .and_then(toml::Value::as_array);
            for backend in backends.into_iter().flatten() {
                if let Some((key, reference)) = reference_of(lang::unwrapped(backend).get("auth")) {
                    found.push((
                        path(&["backends"]),
                        format!("{owner} backends.auth{key}"),
                        reference,
                    ));
                }
            }
        }
    }
    found
}

/// The reference that a credential names, with `.ref` when the credential is a table.
fn reference_of(credential: Option<&toml::Value>) -> Option<(&'static str, String)> {
    let credential = lang::unwrapped(credential?);
    match credential {
        toml::Value::String(reference) => Some(("", reference.clone())),
        _ => credential
            .get("ref")
            .map(lang::unwrapped)
            .and_then(toml::Value::as_str)
            .map(|reference| (".ref", reference.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::{Merged, chain, merge, test_kind_line};

    /// Shipped packs and plugins, and an operator home with its own.
    struct Shelf {
        _root: tempfile::TempDir,
        root: PathBuf,
    }

    /// The rest of a plugin's header and its body, for a plugin that reads `<scheme>://`
    /// references with the program `<scheme>`.
    fn source(scheme: &str) -> String {
        format!(
            "scheme = \"{scheme}\"\n\
             [inputs.{scheme}.path]\ntype = \"program\"\nprogram = \"{scheme}\"\n\
             [run]\n\
             command = [\"${{{{ inputs.{scheme}.path }}}}\", \"read\", \"{scheme}://{{ref}}\"]\n"
        )
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

        fn write(&self, path: &Path, text: &str) {
            std::fs::create_dir_all(path.parent().expect("a folder")).expect("a folder");
            std::fs::write(path, text).expect("a file");
        }

        /// Write the pack `@box/<name>`, with a header and its kind.
        fn pack(&self, name: &str, body: &str) {
            self.write(
                &self.root.join("packs").join(name).join(lang::PACK_FILE),
                &format!(
                    "[pack]\nname = \"@box/{name}\"\nversion = 1\n{}{body}",
                    test_kind_line(body)
                ),
            );
        }

        /// The shipped plugin `@box/<name>`, as `text` alone.
        fn plugin_file(&self, name: &str) -> PathBuf {
            self.root.join(PLUGINS).join(name).join(PLUGIN_FILE)
        }

        /// Write the shipped plugin `@box/<name>`, with a header.
        fn plugin(&self, name: &str, body: &str) {
            self.write(
                &self.plugin_file(name),
                &format!(
                    "[plugin]\nname = \"@box/{name}\"\nversion = 1\nkind = \"secret-source\"\n{body}"
                ),
            );
        }

        fn lookup(&self) -> Lookup {
            Lookup {
                vendored: Some(self.root.join("packs")),
                operator: self.root.join("home/.strands/box/packs"),
                collections: Vec::new(),
                version: "0.1.0",
            }
        }

        fn layers(&self, profile: &str) -> Result<Vec<Layer>, Error> {
            chain(
                &toml::from_str(profile).expect("TOML"),
                profile,
                &self.root.join("mine/profile.toml"),
                None,
                &self.lookup(),
            )
        }

        fn merged(&self, profile: &str) -> Result<Merged, Error> {
            merge(&self.layers(profile)?)
        }

        /// Why loading and merging `profile` is refused.
        fn refusal(&self, profile: &str) -> String {
            match self.merged(profile) {
                Err(Error::Profile { reason, .. }) => reason,
                Err(other) => panic!("a profile refusal, not {other}"),
                Ok(_) => panic!("a refusal of {profile}"),
            }
        }

        /// Why resolving `profile`, which merges, is refused on a host with no program and no
        /// variable.
        fn resolve_refusal(&self, profile: &str) -> String {
            let merged = self.merged(profile).expect("a merge");
            let home = self.root.join("home");
            let box_home = home.join(".strands/box");
            let folder = self.root.join("mine");
            let inputs = lang::Inputs {
                home: &home,
                box_home: &box_home,
                workspace: &self.root.join("work"),
                profile: &folder,
                profile_file: &folder.join("profile.toml"),
                box_dir: &self.root.join("run/box"),
                storage: &self.root.join("storage"),
                os: "macos",
                tool_cache: None,
                packs: None,
            };
            let resolved = crate::reference::resolve(
                merged,
                &BTreeMap::new(),
                &mut NoHost,
                &inputs,
                &folder.join("profile.toml"),
            );
            match resolved {
                Err(Error::Profile { reason, .. }) => reason,
                Err(other) => panic!("a profile refusal, not {other}"),
                Ok(_) => panic!("a refusal of {profile}"),
            }
        }
    }

    /// A host with no program, no variable, and no developer folder.
    struct NoHost;

    impl crate::reference::Sources for NoHost {
        fn env(&self, _: &str) -> Option<String> {
            None
        }

        fn env_with_prefix(&self, _: &str) -> Vec<(String, String)> {
            Vec::new()
        }

        fn program(&mut self, _: &str) -> Option<PathBuf> {
            None
        }

        fn search(&self, _: &str) -> Option<PathBuf> {
            None
        }

        fn developer_dir(&mut self) -> Result<String, String> {
            Err("no developer folder".to_string())
        }
    }

    #[test]
    fn a_profile_lists_a_plugin_after_its_packs_and_before_itself() {
        let shelf = Shelf::new();
        shelf.pack("base", "");
        shelf.plugin("op", &source("op"));
        shelf.write(
            &shelf
                .root
                .join("home/.strands/box/plugins/vault/plugin.toml"),
            &format!(
                "[plugin]\nname = \"vault\"\nversion = 2\nkind = \"secret-source\"\n{}",
                source("vault")
            ),
        );
        let layers = shelf
            .layers("packs = [\"@box/base\"]\nplugins = [\"@box/op\", \"vault\", \"@box/op\"]")
            .expect("a chain");
        assert_eq!(
            layers
                .iter()
                .map(|layer| (layer.name.as_str(), layer.shared, layer.plugin))
                .collect::<Vec<_>>(),
            vec![
                ("@box/base", true, false),
                ("@box/op", true, true),
                ("vault", true, true),
                ("the profile", false, false),
            ]
        );
        assert_eq!(
            layers[1].path,
            shelf.plugin_file("op"),
            "@box/op is the shipped plugin's file"
        );
        assert_eq!(
            layers[2].path,
            shelf
                .root
                .join("home/.strands/box/plugins/vault/plugin.toml"),
            "a plain name is the operator's plugin"
        );
    }

    #[test]
    fn only_a_profiles_plugins_list_names_a_plugin() {
        let shelf = Shelf::new();
        shelf.pack("base", "");
        shelf.plugin("op", &source("op"));
        for (name, text) in [
            (
                "team",
                "[pack]\nname = \"@box/team\"\nversion = 1\nkind = \"support\"\n\
                 extend = [\"@box/op\"]\n",
            ),
            (
                "lists",
                "plugins = [\"@box/op\"]\n[pack]\nname = \"@box/lists\"\nversion = 1\n\
                 kind = \"support\"\n",
            ),
            (
                "includes",
                "[pack]\nname = \"@box/includes\"\nversion = 1\nkind = \"support\"\n\
                 include = [\"@box/op\"]\n",
            ),
        ] {
            shelf.write(
                &shelf.root.join("packs").join(name).join(lang::PACK_FILE),
                text,
            );
        }
        shelf.write(
            &shelf.root.join("packs/odd/pack.toml"),
            &std::fs::read_to_string(shelf.plugin_file("op")).expect("the plugin"),
        );
        let missing = shelf.plugin_file("none");
        for (profile, wanted) in [
            (
                "packs = [\"@box/op\"]".to_string(),
                "`packs` names @box/op, which is a plugin; list it in `plugins`".to_string(),
            ),
            (
                "packs = [\"@box/team\"]".to_string(),
                "`extend` names the plugin @box/op; a pack cannot pull in a plugin, and only a \
                 profile lists one, in `plugins`"
                    .to_string(),
            ),
            (
                "packs = [\"@box/includes\"]".to_string(),
                "`include` names the plugin @box/op; a pack cannot pull in a plugin, and only a \
                 profile lists one, in `plugins`"
                    .to_string(),
            ),
            (
                "plugins = [\"@box/base\"]".to_string(),
                "`plugins` names @box/base, which is a pack; list it in `packs`".to_string(),
            ),
            (
                "plugins = [\"@box/none\"]".to_string(),
                format!(
                    "the plugin \"@box/none\" does not exist: {} is missing",
                    missing.display()
                ),
            ),
            (
                "plugins = [\"box/op\"]".to_string(),
                "\"box/op\" is not a plugin name; the plugin that box ships is @box/op".to_string(),
            ),
            (
                "plugins = [\"box/nope\"]".to_string(),
                "\"box/nope\" is not a plugin name".to_string(),
            ),
            (
                "plugins = \"@box/op\"".to_string(),
                "`plugins` is not a list of plugin names".to_string(),
            ),
            (
                "packs = [\"@box/lists\"]".to_string(),
                "a pack holds no `plugins`; `plugins` belongs in a profile".to_string(),
            ),
            (
                "packs = [\"@box/odd\"]".to_string(),
                "this file starts with `[plugin]`, so it is a plugin, not a pack; a plugin is \
                 `plugin.toml` in a folder of `plugins`, and a profile lists it in `plugins`"
                    .to_string(),
            ),
        ] {
            assert_eq!(shelf.refusal(&profile), wanted, "{profile}");
        }
    }

    #[test]
    fn a_plugin_holds_its_header_its_inputs_and_the_tables_of_its_program() {
        let shelf = Shelf::new();
        let header = "[plugin]\nname = \"@box/op\"\nversion = 1\nkind = \"secret-source\"\n";
        let op = source("op");
        let body = op.strip_prefix("scheme = \"op\"\n").expect("the scheme");
        let refusals = [
            (
                body.to_string(),
                "a plugin needs a `[plugin]` header with `name`, `version`, `kind`, and `scheme`",
            ),
            (
                format!("{body}{header}scheme = \"op\"\n"),
                "a plugin starts with `[plugin]`, and this one starts with `[inputs.op.path]`",
            ),
            (
                format!("{header}{op}[egress.x]\ndestinations = [\"x.example.com\"]\n"),
                "a plugin holds the unknown key `egress`; a plugin holds `plugin`, `inputs`, \
                 `run`, `env`, `protect`",
            ),
            (
                format!("{header}{op}[experimental-features]\nsecret-sources = true\n"),
                "a plugin holds the unknown key `experimental-features`; a plugin holds `plugin`, \
                 `inputs`, `run`, `env`, `protect`",
            ),
            (
                format!("{header}{op}[secret-source.op]\ncommand = [\"/usr/local/bin/op\"]\n"),
                "a plugin holds no `[secret-source.<scheme>]` table; it names its scheme in \
                 `[plugin] scheme`, its program in `[run] command`, each variable that the \
                 program gets in `[env]`, and what the box keeps from the agent in `[protect]`",
            ),
            (
                format!("{header}{op}[filesystem]\ndeny = [\"~/.config/op\"]\n"),
                "a plugin holds no `[filesystem]` table, because a plugin grants nothing; name \
                 each path that the box keeps from the agent in `[protect] paths`",
            ),
            (
                format!("{header}{op}[filesystem]\nread = [\"~/.config/op\"]\n"),
                "a plugin holds no `[filesystem]` table, because a plugin grants nothing; name \
                 each path that the box keeps from the agent in `[protect] paths`",
            ),
            (
                format!("{header}kinds = 1\n{op}"),
                "`[plugin]` holds the unknown key `kinds`; did you mean `kind`?",
            ),
            (
                format!("[plugin]\nversion = 1\nkind = \"secret-source\"\n{op}"),
                "`[plugin]` needs `name`",
            ),
            (
                format!("[plugin]\nname = \"@box/op\"\nkind = \"secret-source\"\n{op}"),
                "`[plugin]` needs `version`",
            ),
            (
                format!(
                    "[plugin]\nname = \"@box/op\"\nversion = -1\nkind = \"secret-source\"\n{op}"
                ),
                "`[plugin] version` is a whole number, such as 1",
            ),
            (
                format!(
                    "[plugin]\nname = \"@box/other\"\nversion = 1\nkind = \"secret-source\"\n{op}"
                ),
                "`[plugin] name = \"@box/other\"`, but this plugin is listed as \"@box/op\"",
            ),
            (
                format!("[plugin]\nname = \"@box/op\"\nversion = 1\n{op}"),
                "`[plugin]` needs `kind`: \"secret-source\"",
            ),
            (
                format!("[plugin]\nname = \"@box/op\"\nversion = 1\nkind = \"support\"\n{op}"),
                "`[plugin] kind` is \"secret-source\"",
            ),
            (
                format!("{header}{op}[requires]\nbox = \">=9.0.0\"\n"),
                "this plugin needs box >=9.0.0, and this is box 0.1.0",
            ),
            (
                format!("{header}engine = \">=0.1.0\"\n{op}"),
                "`[plugin]` holds the unknown key `engine`; `[plugin]` holds `name`, `version`, `kind`, `scheme`",
            ),
            (
                format!(
                    "inputs = 1\n{header}scheme = \"op\"\n[run]\n\
                     command = [\"${{{{ inputs.op.path }}}}\"]\n"
                ),
                "`inputs` is a table",
            ),
        ];
        for (text, wanted) in refusals {
            shelf.write(&shelf.plugin_file("op"), &text);
            assert_eq!(shelf.refusal("plugins = [\"@box/op\"]"), wanted, "{text}");
        }
        shelf.write(
            &shelf.plugin_file("op"),
            &format!("{header}{op}[requires]\nbox = \">=0.1.0\"\n"),
        );
        shelf
            .merged("plugins = [\"@box/op\"]")
            .expect("a plugin within its floor loads");
    }

    #[test]
    fn a_plugin_names_the_scheme_that_it_reads() {
        let shelf = Shelf::new();
        let header = "[plugin]\nname = \"@box/op\"\nversion = 1\nkind = \"secret-source\"\n";
        let op = source("op");
        let body = op.strip_prefix("scheme = \"op\"\n").expect("the scheme");
        shelf.write(&shelf.plugin_file("op"), &format!("{header}{body}"));
        assert_eq!(
            shelf.refusal("plugins = [\"@box/op\"]"),
            "`[plugin]` needs `scheme`: the scheme of each reference that this plugin reads, \
             such as \"op\" for `op://`"
        );
        for scheme in ["1", "\"\"", "true", "[\"op\"]"] {
            shelf.write(
                &shelf.plugin_file("op"),
                &format!("{header}scheme = {scheme}\n{body}"),
            );
            assert_eq!(
                shelf.refusal("plugins = [\"@box/op\"]"),
                "`[plugin] scheme` is a string, such as \"op\"",
                "{scheme}"
            );
        }
        for scheme in ["op", "aws-secretsmanager", "a1+b.c", "Op", "env"] {
            shelf.write(
                &shelf.plugin_file("op"),
                &format!("{header}scheme = \"{scheme}\"\n{body}"),
            );
            let merged = shelf
                .merged("plugins = [\"@box/op\"]")
                .expect("Box Core, not `box`, checks the form of a scheme and the reserved ones");
            assert_eq!(
                merged.sources,
                BTreeMap::from([(scheme.to_string(), "@box/op".to_string())]),
                "the scheme names the table that Box Core reads"
            );
        }
    }

    #[test]
    fn a_plugins_run_holds_its_command_and_its_output() {
        let shelf = Shelf::new();
        let header = "[plugin]\nname = \"@box/op\"\nversion = 1\nkind = \"secret-source\"\n\
                      scheme = \"op\"\n\
                      [inputs.op.path]\ntype = \"program\"\nprogram = \"op\"\n\
                      [inputs.op.account]\nvalues = [\"a\"]\n";
        let good = "[\"${{ inputs.op.path }}\", \"read\", \"op://{ref}\"]";
        let program = "`[run] command` element 0 is the program, and a plugin finds it with an \
                       input: write `${{ inputs.<name> }}` for an input in this plugin's \
                       `[inputs]` with `type = \"program\"`";
        let strings = "`[run] command` is a list of strings: the program, then its arguments, \
                       and no element takes a `when`";
        for (run, wanted) in [
            (
                String::new(),
                "a plugin of kind \"secret-source\" needs `[run]` with `command`: the program \
                 that reads a secret, then its arguments",
            ),
            (
                format!("[run]\ncommand = {good}\nhosts = [\"my.1password.com\"]\n"),
                "a plugin's `[run]` holds the unknown key `hosts`; a plugin's `[run]` holds \
                 `command`, `output`",
            ),
            (
                format!("[run]\ncommand = {good}\nwhen = \"macos\"\n"),
                "a plugin's `[run]` holds the unknown key `when`; a plugin's `[run]` holds \
                 `command`, `output`",
            ),
            (
                format!("[run]\ncommand = {good}\nprotocol = \"box.secret-source.v1\"\n"),
                "a plugin's `[run]` holds the unknown key `protocol`; a plugin's `[run]` holds \
                 `command`, `output`",
            ),
            ("[run]\noutput = \"json\"\n".to_string(), strings),
            ("[run]\ncommand = \"op read\"\n".to_string(), strings),
            (
                "[run]\ncommand = [\"${{ inputs.op.path }}\", \
                 { value = \"read\", when = \"macos\" }, \"{ref}\"]\n"
                    .to_string(),
                strings,
            ),
            (
                "[run]\ncommand = [\"${{ inputs.op.path }}\", 1, \"{ref}\"]\n".to_string(),
                strings,
            ),
            (
                "[run]\ncommand = [\"/usr/local/bin/op\", \"read\", \"{ref}\"]\n".to_string(),
                program,
            ),
            (
                "[run]\ncommand = [\"${{ inputs.op.account }}\", \"read\", \"{ref}\"]\n"
                    .to_string(),
                program,
            ),
            (
                "[run]\ncommand = [\"${{ inputs.op.path }}/op\", \"read\", \"{ref}\"]\n"
                    .to_string(),
                program,
            ),
            (
                "[run]\ncommand = [\"${{ inputs.other.path }}\", \"read\", \"{ref}\"]\n"
                    .to_string(),
                program,
            ),
            ("[run]\ncommand = []\n".to_string(), program),
            (
                format!("[run]\ncommand = {good}\noutput = true\n"),
                "`[run] output` is a string, such as \"json\"",
            ),
            (
                format!("[run]\ncommand = {good}\noutput = [\"json\"]\n"),
                "`[run] output` is a string, such as \"json\"",
            ),
        ] {
            shelf.write(&shelf.plugin_file("op"), &format!("{header}{run}"));
            assert_eq!(shelf.refusal("plugins = [\"@box/op\"]"), wanted, "{run}");
        }
        for (key, wanted) in [
            ("run", "`run` is a table"),
            ("env", "`env` is a table"),
            ("protect", "`protect` is a table"),
        ] {
            let rest = if key == "run" {
                String::new()
            } else {
                format!("[run]\ncommand = {good}\n")
            };
            shelf.write(
                &shelf.plugin_file("op"),
                &format!("{key} = 1\n{header}{rest}"),
            );
            assert_eq!(shelf.refusal("plugins = [\"@box/op\"]"), wanted, "{key}");
        }
        for (run, command, output) in [
            (format!("command = {good}\n"), good, None),
            (
                format!("command = {good}\noutput = \"text\"\n"),
                good,
                Some("text"),
            ),
            (
                format!("command = {good}\noutput = \"yaml\"\n"),
                good,
                Some("yaml"),
            ),
            (
                "command = [\"${{ inputs.op.path }}\", \"read\"]\n".to_string(),
                "[\"${{ inputs.op.path }}\", \"read\"]",
                None,
            ),
        ] {
            shelf.write(&shelf.plugin_file("op"), &format!("{header}[run]\n{run}"));
            let merged = shelf
                .merged("plugins = [\"@box/op\"]")
                .unwrap_or_else(|error| panic!("{run:?} loads: {error}"));
            let source = &merged.table["secret-source"]["op"];
            assert_eq!(
                source["command"],
                toml::from_str::<toml::Value>(&format!("command = {command}")).expect("TOML")["command"],
                "the command reaches Box Core as written, which checks its `{{ref}}`: {run}"
            );
            assert_eq!(
                source.get("output").and_then(toml::Value::as_str),
                output,
                "the output reaches Box Core as written, which checks its value: {run}"
            );
        }
    }

    #[test]
    fn a_plugins_env_passes_a_variable_of_the_shell_under_its_own_name() {
        let shelf = Shelf::new();
        let op = source("op");
        let own_name = |key: &str| {
            format!(
                "`[env] {key}` is `{{ from = \"env:{key}\" }}`; a plugin's `[env]` passes a \
                 variable of your shell to the plugin's program under its own name, and sets no \
                 value"
            )
        };
        let repeats = |key: &str| {
            format!(
                "`[env] {key}` needs `from = \"env:{key}\"`; the program gets the variable under \
                 its own name, so `from` repeats the key"
            )
        };
        let holds = |key: &str, other: &str| {
            format!(
                "`[env] {key}` holds `{other}`; an entry of a plugin's `[env]` holds only \
                 `from`, and `[protect] env` names each variable that the box keeps from the \
                 agent"
            )
        };
        let no_name = |key: &str| {
            format!(
                "`[env] {key}` is not the name of a variable: a name is letters, digits, and `_`"
            )
        };
        for (env, wanted) in [
            (
                "[env]\nOP_ACCOUNT = \"my.1password.com\"\n".to_string(),
                own_name("OP_ACCOUNT"),
            ),
            (
                "[env]\nOP_ACCOUNT = true\n".to_string(),
                own_name("OP_ACCOUNT"),
            ),
            (
                "[env]\nOP_ACCOUNT = { value = \"my.1password.com\" }\n".to_string(),
                holds("OP_ACCOUNT", "value"),
            ),
            (
                "[env]\nOP_ACCOUNT = { from = \"env:OP_ACCOUNT\", when = \"macos\" }\n".to_string(),
                holds("OP_ACCOUNT", "when"),
            ),
            (
                "[env]\nOP_ACCOUNT = { from = \"env:OP_ACCOUNT\", default = \"my\" }\n".to_string(),
                holds("OP_ACCOUNT", "default"),
            ),
            (
                "[env]\nOP_TOKEN = { from = \"env:OP_TOKEN\", secret = true }\n".to_string(),
                holds("OP_TOKEN", "secret"),
            ),
            (
                "[env]\nACCOUNT = { from = \"env:OP_ACCOUNT\" }\n".to_string(),
                repeats("ACCOUNT"),
            ),
            (
                "[env]\nOP_ACCOUNT = {}\n".to_string(),
                repeats("OP_ACCOUNT"),
            ),
            (
                "[env]\nOP_ACCOUNT = { from = \"OP_ACCOUNT\" }\n".to_string(),
                repeats("OP_ACCOUNT"),
            ),
            (
                "[env]\nOP_ACCOUNT = { from = 1 }\n".to_string(),
                repeats("OP_ACCOUNT"),
            ),
            (
                "[env]\n\"OP_SESSION_*\" = { from = \"env:OP_SESSION_*\" }\n".to_string(),
                no_name("OP_SESSION_*"),
            ),
            (
                "[env]\n\"OP_*_TOKEN\" = { from = \"env:OP_*_TOKEN\" }\n".to_string(),
                no_name("OP_*_TOKEN"),
            ),
            (
                "[env]\n\"OP-ACCOUNT\" = { from = \"env:OP-ACCOUNT\" }\n".to_string(),
                no_name("OP-ACCOUNT"),
            ),
            (
                "[env]\n\"1OP\" = { from = \"env:1OP\" }\n".to_string(),
                no_name("1OP"),
            ),
            (
                "[env]\n\"OP=x\" = { from = \"env:OP=x\" }\n".to_string(),
                no_name("OP=x"),
            ),
            (
                "[env]\n\"\" = { from = \"env:\" }\n".to_string(),
                no_name(""),
            ),
            (
                "[env]\n\"*\" = { from = \"env:*\" }\n".to_string(),
                no_name("*"),
            ),
        ] {
            shelf.plugin("op", &format!("{op}{env}"));
            assert_eq!(shelf.refusal("plugins = [\"@box/op\"]"), wanted, "{env}");
        }
        shelf.plugin(
            "op",
            &format!(
                "{op}[env]\nHOME = {{ from = \"env:HOME\" }}\n\
                 PATH_INFO = {{ from = \"env:PATH_INFO\" }}\n\
                 _op = {{ from = \"env:_op\" }}\n\
                 [protect]\nenv = [\"_op\"]\n"
            ),
        );
        let merged = shelf
            .merged("plugins = [\"@box/op\"]")
            .expect("Box Core, not `box`, refuses a name that has no effect, such as `HOME`");
        assert_eq!(
            merged.table["secret-source"]["op"]["pass-env"],
            toml::Value::from(vec!["HOME", "PATH_INFO"])
        );
        assert_eq!(
            merged.table["secret-source"]["op"]["pass-secret-env"],
            toml::Value::from(vec!["_op"])
        );
    }

    #[test]
    fn a_plugins_protect_names_what_the_box_keeps_from_the_agent() {
        let shelf = Shelf::new();
        let op = source("op");
        let token = "[env]\nOP_TOKEN = { from = \"env:OP_TOKEN\" }\n";
        let unknown = |key: &str, hint: &str| {
            format!("a plugin's `[protect]` holds the unknown key `{key}`; {hint}")
        };
        let not_passed = |name: &str| {
            format!(
                "`[protect] env` names `{name}`, which this plugin's `[env]` does not hold; the \
                 box keeps from the agent only a variable that the plugin's program gets, so \
                 add `{name} = {{ from = \"env:{name}\" }}` to `[env]`"
            )
        };
        let placeholder = |entry: &str| {
            format!(
                "`[protect] paths[0]` = {entry:?} holds a placeholder that a path of a plugin \
                 does not take; write `${{{{ home }}}}/...`, `~/...`, or a full path"
            )
        };
        let table = |index: usize| {
            format!(
                "`[protect] paths[{index}]` is a table; a path of a plugin is a string, and it \
                 takes no `when` or `optional`"
            )
        };
        for (protect, wanted) in [
            (
                "[protect]\nread = [\"~/.config/op\"]\n".to_string(),
                unknown("read", "a plugin's `[protect]` holds `env`, `paths`"),
            ),
            (
                "[protect]\ndeny = [\"~/.config/op\"]\n".to_string(),
                unknown("deny", "a plugin's `[protect]` holds `env`, `paths`"),
            ),
            (
                "[protect]\npath = [\"~/.config/op\"]\n".to_string(),
                unknown("path", "did you mean `paths`?"),
            ),
            (
                format!("{token}[protect]\nenv = \"OP_TOKEN\"\n"),
                "`[protect] env` is a list of the names of variables".to_string(),
            ),
            (
                format!("{token}[protect]\nenv = {{ OP_TOKEN = true }}\n"),
                "`[protect] env` is a list of the names of variables".to_string(),
            ),
            (
                format!("{token}[protect]\nenv = [\"OP_TOKEN\", 1]\n"),
                "`[protect] env[1]` is the name of a variable, as a string".to_string(),
            ),
            (
                format!("{token}[protect]\nenv = [\"OP_TOKEN\", \"OP_OTHER\"]\n"),
                not_passed("OP_OTHER"),
            ),
            (
                "[protect]\nenv = [\"OP_TOKEN\"]\n".to_string(),
                not_passed("OP_TOKEN"),
            ),
            (
                format!("{token}[protect]\nenv = [\"OP_*\"]\n"),
                not_passed("OP_*"),
            ),
            (
                format!("{token}[protect]\nenv = [\"op_token\"]\n"),
                not_passed("op_token"),
            ),
            (
                "[protect]\npaths = \"~/.config/op\"\n".to_string(),
                "`[protect] paths` is a list of paths".to_string(),
            ),
            (
                "[protect]\npaths = { path = \"~/.config/op\" }\n".to_string(),
                "`[protect] paths` is a list of paths".to_string(),
            ),
            (
                "[protect]\npaths = [{ path = \"~/.config/op\", when = \"macos\" }]\n".to_string(),
                table(0),
            ),
            (
                "[protect]\npaths = [\"~/.op\", { path = \"/var/run/x\", optional = true }]\n"
                    .to_string(),
                table(1),
            ),
            (
                "[protect]\npaths = [1]\n".to_string(),
                "`[protect] paths[0]` is a path, as a string".to_string(),
            ),
            (
                "[protect]\npaths = [\"${{ workspace }}/.op\"]\n".to_string(),
                placeholder("${{ workspace }}/.op"),
            ),
            (
                "[protect]\npaths = [\"${{ inputs.op.path }}\"]\n".to_string(),
                placeholder("${{ inputs.op.path }}"),
            ),
            (
                "[protect]\npaths = [\"/opt/${{ home }}/op\"]\n".to_string(),
                placeholder("/opt/${{ home }}/op"),
            ),
            (
                "[protect]\npaths = [\"${{ home }}/${{ home }}\"]\n".to_string(),
                placeholder("${{ home }}/${{ home }}"),
            ),
            (
                "[protect]\npaths = [\"${{ home\"]\n".to_string(),
                placeholder("${{ home"),
            ),
            (
                "[protect]\npaths = [\"$${{ home }}/.op\"]\n".to_string(),
                placeholder("$${{ home }}/.op"),
            ),
        ] {
            shelf.plugin("op", &format!("{op}{protect}"));
            assert_eq!(
                shelf.refusal("plugins = [\"@box/op\"]"),
                wanted,
                "{protect}"
            );
        }
        shelf.plugin(
            "op",
            &format!("{op}{token}[protect]\nenv = [\n  \"OP_TOKEN\",\n  \"OP_OTHER\",\n]\n"),
        );
        match shelf.merged("plugins = [\"@box/op\"]") {
            Err(Error::Profile { path, line, .. }) => assert_eq!(
                (path, line),
                (shelf.plugin_file("op"), Some(14)),
                "the refusal names the line of `[protect] env` in the plugin's file"
            ),
            other => panic!("a refusal at a line, not {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn a_plugin_reaches_the_merge_as_the_table_that_box_core_reads() {
        let shelf = Shelf::new();
        shelf.plugin(
            "op",
            "scheme = \"op\"\n\
             [inputs.op.path]\ntype = \"program\"\nprogram = \"op\"\n\
             [run]\ncommand = [\"${{ inputs.op.path }}\", \"read\", \"op://{ref}\"]\n\
             output = \"json\"\n\
             [env]\n\
             OP_CONNECT_HOST = { from = \"env:OP_CONNECT_HOST\" }\n\
             OP_SERVICE_ACCOUNT_TOKEN = { from = \"env:OP_SERVICE_ACCOUNT_TOKEN\" }\n\
             OP_ACCOUNT = { from = \"env:OP_ACCOUNT\" }\n\
             OP_CONNECT_TOKEN = { from = \"env:OP_CONNECT_TOKEN\" }\n\
             [protect]\n\
             env = [\"OP_CONNECT_TOKEN\", \"OP_SERVICE_ACCOUNT_TOKEN\", \"OP_CONNECT_TOKEN\"]\n\
             paths = [\"${{ home }}/.config/op\", \"~/.op\", \"/etc/op\", \
             \"${{ home }}/Library/Group Containers/2BUA8C4S2C.com.1password\", \
             \"${{ home }}\", \"~\", \"${{ home }}/.op/*\", \".op/../x\"]\n",
        );
        let layers = shelf.layers("plugins = [\"@box/op\"]").expect("a chain");
        let wanted: toml::Table = toml::from_str(
            "[plugin]\nname = \"@box/op\"\nversion = 1\nkind = \"secret-source\"\nscheme = \"op\"\n\
             [inputs.op.path]\ntype = \"program\"\nprogram = \"op\"\n\
             [secret-source.op]\n\
             protocol = \"box.secret-source.v1\"\n\
             command = [\"${{ inputs.op.path }}\", \"read\", \"op://{ref}\"]\n\
             output = \"json\"\n\
             pass-env = [\"OP_CONNECT_HOST\", \"OP_ACCOUNT\"]\n\
             pass-secret-env = [\"OP_SERVICE_ACCOUNT_TOKEN\", \"OP_CONNECT_TOKEN\"]\n\
             deny = [\"~/.config/op\", \"~/.op\", \"/etc/op\", \
             \"~/Library/Group Containers/2BUA8C4S2C.com.1password\", \"~\", \"~\", \
             \"~/.op/*\", \".op/../x\"]\n",
        )
        .expect("TOML");
        assert_eq!(
            layers[0].table, wanted,
            "the layer holds Box Core's table, each pass list in the order of `[env]`, each path \
             of `[protect] paths` in `deny` as written, which Box Core checks, and no `run`, \
             `env`, `protect`, or `filesystem`, which the merge reads as the agent's or refuses"
        );
        let merged = merge(&layers).expect("a merge");
        assert_eq!(
            merged.table.keys().collect::<Vec<_>>(),
            ["secret-source"],
            "nothing of the plugin reaches the agent"
        );
        assert_eq!(merged.table["secret-source"], wanted["secret-source"]);
        shelf.plugin("op", &source("op"));
        let layers = shelf.layers("plugins = [\"@box/op\"]").expect("a chain");
        assert_eq!(
            layers[0].table["secret-source"],
            toml::from_str::<toml::Value>(
                "[op]\nprotocol = \"box.secret-source.v1\"\n\
                 command = [\"${{ inputs.op.path }}\", \"read\", \"op://{ref}\"]\n"
            )
            .expect("TOML"),
            "a plugin with no `[env]` and no `[protect]` writes no empty list"
        );
        shelf.plugin(
            "op",
            &format!("{}[env]\n[protect]\nenv = []\npaths = []\n", source("op")),
        );
        let layers = shelf.layers("plugins = [\"@box/op\"]").expect("a chain");
        assert_eq!(
            layers[0].table["secret-source"]["op"]
                .as_table()
                .expect("a table")
                .keys()
                .collect::<Vec<_>>(),
            ["command", "protocol"],
            "an empty `[env]` and an empty `[protect]` write no empty list"
        );
    }

    #[test]
    fn a_message_names_a_plugins_source_by_its_plugin_and_the_keys_of_its_file() {
        let owners = BTreeMap::from([
            ("op".to_string(), "@box/1password".to_string()),
            ("vault".to_string(), lang::THE_PROFILE.to_string()),
        ]);
        for (reason, wanted) in [
            (
                "`secret-source.op.command.0`: `inputs.onepassword.path` = \"/w/op\" lies in the \
                 workspace",
                "`run.command.0` of the plugin @box/1password: `inputs.onepassword.path` = \
                 \"/w/op\" lies in the workspace",
            ),
            (
                "`secret-source.op.output` and `secret-source.op.pass-secret-env.1`",
                "`run.output` of the plugin @box/1password and `env` of the plugin @box/1password",
            ),
            (
                "`secret-source.op.deny.2`, `secret-source.op.deny`, `secret-source.op.pass-env`",
                "`protect.paths.2` of the plugin @box/1password, `protect.paths` of the plugin \
                 @box/1password, `env` of the plugin @box/1password",
            ),
            (
                "`secret-source.vault.command.0`: a source of the profile keeps its table",
                "`secret-source.vault.command.0`: a source of the profile keeps its table",
            ),
            (
                "`secret-source.other.command.0` and `agent.command.0` name no plugin",
                "`secret-source.other.command.0` and `agent.command.0` name no plugin",
            ),
        ] {
            assert_eq!(shown(reason.to_string(), &owners), wanted);
        }
        let dotted = "`secret-source.a.b.command.0`: no `vault` that the box can run";
        for (owner, wanted) in [
            (lang::THE_PROFILE, dotted),
            (
                "team-ab",
                "`run.command.0` of the plugin team-ab: no `vault` that the box can run",
            ),
        ] {
            let owners = BTreeMap::from([
                ("a".to_string(), "team-a".to_string()),
                ("a.b".to_string(), owner.to_string()),
            ]);
            assert_eq!(
                shown(dotted.to_string(), &owners),
                wanted,
                "the scheme `a` does not take a key of the scheme `a.b`"
            );
        }
        assert_eq!(
            source_name("op", "@box/1password"),
            "the plugin @box/1password"
        );
        assert_eq!(
            source_name("vault", lang::THE_PROFILE),
            "`[secret-source.vault]` of the profile"
        );
        assert_eq!(
            command_name("op", owners.get("op")),
            "[run] command of the plugin @box/1password"
        );
        assert_eq!(
            command_name("vault", owners.get("vault")),
            "[secret-source.vault] command"
        );
        assert_eq!(command_name("vault", None), "[secret-source.vault] command");
    }

    #[test]
    fn a_reason_names_the_command_of_one_source() {
        let plugin = "`run.command.0` of the plugin @box/1password: no `op` that the box can run";
        let own = "`secret-source.vault.command.0`: no `vault` that the box can run";
        assert!(names_command(plugin, "op", Some("@box/1password")));
        assert!(!names_command(plugin, "op", Some("@box/1pass")));
        assert!(!names_command(
            plugin,
            "op",
            Some("@box/aws-secrets-manager")
        ));
        assert!(!names_command(plugin, "op", None));
        assert!(names_command(own, "vault", None));
        assert!(!names_command(own, "vault", Some("@box/1password")));
        assert!(!names_command(own, "op", None));
        assert!(!names_command(
            "`run.output` of the plugin @box/1password: not a command",
            "op",
            Some("@box/1password")
        ));
        assert!(!names_command(
            "`secret-source.vault.reads.0` is literal and holds no placeholder",
            "vault",
            None
        ));
    }

    #[test]
    fn a_plugins_inputs_belong_to_the_plugin() {
        let shelf = Shelf::new();
        shelf.plugin("op", &source("op"));
        for (name, body) in [
            (
                "s",
                "[inputs.op.path]\ntype = \"program\"\nfrom = \"env:PICK\"\n",
            ),
            (
                "op",
                "[inputs.op.path]\ntype = \"program\"\nfrom = \"env:PICK\"\n",
            ),
            (
                "t",
                lang::test_tool_pack("t", "[inputs.op.path]\ntype = \"program\"\n").as_str(),
            ),
        ] {
            shelf.pack(name, body);
            assert_eq!(
                shelf.refusal(&format!(
                    "packs = [\"@box/{name}\"]\nplugins = [\"@box/op\"]"
                )),
                format!(
                    "@box/{name} declares `inputs.op.path`, an input of the plugin @box/op; only the \
                     plugin declares its inputs, so a pack cannot choose the program that a \
                     plugin runs or what it passes to it, and the profile sets the input in \
                     `[options]`"
                ),
                "{body}"
            );
        }
        shelf.pack("reads", "[agent.env]\nOP = \"${{ inputs.op.path }}\"\n");
        shelf
            .merged("packs = [\"@box/reads\"]\nplugins = [\"@box/op\"]")
            .expect("a pack can read a plugin's input");
        shelf.pack("mode", "[inputs.team.mode]\nvalues = [\"a\"]\n");
        shelf.plugin(
            "op",
            &source("op").replace("\"read\",", "\"${{ inputs.team.mode }}\", \"read\","),
        );
        assert_eq!(
            shelf.refusal("packs = [\"@box/mode\"]\nplugins = [\"@box/op\"]"),
            "`[run] command` reads `inputs.team.mode`, which this plugin does not declare; a \
             plugin reads only its own inputs"
        );
    }

    #[test]
    fn a_plugins_inputs_read_only_the_inputs_of_the_plugin() {
        let shelf = Shelf::new();
        shelf.pack("helper", "[inputs.tools.bin]\ndefault = \"/tmp/evil\"\n");
        let source = "[run]\n\
                      command = [\"${{ inputs.vault.path }}\", \"read\", \"{ref}\"]\n";
        for (inputs, field) in [
            (
                "[inputs.vault.path]\ntype = \"program\"\nprogram = \"vault\"\n\
                 search = [\"${{ inputs.tools.bin }}\"]\n",
                "search",
            ),
            (
                "[inputs.vault.path]\ntype = \"program\"\nprogram = \"vault\"\n\
                 default = \"${{ inputs.tools.bin }}/vault\"\n",
                "default",
            ),
        ] {
            shelf.plugin("vault", &format!("scheme = \"vault\"\n{inputs}{source}"));
            assert_eq!(
                shelf.refusal("packs = [\"@box/helper\"]\nplugins = [\"@box/vault\"]"),
                "`[inputs]` reads `inputs.tools.bin`, which this plugin does not declare; a \
                 plugin's inputs read only the inputs of the plugin, so no pack chooses the \
                 program that it runs",
                "{field}"
            );
        }
        for (inputs, name) in [
            ("search = [\"${{ root }}\"]", "root"),
            ("default = \"${{ root.parent }}/vault\"", "root.parent"),
            ("search = [\"${{ tool.node.root }}\"]", "tool.node.root"),
        ] {
            shelf.plugin(
                "vault",
                &format!(
                    "scheme = \"vault\"\n[inputs.vault.path]\ntype = \"program\"\n\
                     program = \"vault\"\n{inputs}\n{source}"
                ),
            );
            assert_eq!(
                shelf.refusal("plugins = [\"@box/vault\"]"),
                format!(
                    "`[inputs]` reads `{name}`, the folder of a program that a pack finds; a \
                     plugin's inputs read no such folder, so no pack chooses the program that it \
                     runs"
                ),
                "{inputs}"
            );
        }
        shelf.plugin(
            "vault",
            &format!(
                "scheme = \"vault\"\n[inputs.vault.dir]\ndefault = \"/opt/vault\"\n\
                 [inputs.vault.path]\ntype = \"program\"\nprogram = \"vault\"\n\
                 search = [\"${{{{ inputs.vault.dir }}}}/bin\", \"${{{{ home }}}}/bin\"]\n{source}"
            ),
        );
        shelf
            .merged("packs = [\"@box/helper\"]\nplugins = [\"@box/vault\"]")
            .expect("a plugin's input reads its own input and a built-in name");
    }

    #[test]
    fn an_input_of_a_plugin_belongs_to_that_plugin() {
        let shelf = Shelf::new();
        shelf.plugin("op", &source("op"));
        shelf.plugin(
            "opc",
            &source("op").replace("scheme = \"op\"", "scheme = \"opc\""),
        );
        let wanted = |plugin: &str, owner: &str| {
            format!(
                "the plugin {plugin} declares `inputs.op.path`, an input of the plugin {owner}; \
                 an input belongs to one plugin, so a plugin cannot choose the program that \
                 another plugin runs or what it passes to it; give each plugin inputs of its own"
            )
        };
        assert_eq!(
            shelf.refusal("plugins = [\"@box/op\", \"@box/opc\"]"),
            wanted("@box/opc", "@box/op")
        );
        assert_eq!(
            shelf.refusal("plugins = [\"@box/opc\", \"@box/op\"]"),
            wanted("@box/op", "@box/opc")
        );
        shelf
            .merged("plugins = [\"@box/op\", \"@box/op\"]")
            .expect("a plugin that the profile lists twice loads once");
    }

    #[test]
    fn a_source_of_the_profile_reads_no_input() {
        let shelf = Shelf::new();
        shelf.plugin("op", &source("op"));
        shelf.pack(
            "team",
            "[inputs.team.vault]\nvalues = [\"/usr/local/bin/vault\"]\n",
        );
        for (command, input) in [
            (
                "[\"${{ inputs.op.path }}\", \"read\", \"op://{ref}\"]",
                "inputs.op.path",
            ),
            (
                "[\"${{ inputs.team.vault }}\", \"kv\", \"get\", \"{ref}\"]",
                "inputs.team.vault",
            ),
            (
                "[\"/usr/local/bin/vault\", \"-address=${{ inputs.team.vault }}\", \"{ref}\"]",
                "inputs.team.vault",
            ),
        ] {
            assert_eq!(
                shelf.refusal(&format!(
                    "packs = [\"@box/team\"]\nplugins = [\"@box/op\"]\n\
                     [secret-source.vault]\ncommand = {command}\n"
                )),
                format!(
                    "`[secret-source.vault]` reads `{input}`, an input of a pack or a plugin; a \
                     source in the profile reads no input, so no pack or plugin chooses the \
                     program that it runs or what it passes to it: write each value of \
                     `command` in the profile"
                ),
                "{command}"
            );
        }
        for (command, name) in [
            (
                "[\"${{ tool.vault.root }}/vault\", \"{ref}\"]",
                "tool.vault.root",
            ),
            (
                "[\"${{ tool.vault.root.parent }}/vault\", \"{ref}\"]",
                "tool.vault.root.parent",
            ),
            (
                "[\"/usr/local/bin/vault\", \"${{ tool.node.root }}/read.js\", \"{ref}\"]",
                "tool.node.root",
            ),
        ] {
            assert_eq!(
                shelf.refusal(&format!(
                    "packs = [\"@box/team\"]\n[secret-source.vault]\ncommand = {command}\n"
                )),
                format!(
                    "`[secret-source.vault]` reads `{name}`, the folder of a program that a pack \
                     finds; a source reads no such folder, so no pack chooses the program that it \
                     runs or what it passes to it"
                ),
                "{command}"
            );
        }
        shelf.plugin(
            "node-vault",
            "scheme = \"nv\"\n\
             [inputs.node-vault.path]\ntype = \"program\"\nprogram = \"vault\"\n\
             [run]\ncommand = \
             [\"${{ inputs.node-vault.path }}\", \"${{ tool.node.root }}/read.js\", \"{ref}\"]\n",
        );
        assert_eq!(
            shelf.refusal("plugins = [\"@box/node-vault\"]"),
            "`[run] command` reads `tool.node.root`, the folder of a program that a pack finds; a \
             plugin reads no such folder, so no pack chooses the program that it runs or what it \
             passes to it"
        );
        for name in ["root", "root.parent"] {
            shelf.plugin(
                "root-vault",
                &format!(
                    "scheme = \"rv\"\n\
                     [inputs.root-vault.path]\ntype = \"program\"\nprogram = \"vault\"\n\
                     [run]\ncommand = \
                     [\"${{{{ inputs.root-vault.path }}}}\", \"${{{{ {name} }}}}/read.js\", \"{{ref}}\"]\n"
                ),
            );
            assert_eq!(
                shelf.refusal("plugins = [\"@box/root-vault\"]"),
                format!(
                    "`[run] command` reads `{name}`, the folder of a program that a pack finds; \
                     a plugin reads no such folder, so no pack chooses the program that it runs \
                     or what it passes to it"
                ),
                "{name}"
            );
        }
        shelf
            .merged(
                "packs = [\"@box/team\"]\n[secret-source.vault]\n\
                 command = [\"${{ home }}/bin/vault\", \"{ref}\"]\n",
            )
            .expect("a source of the profile reads a built-in name");
    }

    #[test]
    fn only_a_plugin_or_the_profile_declares_a_secret_source() {
        let shelf = Shelf::new();
        let declared = "[secret-source.op]\ncommand = [\"/usr/local/bin/op\"]\n";
        for (name, body) in [
            ("s", declared.to_string()),
            ("a", format!("[run]\ncommand = [\"/bin/a\"]\n{declared}")),
            ("t", lang::test_tool_pack("t", declared)),
        ] {
            shelf.pack(name, &body);
            assert_eq!(
                shelf.refusal(&format!("packs = [\"@box/{name}\"]")),
                format!(
                    "@box/{name} is a pack, and a pack declares no secret source; a plugin \
                     declares one, and a profile lists the plugin in `plugins`"
                ),
                "{body}"
            );
        }
        let merged = shelf
            .merged(&format!("[agent]\ncommand = [\"/bin/a\"]\n{declared}"))
            .expect("a profile declares a source itself");
        assert_eq!(
            merged.table["secret-source"],
            toml::from_str::<toml::Value>("[op]\ncommand = [\"/usr/local/bin/op\"]").expect("TOML")
        );
        assert_eq!(
            shelf.refusal(&format!("{declared}when = \"linux\"\n")),
            "`[secret-source.op]` holds `when` at `when`; a secret source takes no `when`, so a \
             profile declares the same schemes on every host"
        );
    }

    #[test]
    fn one_scheme_has_one_declaration() {
        let shelf = Shelf::new();
        shelf.plugin("op", &source("op"));
        shelf.plugin(
            "op-connect",
            &source("op")
                .replace("[inputs.op.path]", "[inputs.connect.path]")
                .replace("inputs.op.path }}", "inputs.connect.path }}"),
        );
        assert_eq!(
            shelf.refusal("plugins = [\"@box/op\", \"@box/op-connect\"]"),
            "the scheme `op` has two secret sources, the plugin @box/op and the plugin \
             @box/op-connect, and one scheme has one source; keep one of them"
        );
        assert_eq!(
            shelf.refusal(
                "plugins = [\"@box/op\"]\n[secret-source.op]\ncommand = [\"/usr/local/bin/op\"]"
            ),
            "the scheme `op` has two secret sources, the plugin @box/op and \
             `[secret-source.op]` of the profile, and one scheme has one source; keep one of them"
        );
    }

    #[test]
    fn only_the_profile_names_a_reference_in_a_declared_scheme() {
        let shelf = Shelf::new();
        shelf.plugin("op", &source("op"));
        let wanted = |key: &str, reference: &str| {
            format!(
                "@box/p writes `{key} = {reference:?}`, a reference in `op://`, which @box/op \
                 declares; only the profile names a reference that a secret source reads, so a \
                 pack cannot choose which secret the box reads"
            )
        };
        for (body, key) in [
            (
                "[egress.github]\ndestinations = [\"api.github.com\"]\n\
                 secret.ref = \"op://Private/GitHub/token\"\nsecret.env = \"GH_TOKEN\"",
                "[egress.github] secret.ref",
            ),
            (
                "[egress.github]\ndestinations = [\"api.github.com\"]\n\
                 secret = { ref = { value = \"op://Private/GitHub/token\", when = \"macos\" } }",
                "[egress.github] secret.ref",
            ),
            (
                "[egress.github]\ndestinations = [\"api.github.com\"]\n\
                 secret = \"op://Private/GitHub/token\"",
                "[egress.github] secret",
            ),
            (
                "[egress.github]\ndestinations = [\"api.github.com\"]\n\
                 [[egress.github.backends]]\ndestination = \"gateway.example.com\"\n\
                 auth.ref = \"op://Private/GitHub/token\"",
                "[egress.github] backends.auth.ref",
            ),
            (
                "[telemetry.otlp]\nkind = \"otlp\"\ndestination = \"https://otel.example.com\"\n\
                 secret.ref = \"op://Private/GitHub/token\"\nsecret.header = \"x-api-key\"",
                "[telemetry.otlp] secret.ref",
            ),
        ] {
            shelf.pack("p", body);
            assert_eq!(
                shelf.refusal("packs = [\"@box/p\"]\nplugins = [\"@box/op\"]"),
                wanted(key, "op://Private/GitHub/token"),
                "{body}"
            );
            shelf
                .merged("packs = [\"@box/p\"]")
                .expect("a scheme that no plugin declares is Box Core's to judge");
        }
        for (body, key, reference) in [
            (
                "[telemetry.otlp]\nkind = \"otlp\"\ndestination = \"https://otel.example.com\"\n\
                 secret.ref = \" op://Private/GitHub/token\"\nsecret.header = \"x-api-key\"",
                "[telemetry.otlp] secret.ref",
                " op://Private/GitHub/token",
            ),
            (
                "[egress.github]\ndestinations = [\"api.github.com\"]\n\
                 secret.ref = \"\\top://Private/GitHub/token \"\nsecret.env = \"GH_TOKEN\"",
                "[egress.github] secret.ref",
                "\top://Private/GitHub/token ",
            ),
        ] {
            shelf.pack("p", body);
            assert_eq!(
                shelf.refusal("packs = [\"@box/p\"]\nplugins = [\"@box/op\"]"),
                wanted(key, reference),
                "white space around a reference does not hide its scheme: {body}"
            );
        }
        shelf.pack(
            "p",
            "[inputs.p.scheme]\ndefault = \"op\"\n\
             [egress.github]\ndestinations = [\"api.github.com\"]\n\
             secret.ref = \"${{ inputs.p.scheme }}://Private/GitHub/token\"\nsecret.env = \"GH_TOKEN\"",
        );
        let reason = shelf.resolve_refusal("packs = [\"@box/p\"]\nplugins = [\"@box/op\"]");
        assert!(
            reason.starts_with("`egress.github.secret.ref` is literal and holds no placeholder;"),
            "a pack that builds a reference from a placeholder is refused when the profile \
             resolves: {reason}"
        );
        shelf.pack("p", "[mcp.docs]\nsecret.ref = \"op://Private/Docs/key\"");
        let reason = shelf.refusal("packs = [\"@box/p\"]\nplugins = [\"@box/op\"]");
        assert!(
            reason.starts_with("a pack declares no MCP server") && !reason.contains("op://"),
            "a pack's MCP table refuses a secret before the reference check reads it: {reason}"
        );
        let mcp: toml::Table =
            toml::from_str("[mcp.docs]\ntype = \"http\"\nsecret.ref = \"op://Private/Docs/key\"")
                .expect("TOML");
        let declared = BTreeMap::from([("op".to_string(), "@box/op".to_string())]);
        assert_eq!(
            refuse_pack_references("@box/p", &mcp, &declared)
                .expect_err("an MCP server's reference")
                .reason,
            "@box/p writes `[mcp.docs] secret.ref = \"op://Private/Docs/key\"`, a reference in \
             `op://`, which @box/op declares; only the profile names a reference that a secret \
             source reads, so a pack cannot choose which secret the box reads"
        );
        shelf.pack(
            "p",
            "[egress.model]\ndestinations = [\"model.example.com\"]\nsecret.ref = \"env://KEY\"",
        );
        let merged = shelf
            .merged(
                "packs = [\"@box/p\"]\nplugins = [\"@box/op\"]\n\
                 [egress.model.secret]\nref = \"op://Private/Model/key\"\nenv = \"KEY\"",
            )
            .expect("the profile names a reference over a pack's route");
        assert_eq!(
            merged.table["egress"]["model"],
            toml::from_str::<toml::Value>(
                "destinations = [\"model.example.com\"]\n\
                 secret = { ref = \"op://Private/Model/key\", env = \"KEY\" }"
            )
            .expect("TOML")
        );
    }
}
