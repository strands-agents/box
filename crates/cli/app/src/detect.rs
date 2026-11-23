//! The host values a starter reads once, when it creates a profile.

use std::fmt;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::host::{Host, tilde};
use crate::mcp::Format;
use crate::storage_edit::shown;
use crate::storage_files::Refusals;

/// One `[[source]]` of a starter: a host value the agent reads, with its places highest first.
#[derive(Debug, Clone)]
pub(crate) struct Source {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) input: Option<String>,
    pub(crate) pack: Option<String>,
    pub(crate) equals: Vec<String>,
    pub(crate) places: Vec<Place>,
}

/// One place a source reads, on the OS that its `when` names.
#[derive(Debug, Clone)]
pub(crate) struct Place {
    pub(crate) at: At,
    pub(crate) when: Option<String>,
}

/// What a place reads.
#[derive(Debug, Clone)]
pub(crate) enum At {
    File {
        file: String,
        directory_env: Option<String>,
        kind: Format,
        key: Vec<String>,
    },
    Env(String),
}

/// A choice's `detect`: the choice holds when the source gives one of `equals`.
#[derive(Debug, Clone)]
pub(crate) struct Detect {
    pub(crate) source: String,
    pub(crate) equals: Vec<String>,
}

/// What one source gave: the value and the place it came from, and each place it skipped.
#[derive(Debug, Clone, Default)]
pub(crate) struct Reading {
    pub(crate) value: Option<(String, String)>,
    pub(crate) skipped: Vec<String>,
}

/// One line of the `Detected` block: the source's label, the answer it made, and its place or
/// why it made none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    pub(crate) label: String,
    pub(crate) answer: Option<String>,
    pub(crate) text: String,
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.answer {
            Some(answer) => write!(f, "{} | {answer} | {}", self.label, self.text),
            None => write!(f, "{} | {}", self.label, self.text),
        }
    }
}

/// The `[[source]]` tables of a `starter.toml`.
pub(crate) fn parse_sources(
    value: Option<&toml::Value>,
    lookup: &crate::lang::Lookup,
) -> Result<Vec<Source>, String> {
    let items = match value {
        None => return Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items,
        Some(_) => return Err("`[[source]]` is not a list of tables".to_string()),
    };
    let mut sources: Vec<Source> = Vec::new();
    for item in items {
        let table = item
            .as_table()
            .ok_or("`[[source]]` is not a list of tables")?;
        known(
            table,
            "[[source]]",
            &["id", "label", "input", "pack", "equals", "places"],
        )?;
        let id = string(table, "id", "[[source]]")?;
        if sources.iter().any(|source| source.id == id) {
            return Err(format!("two sources have the id {id:?}"));
        }
        let owner = format!("source {id:?}");
        let label = match table.get("label") {
            None => id.clone(),
            Some(_) => string(table, "label", &owner)?,
        };
        let input = match table.get("input") {
            None => None,
            Some(_) => Some(string(table, "input", &owner)?),
        };
        let pack = match table.get("pack") {
            None => None,
            Some(_) if input.is_none() => return Err(format!("{owner} has `pack` but no `input`")),
            Some(_) => {
                let pack = lookup
                    .full_name(&string(table, "pack", &owner)?)
                    .map_err(|reason| format!("{owner}: {reason}"))?;
                lookup
                    .table(&pack)
                    .map_err(|reason| format!("{owner}: {reason}"))?;
                Some(pack)
            }
        };
        let equals = match table.get("equals") {
            None => Vec::new(),
            Some(value) => equals(value, &owner)?,
        };
        if input.is_none() && !equals.is_empty() {
            return Err(format!(
                "{owner} has `equals` but no `input`; a choice's `detect` holds its own `equals`"
            ));
        }
        let places = match table.get("places") {
            Some(toml::Value::Array(places)) if !places.is_empty() => places
                .iter()
                .map(|place| parse_place(place, &owner))
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(format!("{owner} has no `places` list")),
        };
        sources.push(Source {
            id,
            label,
            input,
            pack,
            equals,
            places,
        });
    }
    Ok(sources)
}

fn parse_place(value: &toml::Value, owner: &str) -> Result<Place, String> {
    let at = format!("a place of {owner}");
    let table = value
        .as_table()
        .ok_or_else(|| format!("{at} is not a table"))?;
    known(
        table,
        "place",
        &["file", "directory-env", "kind", "key", "env", "when"],
    )?;
    let when = match table.get("when") {
        None => None,
        Some(toml::Value::String(os)) if matches!(os.as_str(), "macos" | "linux") => {
            Some(os.clone())
        }
        Some(_) => return Err(format!("the `when` of {at} is not `macos` or `linux`")),
    };
    let place = match (table.get("file"), table.get("env")) {
        (Some(_), Some(_)) => return Err(format!("{at} has both `file` and `env`")),
        (None, None) => return Err(format!("{at} has no `file` or `env`")),
        (None, Some(_)) => {
            if let Some(key) = ["kind", "key", "directory-env"]
                .iter()
                .find(|key| table.contains_key(**key))
            {
                return Err(format!("{at} reads `env`, so it has no `{key}`"));
            }
            At::Env(string(table, "env", &at)?)
        }
        (Some(_), None) => {
            let file = string(table, "file", &at)?;
            if file.contains("${{") {
                return Err(format!("the `file` of {at} holds a placeholder"));
            }
            if !file.starts_with("~/") && !Path::new(&file).is_absolute() {
                return Err(format!(
                    "the `file` of {at}, {file:?}, is not absolute and does not start with `~/`"
                ));
            }
            let kind = string(table, "kind", &at)?;
            let kind = Format::named(&kind)
                .ok_or_else(|| format!("the `kind` of {at} is {kind:?}; it is json or toml"))?;
            let key = match table.get("key") {
                Some(toml::Value::Array(items)) if !items.is_empty() => items
                    .iter()
                    .map(|item| item.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| format!("the `key` of {at} is not a list of strings"))?,
                _ => return Err(format!("{at} has no `key` list")),
            };
            let directory_env = table
                .get("directory-env")
                .map(|_| string(table, "directory-env", &at))
                .transpose()?;
            if directory_env.is_some()
                && Path::new(file.strip_prefix("~/").unwrap_or(&file))
                    .file_name()
                    .is_none()
            {
                return Err(format!("the `file` of {at} has no file name"));
            }
            At::File {
                file,
                directory_env,
                kind,
                key,
            }
        }
    };
    Ok(Place { at: place, when })
}

/// A choice's `detect` table, whose source must be one of `sources`.
pub(crate) fn parse_detect(
    value: &toml::Value,
    owner: &str,
    sources: &[Source],
) -> Result<Detect, String> {
    let table = value
        .as_table()
        .ok_or_else(|| format!("the `detect` of {owner} is not a table"))?;
    known(table, "detect", &["source", "equals"])?;
    let at = format!("the `detect` of {owner}");
    let source = string(table, "source", &at)?;
    if sources
        .iter()
        .any(|known| known.id == source && known.pack.is_some())
    {
        return Err(format!(
            "{at} cannot detect a choice from pack-specific source {source:?}"
        ));
    }
    if !sources.iter().any(|known| known.id == source) {
        return Err(format!(
            "{at} names the source {source:?}, which the starter does not have"
        ));
    }
    let equals = equals(
        table
            .get("equals")
            .ok_or_else(|| format!("{at} has no `equals`"))?,
        &at,
    )?;
    Ok(Detect { source, equals })
}

fn equals(value: &toml::Value, owner: &str) -> Result<Vec<String>, String> {
    let items = match value {
        toml::Value::String(text) => vec![text.clone()],
        toml::Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                format!("the `equals` of {owner} is not a string or a list of strings")
            })?,
        _ => {
            return Err(format!(
                "the `equals` of {owner} is not a string or a list of strings"
            ));
        }
    };
    if items.is_empty() {
        return Err(format!("the `equals` of {owner} is empty"));
    }
    Ok(items)
}

fn known(table: &toml::Table, owner: &str, keys: &[&str]) -> Result<(), String> {
    match table.keys().find(|key| !keys.contains(&key.as_str())) {
        Some(key) => Err(format!(
            "`{owner}` holds the unknown key `{key}`; it holds {}",
            keys.iter()
                .map(|key| format!("`{key}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        None => Ok(()),
    }
}

fn string(table: &toml::Table, key: &str, owner: &str) -> Result<String, String> {
    match table.get(key) {
        Some(toml::Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(_) => Err(format!("the `{key}` of {owner} is not a string")),
        None => Err(format!("{owner} has no `{key}`")),
    }
}

/// The first place of `sources` that reads a variable that `credentials` holds, as an error.
pub(crate) fn credential_place(
    sources: &[Source],
    credentials: &crate::reference::Credentials,
) -> Option<String> {
    sources.iter().find_map(|source| {
        source.places.iter().find_map(|place| {
            let variable = match &place.at {
                At::Env(name) => name,
                At::File {
                    directory_env, key, ..
                } => directory_env
                    .as_ref()
                    .filter(|name| credentials.holder(name).is_some())
                    .or_else(|| key.last())?,
            };
            credentials.holder(variable).map(|holder| {
                format!(
                    "source {:?} reads {variable}, which {holder}; detection reads no credential",
                    source.id
                )
            })
        })
    })
}

/// The places a source may not read at create: the current directory, each box home, and each
/// write grant of `table`, with `${{ home }}`, `${{ workspace }}`, and its steps filled in. A grant with a
/// `when` counts whether or not its `when` holds, because the profile's answers are not known yet.
pub(crate) fn refusals(
    table: &toml::Table,
    home: &Path,
    box_home: &Path,
    workspace: &Path,
) -> Refusals {
    let mut table = toml::Value::Table(table.clone());
    fill(&mut table, home, workspace);
    unwrap_entries(&mut table);
    let toml::Value::Table(table) = table else {
        unreachable!("a table stays a table");
    };
    let holds_home = crate::host::within(
        &crate::host::resolved(home),
        &crate::host::resolved(workspace),
    );
    let project =
        (!holds_home).then(|| (workspace.to_path_buf(), "the current directory".to_string()));
    let fixed = project.into_iter().chain(
        crate::host::box_homes(home, box_home)
            .into_iter()
            .map(|box_home| (box_home, "the box home".to_string())),
    );
    let grants = crate::lang::write_grants(&table, home)
        .into_iter()
        .map(|grant| (grant, "a write grant".to_string()));
    Refusals {
        home: home.to_path_buf(),
        roots: fixed.into_iter().chain(grants).collect(),
        shipped: None,
        protected: Vec::new(),
    }
}

/// Each filesystem entry table `{ path, optional, when }` in `value`, as its `path` alone.
fn unwrap_entries(value: &mut toml::Value) {
    match value {
        toml::Value::Array(items) => {
            for item in items.iter_mut() {
                if let Some(path) = item
                    .as_table()
                    .and_then(|entry| entry.get("path"))
                    .and_then(toml::Value::as_str)
                    .map(str::to_string)
                {
                    *item = toml::Value::String(path);
                } else {
                    unwrap_entries(item);
                }
            }
        }
        toml::Value::Table(table) => table.iter_mut().for_each(|(_, item)| unwrap_entries(item)),
        _ => {}
    }
}

fn fill(value: &mut toml::Value, home: &Path, workspace: &Path) {
    match value {
        toml::Value::String(text) => {
            if let Ok(pieces) = crate::lang::pieces(text) {
                *text = pieces
                    .into_iter()
                    .map(|piece| match piece {
                        crate::lang::Piece::Text(text) => text,
                        crate::lang::Piece::Name(name) => {
                            let filled = match name.split_once('.') {
                                _ if name == "home" => Some(home.display().to_string()),
                                _ if name == "workspace" => Some(workspace.display().to_string()),
                                Some(("workspace", rest)) => {
                                    crate::lang::workspace_value(workspace, rest).ok()
                                }
                                _ => None,
                            };
                            filled.unwrap_or_else(|| format!("${{{{ {name} }}}}"))
                        }
                    })
                    .collect();
            }
        }
        toml::Value::Array(items) => items
            .iter_mut()
            .for_each(|item| fill(item, home, workspace)),
        toml::Value::Table(table) => table
            .iter_mut()
            .for_each(|(_, item)| fill(item, home, workspace)),
        _ => {}
    }
}

/// Read `source` on `host`: the first place that holds a value gives it.
pub(crate) fn read(source: &Source, host: &Host, refusals: &Refusals) -> Reading {
    let mut reading = Reading::default();
    for place in &source.places {
        if place.when.as_deref().is_some_and(|os| os != host.os) {
            continue;
        }
        match &place.at {
            At::Env(name) => {
                if let Some(value) = host.variable(name).filter(|value| !value.is_empty()) {
                    reading.value = Some((value, format!("{name} in the environment")));
                    return reading;
                }
            }
            At::File {
                file,
                directory_env,
                kind,
                key,
            } => {
                let mut path = match file.strip_prefix("~/") {
                    Some(rest) => host.home.join(rest),
                    None => PathBuf::from(file),
                };
                if let Some((name, value)) = directory_env.as_ref().and_then(|name| {
                    host.variable(name)
                        .filter(|value| !value.is_empty())
                        .map(|value| (name, value))
                }) {
                    let directory = Path::new(&value);
                    if let Err(reason) = refusals.check_root(directory) {
                        reading
                            .skipped
                            .push(format!("{name}: {reason}; detection skipped"));
                        continue;
                    }
                    path = directory.join(path.file_name().expect("a parsed file name"));
                }
                let shown_file = tilde(&host.home, &path);
                let place_name = format!("{} in {shown_file}", shown(key));
                if let Some(reason) = refusals.reach(&path).or_else(|| refusals.protects(&path)) {
                    reading
                        .skipped
                        .push(format!("{reason}; detection does not read it"));
                    continue;
                }
                let text = match std::fs::read_to_string(&path) {
                    Ok(text) => text,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        reading
                            .skipped
                            .push(format!("{shown_file} is not read: {error}"));
                        continue;
                    }
                };
                let document = match kind.parse(&text) {
                    Ok(document) => document,
                    Err(reason) => {
                        reading
                            .skipped
                            .push(format!("{shown_file} is not read: it is {reason}"));
                        continue;
                    }
                };
                let Some(found) = key.iter().try_fold(&document, |value, key| value.get(key))
                else {
                    continue;
                };
                match found {
                    Value::String(text) if text.is_empty() => {}
                    Value::String(text) => {
                        reading.value = Some((text.clone(), place_name));
                        return reading;
                    }
                    Value::Bool(flag) => {
                        reading.value = Some((flag.to_string(), place_name));
                        return reading;
                    }
                    Value::Number(number) => {
                        reading.value = Some((number.to_string(), place_name));
                        return reading;
                    }
                    _ => reading.skipped.push(format!(
                        "{place_name} is not a string, a number, or true or false"
                    )),
                }
            }
        }
    }
    reading
}
