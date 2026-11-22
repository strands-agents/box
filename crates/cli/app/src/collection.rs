//! Collections: the folders in `~/.strands/box/external/`, each a clone of a team's repository
//! of packs, plugins, starters, and policy starters, whose names start with `@<folder>/`. A
//! collection lives in the box home, so each run protects it as it protects the box home.

use std::path::Path;

use crate::error::Error;
use crate::files::io_error;
use crate::lang::{Collection, VENDORED};

/// The folder in the box home that holds one folder for each collection.
pub(crate) const EXTERNAL: &str = "external";

/// The optional file in a collection's folder that changes the `box profile create` menus.
pub(crate) const COLLECTION_FILE: &str = "collection.toml";

/// What one `collection.toml` adds to the `box profile create` menus, by full name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Menus {
    pub(crate) starters_add: Vec<String>,
    pub(crate) starters_remove: Vec<String>,
    pub(crate) policies_add: Vec<String>,
    pub(crate) policies_remove: Vec<String>,
    pub(crate) policies_default: Option<String>,
}

/// The collections in `box_home`'s `external/`, in folder-name order. A name that starts with `.`
/// is skipped; any other entry must be a real folder with a scope's name, so a link that a box
/// could repoint, or a mistyped clone, stops the command instead of being skipped.
pub(crate) fn listed(box_home: &Path) -> Result<Vec<Collection>, Error> {
    let folder = box_home.join(EXTERNAL);
    let entries = match std::fs::read_dir(&folder) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(io_error("read", &folder, source)),
    };
    let mut collections: Vec<Collection> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read", &folder, source))?;
        let root = entry.path();
        let invalid = |reason: String| Error::Config {
            path: root.clone(),
            reason,
        };
        let Some(scope) = entry.file_name().to_str().map(str::to_string) else {
            return Err(invalid("the folder name is not UTF-8".to_string()));
        };
        if scope.starts_with('.') {
            continue;
        }
        let kind = entry
            .file_type()
            .map_err(|source| io_error("read", &root, source))?;
        if kind.is_symlink() {
            return Err(invalid(
                "a collection is a symbolic link; clone the repository into external/ instead, \
                 so each run protects it"
                    .to_string(),
            ));
        }
        if !kind.is_dir() {
            return Err(invalid(
                "external/ holds only collection folders, and this is not a folder".to_string(),
            ));
        }
        if !is_scope(&scope) {
            return Err(invalid(format!(
                "{scope:?} is not a collection name; a collection folder's name is lowercase \
                 letters, digits, and -, such as acme"
            )));
        }
        if format!("@{scope}/") == VENDORED {
            return Err(invalid(
                "a collection can't be called box, which names the packs that box ships"
                    .to_string(),
            ));
        }
        collections.push(Collection { scope, root });
    }
    collections.sort_by(|a, b| a.scope.cmp(&b.scope));
    Ok(collections)
}

/// The menus of the collection `collection`, from its `collection.toml`, or none when it has
/// no such file.
pub(crate) fn read(collection: &Collection) -> Result<Menus, Error> {
    let path = collection.root.join(COLLECTION_FILE);
    let invalid = |reason: String| Error::Config {
        path: path.clone(),
        reason,
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Menus::default()),
        Err(error) => return Err(io_error("read", &path, error)),
    };
    let table: toml::Table = toml::from_str(&text).map_err(|error| invalid(error.to_string()))?;
    let known = ["starters", crate::policy_starter::MENU_KEY];
    if let Some(key) = table.keys().find(|key| !known.contains(&key.as_str())) {
        return Err(invalid(format!(
            "the unknown key `{key}`; a collection holds `[starters]` and `[{}]`, and its folder \
             name is its name",
            crate::policy_starter::MENU_KEY
        )));
    }
    let scope = collection.scope.as_str();
    let own = format!("@{scope}/");
    let mut menus = Menus::default();
    for (key, add, remove, default) in [
        (
            "starters",
            &mut menus.starters_add,
            &mut menus.starters_remove,
            None,
        ),
        (
            crate::policy_starter::MENU_KEY,
            &mut menus.policies_add,
            &mut menus.policies_remove,
            Some(&mut menus.policies_default),
        ),
    ] {
        let Some(value) = table.get(key) else {
            continue;
        };
        let menu = value
            .as_table()
            .ok_or_else(|| invalid(format!("`{key}` is not a table")))?;
        let keys: &[&str] = match default {
            Some(_) => &["add", "remove", "default"],
            None => &["add", "remove"],
        };
        if let Some(unknown) = menu.keys().find(|found| !keys.contains(&found.as_str())) {
            return Err(invalid(format!(
                "`[{key}]` holds the unknown key `{unknown}`; it holds {}",
                keys.iter()
                    .map(|key| format!("`{key}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        for (list, into, prefix) in [("add", add, own.as_str()), ("remove", remove, VENDORED)] {
            let Some(value) = menu.get(list) else {
                continue;
            };
            let names = strings(Some(value))
                .ok_or_else(|| invalid(format!("`[{key}] {list}` is not a list of names")))?;
            if let Some(name) = names.iter().find(|name| {
                name.strip_prefix(prefix)
                    .is_none_or(|short| short.is_empty() || short.contains('/'))
            }) {
                return Err(invalid(match list {
                    "add" => format!(
                        "`[{key}] add` names {name:?}; a collection adds only its own, \
                         such as \"{own}<name>\""
                    ),
                    _ => format!(
                        "`[{key}] remove` names {name:?}; a collection removes only what box \
                         ships, such as \"{VENDORED}<name>\""
                    ),
                }));
            }
            *into = names;
        }
        if let Some(default) = default
            && let Some(value) = menu.get("default")
        {
            *default = Some(
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| invalid(format!("`[{key}] default` is not a name")))?,
            );
        }
    }
    Ok(menus)
}

/// Whether `scope` is a collection's scope: lowercase letters, digits, and `-`.
fn is_scope(scope: &str) -> bool {
    !scope.is_empty()
        && !scope.starts_with('-')
        && scope
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The strings of the list `value`, or `None` when it is not a list of strings.
fn strings(value: Option<&toml::Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
#[path = "collection_tests.rs"]
mod tests;
