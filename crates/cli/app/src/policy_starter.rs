//! The policy starters that `box` ships and the operator's own, the `[policy-starters]` menu, and
//! the policy question.

use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::files::io_error;
use crate::lang::{Lookup, VENDORED};
use crate::profile::ProjectAccess;
use crate::starter::{CONFIG_FILE, Terminal, columns};

/// The folder beside the packs that holds one folder for each policy starter.
pub(crate) const POLICIES: &str = "policies";

/// The file that names and describes a policy starter.
pub(crate) const STARTER_FILE: &str = "policy.toml";

/// The file that holds the rules of a policy starter.
pub(crate) const RULES_FILE: &str = "policy.dw";

/// The file in a profile folder that `box profile create` copies a policy starter into.
pub(crate) const PROFILE_FILE: &str = "policy.dw";

/// The `config.toml` table that lists the policy starters.
pub(crate) const MENU_KEY: &str = "policy-starters";

/// The question that `box profile create` asks after the agent starter's questions.
pub(crate) const QUESTION: &str = "Which policy should the agent start with?";

/// A policy starter: the rules that `box profile create` copies into a new profile.
#[derive(Debug, Clone)]
pub(crate) struct PolicyStarter {
    pub(crate) name: String,
    pub(crate) label: String,
    pub(crate) description: String,
    /// The `[project] access` that a profile made from this starter gets, if the starter sets one.
    pub(crate) project: Option<ProjectAccess>,
    folder: PathBuf,
    flag: String,
}

/// The folder of the operator's policy starters for `lookup`: `policies` beside the operator's
/// packs.
fn operator_root(lookup: &Lookup) -> Option<PathBuf> {
    lookup.operator.parent().map(|home| home.join(POLICIES))
}

/// Whether `short` is a policy starter's folder name.
fn is_policy_name(short: &str) -> bool {
    !short.is_empty()
        && short
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Whether the operator has a policy starter entry `short`. Any entry claims the name, even a
/// folder without a `policy.toml` or a broken link, so a broken own policy starter fails loudly
/// instead of falling back to the shipped one of the same name.
fn operator_has(lookup: &Lookup, short: &str) -> bool {
    is_policy_name(short)
        && operator_root(lookup)
            .is_some_and(|root| std::fs::symlink_metadata(root.join(short)).is_ok())
}

/// The full name of the policy starter `name`: a name with `/` as it is, a plain name of the
/// operator's own policy starter as it is, else `@box/<name>`.
pub(crate) fn full_name(name: &str, lookup: &Lookup) -> String {
    if name.contains('/') || operator_has(lookup, name) {
        name.to_string()
    } else {
        format!("{VENDORED}{name}")
    }
}

impl PolicyStarter {
    /// The policy starter that `name` names after [`full_name`]. A plain name that is neither
    /// the operator's nor shipped names both missing folders.
    pub(crate) fn find(name: &str, lookup: &Lookup) -> Result<Self, String> {
        if !name.contains('/') && !is_policy_name(name) {
            return Err(format!(
                "{name:?} is not a policy name; a policy folder name uses lowercase letters, \
                 digits, and -"
            ));
        }
        let full = full_name(name, lookup);
        match Self::load(&full, lookup) {
            Err(_) if full != name && is_policy_name(name) => Err(format!(
                "no policy named {name}; neither {} nor {} exists",
                operator_root(lookup)
                    .map(|root| root.join(name).join(STARTER_FILE).display().to_string())
                    .unwrap_or_default(),
                resources_root(lookup)
                    .map(|root| root.join(POLICIES).join(name).join(STARTER_FILE))
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
            )),
            found => found,
        }
    }

    /// The policy starter `name`: `@box/<name>` that `box` ships, or `<name>` in the operator's
    /// `~/.strands/box/policies/`.
    pub(crate) fn load(name: &str, lookup: &Lookup) -> Result<Self, String> {
        let (root, short) = match (name.strip_prefix(VENDORED), lookup.in_collection(name)) {
            (Some(short), _) if is_policy_name(short) => (
                resources_root(lookup)
                    .map(|root| root.join(POLICIES))
                    .ok_or("box's own policies were not found; set BOX_RESOURCES")?,
                short,
            ),
            (None, Some(found)) => match found? {
                (collection, short) if is_policy_name(short) => (collection.join(POLICIES), short),
                _ => {
                    return Err(format!(
                        "{name:?} is not a policy name; a policy folder name uses lowercase \
                         letters, digits, and -"
                    ));
                }
            },
            (None, None) if is_policy_name(name) => (
                operator_root(lookup).ok_or("the box home has no parent folder")?,
                name,
            ),
            _ => {
                return Err(format!(
                    "{name:?} is not a policy name; name one that box ships as @box/<name>, such \
                     as @box/open, or your own in ~/.strands/box/policies/<name>/ as <name>"
                ));
            }
        };
        let folder = root.join(short);
        let path = folder.join(STARTER_FILE);
        let text = match crate::starter::read_unlinked(&folder, &path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(match name.starts_with(VENDORED) {
                    true => format!(
                        "box ships no policy named {name}; {} is missing",
                        path.display()
                    ),
                    false => format!("no policy named {name}; {} is missing", path.display()),
                });
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let invalid = |reason: String| format!("{}: {reason}", path.display());
        let table: toml::Table =
            toml::from_str(&text).map_err(|error| invalid(error.to_string()))?;
        if let Some(key) = table.keys().find(|key| *key != "policy") {
            return Err(invalid(format!(
                "the unknown key `{key}`; a policy starter holds `[policy]`"
            )));
        }
        let header = table
            .get("policy")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| invalid("no `[policy]` table".to_string()))?;
        if let Some(key) = header
            .keys()
            .find(|key| !matches!(key.as_str(), "name" | "label" | "description" | "project"))
        {
            return Err(invalid(format!(
                "`[policy]` holds the unknown key `{key}`; it holds `name`, `label`, \
                 `description`, and `project`"
            )));
        }
        let project = match header.get("project") {
            None => None,
            Some(value) => Some(value.as_str().and_then(ProjectAccess::parse).ok_or_else(
                || {
                    invalid(format!(
                        "`[policy] project` is one of {}",
                        ProjectAccess::VALUES
                            .map(|value| format!("{value:?}"))
                            .join(", ")
                    ))
                },
            )?),
        };
        let text_of = |key: &str| {
            header
                .get(key)
                .and_then(toml::Value::as_str)
                .filter(|text| !text.trim().is_empty())
                .map(str::to_string)
                .ok_or_else(|| invalid(format!("`[policy] {key}` is not a nonempty string")))
        };
        let written = text_of("name")?;
        if written != name {
            return Err(invalid(format!(
                "`[policy] name` is {written:?}, and the folder holds {name}"
            )));
        }
        let flag = match name.strip_prefix(VENDORED) {
            Some(short) if !operator_has(lookup, short) => short.to_string(),
            _ => written.clone(),
        };
        Ok(Self {
            name: written,
            label: text_of("label")?,
            description: text_of("description")?,
            project,
            folder,
            flag,
        })
    }

    /// The rules of this policy starter, refusing a symbolic link as [`PolicyStarter::load`] does.
    pub(crate) fn rules(&self) -> Result<String, String> {
        let path = self.folder.join(RULES_FILE);
        crate::starter::read_unlinked(&self.folder, &path)
            .map_err(|error| format!("{}: {error}", path.display()))
    }

    /// The `policy.dw` that `box profile create` writes into a new profile: a header that names
    /// this policy starter, then its rules.
    pub(crate) fn copy(&self) -> Result<String, String> {
        let rules = self.rules()?;
        let mut text = format!(
            "// Copied from {} ({}) by `box profile create`. This file is yours: only\n\
             // `box profile create --force` replaces it. Edit the rules here, and the next run\n\
             // uses them.\n",
            self.name, self.label
        );
        if !rules.trim().is_empty() {
            text.push('\n');
            text.push_str(rules.trim_end());
            text.push('\n');
        }
        Ok(text)
    }

    /// The name `--policy` gives this policy starter: its name without `@box/`, unless the
    /// operator's own policy starter has that name.
    pub(crate) fn flag_name(&self) -> &str {
        &self.flag
    }
}

/// The `resources/` directory that holds the packs of `lookup`.
fn resources_root(lookup: &Lookup) -> Option<&Path> {
    lookup.vendored.as_deref().and_then(Path::parent)
}

/// The policy starters that `box profile create` offers, in menu order, and the one that Enter
/// picks.
#[derive(Debug, Clone)]
pub(crate) struct PolicyMenu {
    pub(crate) starters: Vec<PolicyStarter>,
    pub(crate) default: usize,
}

/// The entries of the policy menu, by the name each file gives, before any folder is read: the
/// name, the key that lists it, and the file that holds the key.
struct Listed {
    entries: Vec<(String, &'static str, PathBuf)>,
    default: usize,
}

/// The `[policy-starters]` table of one `config.toml`.
#[derive(Debug, Default)]
struct Table {
    only: Option<Vec<String>>,
    add: Vec<String>,
    remove: Vec<String>,
    default: Option<String>,
}

impl PolicyMenu {
    /// Refuse a `[policy-starters]` table in a `config.toml` or a `collection.toml` that `load`
    /// refuses, without reading a policy folder.
    pub(crate) fn check_config(lookup: &Lookup) -> Result<(), Error> {
        Self::listed(lookup).map(|_| ())
    }

    /// The entries that the `config.toml` files and the collections list, checked by name only.
    fn listed(lookup: &Lookup) -> Result<Listed, Error> {
        let built_in_path = resources_root(lookup)
            .map(|root| root.join(CONFIG_FILE))
            .unwrap_or_else(|| PathBuf::from(CONFIG_FILE));
        let built_in = read_table(&built_in_path)?.unwrap_or_default();
        let user_path = lookup.config_file();
        let user = read_table(&user_path)?.unwrap_or_default();
        let invalid = |path: &Path, reason: String| Error::Config {
            path: path.to_path_buf(),
            reason,
        };
        if !built_in.add.is_empty() || !built_in.remove.is_empty() {
            return Err(invalid(
                &built_in_path,
                "the built-in list uses `only`".to_string(),
            ));
        }
        if user.only.is_some() && (!user.add.is_empty() || !user.remove.is_empty()) {
            return Err(invalid(
                &user_path,
                format!(
                    "`[{MENU_KEY}]` holds `only` with `add` or `remove`; `only` is the whole list"
                ),
            ));
        }
        let mut offered: Vec<(String, &'static str, PathBuf)> = built_in
            .only
            .unwrap_or_default()
            .iter()
            .map(|name| (full_name(name, lookup), "only", built_in_path.clone()))
            .collect();
        let mut default = built_in
            .default
            .map(|name| (full_name(&name, lookup), built_in_path.clone()));
        // Every policy starter that a layer has offered, by full name, so a `remove` of one that
        // an earlier layer already removed is no change.
        let mut ever: Vec<String> = offered.iter().map(|(name, _, _)| name.clone()).collect();
        let mut default_removed = false;
        for collection in &lookup.collections {
            let menus = crate::collection::read(collection)?;
            let path = collection.root.join(crate::collection::COLLECTION_FILE);
            remove(&mut offered, &menus.policies_remove, &path, lookup, &ever)?;
            ever.extend(
                menus
                    .policies_add
                    .iter()
                    .map(|name| full_name(name, lookup)),
            );
            offered.extend(
                menus
                    .policies_add
                    .into_iter()
                    .map(|name| (name, "add", path.clone())),
            );
            match menus.policies_default {
                Some(name) => {
                    default = Some((full_name(&name, lookup), path));
                    default_removed = false;
                }
                // A collection that removes the default and names none leaves the menu to start
                // at its first entry, as an operator's `remove` does.
                None if default.as_ref().is_some_and(|(name, _)| {
                    !offered
                        .iter()
                        .any(|(listed, _, _)| full_name(listed, lookup) == *name)
                }) =>
                {
                    default = None;
                    default_removed = true;
                }
                None => {}
            }
        }
        let user_changed = user.only.is_some() || !user.add.is_empty() || !user.remove.is_empty();
        let names_from = if user_changed {
            user_path.clone()
        } else {
            offered
                .last()
                .map(|(_, _, path)| path.clone())
                .unwrap_or_else(|| built_in_path.clone())
        };
        let mut entries: Vec<(String, &'static str, PathBuf)> = Vec::new();
        match user.only {
            Some(only) => {
                entries.extend(
                    only.into_iter()
                        .map(|name| (name, "only", user_path.clone())),
                );
            }
            None => {
                remove(&mut offered, &user.remove, &user_path, lookup, &ever)?;
                entries.extend(offered);
                entries.extend(
                    user.add
                        .into_iter()
                        .map(|name| (name, "add", user_path.clone())),
                );
            }
        }
        if entries.is_empty() {
            return Err(invalid(
                &names_from,
                format!("`[{MENU_KEY}]` lists no policy starter"),
            ));
        }
        let mut names: Vec<String> = Vec::new();
        for (name, key, path) in &entries {
            let full = full_name(name, lookup);
            if names.contains(&full) {
                let reason = match *key {
                    "add" => format!("`[{MENU_KEY}] add` names {full}, which is already listed"),
                    _ => format!("`[{MENU_KEY}] only` names {full} twice"),
                };
                return Err(invalid(path, reason));
            }
            names.push(full);
        }
        let (default, default_from) = match (user.default, default) {
            (Some(default), _) => (full_name(&default, lookup), user_path.clone()),
            (None, Some((default, path))) if !user_changed || names.contains(&default) => {
                (default, path)
            }
            (None, _) if user_changed || default_removed => (names[0].clone(), user_path.clone()),
            (None, _) => {
                return Err(invalid(
                    &built_in_path,
                    format!("`[{MENU_KEY}]` sets no `default`"),
                ));
            }
        };
        let default = names.iter().position(|name| *name == default).ok_or_else(|| {
            invalid(
                &default_from,
                format!(
                    "`[{MENU_KEY}] default` is {default}, which is not in the list; the list is {}",
                    names.join(", ")
                ),
            )
        })?;
        Ok(Listed { entries, default })
    }

    /// The built-in list beside the packs, changed by each collection and by
    /// `~/.strands/box/config.toml`.
    pub(crate) fn load(lookup: &Lookup) -> Result<Self, Error> {
        let listed = Self::listed(lookup)?;
        let mut starters: Vec<PolicyStarter> = Vec::new();
        for (name, key, path) in &listed.entries {
            let starter = PolicyStarter::find(name, lookup).map_err(|reason| Error::Config {
                path: path.clone(),
                reason: format!("`[{MENU_KEY}] {key}`: {reason}"),
            })?;
            starters.push(starter);
        }
        Ok(Self {
            starters,
            default: listed.default,
        })
    }

    /// The policy starter that `entry` names: its full name, or its name without `@box/`.
    pub(crate) fn named(&self, entry: &str) -> Option<&PolicyStarter> {
        self.starters
            .iter()
            .find(|starter| starter.name == entry || starter.flag_name() == entry)
    }
}

/// Take each of `names` out of `offered`, refusing one that is not there, as `[policy-starters]
/// remove` in `path` asks.
fn remove(
    offered: &mut Vec<(String, &'static str, PathBuf)>,
    names: &[String],
    path: &Path,
    lookup: &Lookup,
    ever: &[String],
) -> Result<(), Error> {
    for name in names {
        let full = full_name(name, lookup);
        if !ever.contains(&full) {
            return Err(Error::Config {
                path: path.to_path_buf(),
                reason: format!(
                    "`[{MENU_KEY}] remove` names {name}, which is not in the policy menu; the \
                     menu offers {}",
                    ever.join(", ")
                ),
            });
        }
        offered.retain(|(listed, _, _)| full_name(listed, lookup) != full);
    }
    Ok(())
}

/// The `[policy-starters]` table of the `config.toml` at `path`, or `None` when the file or the
/// table is absent.
fn read_table(path: &Path) -> Result<Option<Table>, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("read", path, source)),
    };
    let invalid = |reason: String| Error::Config {
        path: path.to_path_buf(),
        reason,
    };
    let table: toml::Table = toml::from_str(&text).map_err(|error| invalid(error.to_string()))?;
    let Some(menu) = table.get(MENU_KEY) else {
        return Ok(None);
    };
    let menu = menu
        .as_table()
        .ok_or_else(|| invalid(format!("`{MENU_KEY}` is not a table")))?;
    if let Some(key) = menu
        .keys()
        .find(|key| !matches!(key.as_str(), "only" | "add" | "remove" | "default"))
    {
        return Err(invalid(format!(
            "`[{MENU_KEY}]` holds the unknown key `{key}`; it holds `only`, `add`, `remove`, and \
             `default`"
        )));
    }
    let list = |key: &str| -> Result<Option<Vec<String>>, Error> {
        match menu.get(key) {
            None => Ok(None),
            Some(value) => value
                .as_array()
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                })
                .map(Some)
                .ok_or_else(|| {
                    invalid(format!(
                        "`[{MENU_KEY}] {key}` is not a list of policy names"
                    ))
                }),
        }
    };
    let only = list("only")?;
    let add = list("add")?.unwrap_or_default();
    let remove = list("remove")?.unwrap_or_default();
    let default = match menu.get("default") {
        None => None,
        Some(toml::Value::String(name)) => Some(name.clone()),
        Some(_) => {
            return Err(invalid(format!(
                "`[{MENU_KEY}] default` is not a policy name"
            )));
        }
    };
    Ok(Some(Table {
        only,
        add,
        remove,
        default,
    }))
}

/// The facts the create step answers the policy question with.
pub(crate) struct Request<'a> {
    /// The command that `StarterUnanswered` names.
    pub(crate) command: &'a str,
    /// What `--policy` names.
    pub(crate) given: Option<&'a str>,
    /// Where the profile is written, for an error.
    pub(crate) path: &'a Path,
    /// Refuse before the prompt: the profile exists, and `--force` is not given.
    pub(crate) exists: bool,
}

/// The policy starter of a new profile: the one `--policy` names, else the operator's pick at
/// `terminal`. With no terminal and no `--policy`, the step stops.
pub(crate) fn choose(
    menu: &PolicyMenu,
    request: &Request<'_>,
    terminal: Option<&mut Terminal<'_>>,
) -> Result<String, Error> {
    if let Some(given) = request.given {
        return menu
            .named(given)
            .map(|starter| starter.name.clone())
            .ok_or_else(|| Error::Profile {
                path: request.path.to_path_buf(),
                line: None,
                reason: format!(
                    "`--policy` names {given:?}, which is not a policy starter; the policy \
                     starters are {}",
                    menu.starters
                        .iter()
                        .map(|starter| starter.flag_name())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
    }
    let Some(terminal) = terminal else {
        let rows: Vec<(String, String)> = menu
            .starters
            .iter()
            .map(|starter| {
                (
                    format!("--policy {}", starter.flag_name()),
                    starter.label.clone(),
                )
            })
            .collect();
        return Err(Error::StarterUnanswered {
            command: request.command.to_string(),
            question: QUESTION.to_string(),
            flags: columns(&rows),
        });
    };
    if request.exists {
        return Err(Error::Exists {
            path: request.path.to_path_buf(),
        });
    }
    Ok(menu.starters[ask(menu, terminal)?].name.clone())
}

/// Ask the policy question until the operator picks a policy starter. Enter picks the default.
fn ask(menu: &PolicyMenu, terminal: &mut Terminal<'_>) -> Result<usize, Error> {
    terminal.question(QUESTION);
    for (index, starter) in menu
        .starters
        .iter()
        .enumerate()
        .filter(|_| !terminal.choice_controls)
    {
        let _ = writeln!(
            terminal.output,
            "  {}. {}: {}",
            index + 1,
            starter.label,
            starter.description
        );
    }
    let count = menu.starters.len();
    let labels: Vec<&str> = menu
        .starters
        .iter()
        .map(|starter| starter.label.as_str())
        .collect();
    let descriptions: Vec<&str> = menu
        .starters
        .iter()
        .map(|starter| starter.description.as_str())
        .collect();
    let answer = loop {
        let line = if terminal.choice_controls {
            crate::prompt::described(terminal, &labels, &descriptions, Some(menu.default))?
        } else {
            let _ = write!(terminal.output, "> [{}] ", menu.default + 1);
            let _ = terminal.output.flush();
            let mut line = String::new();
            let read = terminal
                .input
                .read_line(&mut line)
                .map_err(|source| io_error("read", Path::new("stdin"), source))?;
            (read > 0).then_some(line)
        };
        let Some(line) = line else {
            return Err(Error::StarterAborted {
                question: QUESTION.to_string(),
            });
        };
        let line = line.trim();
        if line.is_empty() {
            break menu.default;
        }
        match line.parse::<usize>() {
            Ok(number) if (1..=count).contains(&number) => break number - 1,
            _ => {
                terminal.feedback(&format!("Type a number from 1 to {count}.\n"));
            }
        }
    };
    if let Some(session) = &mut terminal.session {
        session.accept((answer + 1).to_string());
    }
    Ok(answer)
}

#[cfg(test)]
#[path = "policy_starter_tests.rs"]
mod tests;
