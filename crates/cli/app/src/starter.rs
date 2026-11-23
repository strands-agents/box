use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::detect::{self, Detect, Line, Reading, Source};
use crate::error::Error;
use crate::files::io_error;
use crate::host::Host;
use crate::lang::{self, Declaration, Lookup, VENDORED};

/// The file that holds the settings of `box` itself.
pub(crate) const CONFIG_FILE: &str = "config.toml";

/// The folder beside the packs, and the folder in the box home, that holds one folder for each
/// starter.
pub(crate) const STARTERS: &str = "starters";

/// The file that holds a starter.
pub(crate) const STARTER_FILE: &str = "starter.toml";

/// The last segment of a pack or starter name.
pub(crate) fn short_name(pack: &str) -> &str {
    pack.rsplit('/').next().unwrap_or(pack)
}

/// The folder of the starter `name`: `@box/<name>` in the `starters/` folder beside the packs that
/// `box` ships, and `<name>` in `~/.strands/box/starters/`.
fn starter_folder(lookup: &Lookup, name: &str) -> Option<PathBuf> {
    let (root, short) = match (name.strip_prefix(VENDORED), lookup.in_collection(name)) {
        (Some(short), _) => (lookup.vendored.as_deref()?.parent()?.join(STARTERS), short),
        (None, Some(found)) => {
            let (collection, short) = found.ok()?;
            (collection.join(STARTERS), short)
        }
        (None, None) => (lookup.operator.parent()?.join(STARTERS), name),
    };
    let valid = !short.is_empty()
        && !short.starts_with('.')
        && short
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    valid.then(|| root.join(short))
}

/// The text of the starter file `path` in `folder`, refusing a symbolic link at the file, at its
/// folder, or at the `starters/` or `policies/` folder that holds it, and a file with more than
/// one hard link. Policy starters read their files through it too.
pub(crate) fn read_unlinked(folder: &Path, path: &Path) -> std::io::Result<String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    for at in [folder.parent(), Some(folder)].into_iter().flatten() {
        if std::fs::symlink_metadata(at).is_ok_and(|metadata| metadata.is_symlink()) {
            return Err(std::io::Error::other(format!(
                "{} is a symbolic link; a starter is a regular file in a folder of its own",
                at.display()
            )));
        }
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(nix::libc::ELOOP) => std::io::Error::other(
                "a symbolic link; a starter is a regular file in a folder of its own",
            ),
            _ => error,
        })?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    if std::os::unix::fs::MetadataExt::nlink(&metadata) != 1 {
        return Err(std::io::Error::other(
            "starter files must have exactly one hard link; use a separate copy",
        ));
    }
    std::io::read_to_string(file)
}

/// The full starter name that `name` gives: a full name as written; a short name is your
/// starter, else nothing when it names your pack, else `@box/<name>`.
fn resolve(lookup: &Lookup, name: &str) -> Option<String> {
    if name.contains('/') {
        return Some(name.to_string());
    }
    if starter_folder(lookup, name).is_some_and(|folder| folder.join(STARTER_FILE).is_file()) {
        return Some(name.to_string());
    }
    if lookup.full_name(name).is_ok_and(|pack| pack == name) {
        return None;
    }
    Some(format!("{VENDORED}{name}"))
}

/// The agent's name as a person reads it: the `label` of the starter that has the name of the
/// agent pack `agent`, else of the pack it extends that runs an agent. The menu does not change
/// it, so a team starter that lists the agent pack never names the agent.
pub(crate) fn agent_name(lookup: &Lookup, agent: &str) -> Result<Option<String>, String> {
    let mut packs = vec![agent.to_string()];
    for pack in lang::imported(lookup, &[agent.to_string()])? {
        if pack != agent && lang::runs_agent(lookup, &pack)? {
            packs.push(pack);
        }
    }
    Ok(packs.iter().find_map(|pack| {
        Starter::load(pack, lookup)
            .ok()
            .map(|starter| starter.label)
    }))
}

/// Whether the starter `name` is the own starter of the pack `pack`: it has the pack's name, or
/// it is your starter with the short name of a pack that `box` ships, which it replaces.
pub(crate) fn owns(name: &str, pack: &str) -> bool {
    name == pack || (!name.contains('/') && pack.strip_prefix(VENDORED) == Some(name))
}

/// The starters that `box` offers, in menu order, by full starter name.
#[derive(Debug, Clone, Default)]
pub(crate) struct Menu {
    pub(crate) starters: Vec<String>,
}

impl Menu {
    /// The built-in list beside the packs, changed by `~/.strands/box/config.toml`.
    pub(crate) fn load(lookup: &Lookup) -> Result<Self, Error> {
        let built_in = match lookup.vendored.as_deref().and_then(Path::parent) {
            Some(root) => {
                let path = root.join(CONFIG_FILE);
                let lists = read_lists(&path, Kind::Shipped)?.unwrap_or_default();
                if !lists.add.is_empty() || !lists.remove.is_empty() {
                    return Err(Error::Config {
                        path,
                        reason: "the built-in list uses `only`".to_string(),
                    });
                }
                lists.only.unwrap_or_default()
            }
            None => Vec::new(),
        };
        let mut built_in = built_in;
        // Every starter that a layer has offered, so a `remove` of one that an earlier layer
        // already removed is no change, and a name that no layer offers is still refused.
        let mut offered = built_in.clone();
        for collection in &lookup.collections {
            let menus = crate::collection::read(collection)?;
            let path = collection.root.join(crate::collection::COLLECTION_FILE);
            let invalid = |reason: String| Error::Config {
                path: path.clone(),
                reason,
            };
            for starter in &menus.starters_remove {
                if !offered.contains(starter) {
                    return Err(invalid(format!(
                        "`[starters] remove` names {starter:?}, which is not in the starter \
                         menu; the menu offers {}",
                        offered.join(", ")
                    )));
                }
                built_in.retain(|kept| kept != starter);
            }
            for starter in menus.starters_add {
                if built_in.contains(&starter) {
                    return Err(invalid(format!(
                        "`[starters] add` names {starter:?}, which is already a starter"
                    )));
                }
                offered.push(starter.clone());
                built_in.push(starter);
            }
            Self::checked(built_in.clone(), &path, lookup)?;
        }
        let path = lookup.config_file();
        let Some(user) = read_lists(&path, Kind::Operator)? else {
            return Self::checked(built_in, &path, lookup);
        };
        let invalid = |reason: String| Error::Config {
            path: path.clone(),
            reason,
        };
        if let Some(only) = user.only {
            if !user.add.is_empty() || !user.remove.is_empty() {
                return Err(invalid(
                    "`[starters]` holds `only` with `add` or `remove`; `only` is the whole list"
                        .to_string(),
                ));
            }
            return Self::checked(only, &path, lookup);
        }
        let mut starters = built_in.clone();
        for starter in &user.remove {
            if !offered.contains(starter) {
                return Err(invalid(format!(
                    "`[starters] remove` names {starter:?}, which is not in the starter menu; \
                     the menu offers {}",
                    offered.join(", ")
                )));
            }
            starters.retain(|kept| kept != starter);
        }
        for starter in user.add {
            if starters.contains(&starter) {
                return Err(invalid(format!(
                    "`[starters] add` names {starter:?}, which is already a starter"
                )));
            }
            starters.push(starter);
        }
        Self::checked(starters, &path, lookup)
    }

    fn checked(starters: Vec<String>, path: &Path, lookup: &Lookup) -> Result<Self, Error> {
        for (index, starter) in starters.iter().enumerate() {
            if let Some(Err(reason)) = lookup.in_collection(starter) {
                return Err(Error::Config {
                    path: path.to_path_buf(),
                    reason,
                });
            }
            if starter.contains('/')
                && !starter.starts_with(VENDORED)
                && lookup.in_collection(starter).is_none()
            {
                return Err(Error::Config {
                    path: path.to_path_buf(),
                    reason: format!(
                        "`[starters]` names {starter:?}, which is not a starter name; a starter \
                         that box ships is {VENDORED}<name>"
                    ),
                });
            }
            if let Some(earlier) = starters[..index]
                .iter()
                .find(|earlier| short_name(earlier) == short_name(starter))
            {
                return Err(Error::Config {
                    path: path.to_path_buf(),
                    reason: format!(
                        "the starters {earlier} and {starter} share the name {:?}; remove one of \
                         them in `[starters]`",
                        short_name(starter)
                    ),
                });
            }
        }
        Ok(Self { starters })
    }

    /// The starter in the menu that the name `name` resolves to.
    pub(crate) fn named(&self, lookup: &Lookup, name: &str) -> Option<&str> {
        let full = resolve(lookup, name)?;
        self.starters
            .iter()
            .find(|starter| **starter == full)
            .map(String::as_str)
    }

    /// The name that `--with` and `box profile create` take for the starter `name`: its short
    /// name, unless that names something else.
    pub(crate) fn spelling(lookup: &Lookup, name: &str) -> String {
        let short = short_name(name);
        if resolve(lookup, short).is_some_and(|full| full == name) {
            short.to_string()
        } else {
            name.to_string()
        }
    }
}

/// The lists of one `[starters]` table.
#[derive(Debug, Default)]
struct Lists {
    only: Option<Vec<String>>,
    add: Vec<String>,
    remove: Vec<String>,
}

/// Which `config.toml` a reader reads: the one `box` ships beside its packs, or the operator's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Shipped,
    Operator,
}

/// The `config.toml` at `path` as a table, refusing a key that `kind` does not hold, or `None`
/// when the file is absent.
fn read_config(path: &Path, kind: Kind) -> Result<Option<toml::Table>, Error> {
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
    let known: &[&str] = match kind {
        Kind::Shipped => &["starters", "policy-starters", "tools"],
        Kind::Operator => &["starters", "policy-starters", lang::BANNER],
    };
    if let Some(key) = table.keys().find(|key| !known.contains(&key.as_str())) {
        let holds = known
            .iter()
            .map(|key| format!("`[{key}]`"))
            .collect::<Vec<_>>()
            .join(" and ");
        return Err(invalid(format!(
            "`config.toml` holds the unknown key `{key}`; it holds {holds}"
        )));
    }
    Ok(Some(table))
}

/// The operator's `[banner] enabled` in the `config.toml` in the box home of `lookup`, or `None`
/// when the file or the key is absent.
pub(crate) fn banner_enabled(lookup: &Lookup) -> Result<Option<bool>, Error> {
    let path = lookup
        .operator
        .parent()
        .map(|root| root.join(CONFIG_FILE))
        .unwrap_or_else(|| PathBuf::from(CONFIG_FILE));
    let Some(table) = read_config(&path, Kind::Operator)? else {
        return Ok(None);
    };
    lang::banner_enabled(&table).map_err(|reason| Error::Config { path, reason })
}

/// The tools `box profile create` adds when `--tools` names none, by full pack name: the
/// `[tools] defaults` of the `config.toml` beside the packs `box` ships.
pub(crate) fn default_tools(lookup: &Lookup) -> Result<Vec<String>, Error> {
    let Some(root) = lookup.vendored.as_deref().and_then(Path::parent) else {
        return Ok(Vec::new());
    };
    let path = root.join(CONFIG_FILE);
    let invalid = |reason: String| Error::Config {
        path: path.clone(),
        reason,
    };
    let Some(table) = read_config(&path, Kind::Shipped)? else {
        return Err(invalid(
            "the `config.toml` that ships with `box` is missing; it names the default tools"
                .to_string(),
        ));
    };
    let Some(tools) = table.get("tools") else {
        return Err(invalid(
            "`config.toml` holds no `[tools] defaults`; it names the default tools".to_string(),
        ));
    };
    let tools = tools
        .as_table()
        .ok_or_else(|| invalid("`tools` is not a table".to_string()))?;
    if let Some(key) = tools.keys().find(|key| *key != "defaults") {
        return Err(invalid(format!(
            "`[tools]` holds the unknown key `{key}`; it holds `defaults`"
        )));
    }
    let names = match tools.get("defaults") {
        None => {
            return Err(invalid(
                "`config.toml` holds no `[tools] defaults`; it names the default tools".to_string(),
            ));
        }
        Some(value) => value
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or_else(|| invalid("`[tools] defaults` is not a list of tool names".to_string()))?,
    };
    let shipped = lookup.tool_packs();
    let mut packs: Vec<String> = Vec::new();
    for name in names {
        let pack = format!("{}{name}", lang::VENDORED);
        if !shipped.contains(&pack) {
            return Err(invalid(format!(
                "`[tools] defaults` names `{name}`, which is not a tool pack `box` ships; the tool \
                 packs are {}",
                shipped
                    .iter()
                    .map(|pack| pack.trim_start_matches(lang::VENDORED))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        if packs.contains(&pack) {
            return Err(invalid(format!("`[tools] defaults` names `{name}` twice")));
        }
        packs.push(pack);
    }
    Ok(packs)
}

/// The `[starters]` table of the `config.toml` at `path`, or `None` when the file is absent.
fn read_lists(path: &Path, kind: Kind) -> Result<Option<Lists>, Error> {
    let invalid = |reason: String| Error::Config {
        path: path.to_path_buf(),
        reason,
    };
    let Some(table) = read_config(path, kind)? else {
        return Ok(None);
    };
    let Some(starters) = table.get("starters") else {
        return Ok(Some(Lists::default()));
    };
    let starters = starters
        .as_table()
        .ok_or_else(|| invalid("`starters` is not a table".to_string()))?;
    if let Some(key) = starters
        .keys()
        .find(|key| !matches!(key.as_str(), "only" | "add" | "remove"))
    {
        return Err(invalid(format!(
            "`[starters]` holds the unknown key `{key}`; it holds `add`, `remove`, or `only`"
        )));
    }
    let list = |key: &str| -> Result<Option<Vec<String>>, Error> {
        let Some(value) = starters.get(key) else {
            return Ok(None);
        };
        let items = value
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or_else(|| invalid(format!("`[starters] {key}` is not a list of starter names")))?;
        Ok(Some(items))
    };
    Ok(Some(Lists {
        only: list("only")?,
        add: list("add")?.unwrap_or_default(),
        remove: list("remove")?.unwrap_or_default(),
    }))
}

/// A starter: the `starter.toml` that turns `box profile create <name>` into a profile.
#[derive(Debug, Clone)]
pub(crate) struct Starter {
    pub(crate) name: String,
    pub(crate) label: String,
    pub(crate) packs: Vec<String>,
    pub(crate) options: Vec<(String, String)>,
    pub(crate) ask: Vec<String>,
    pub(crate) sources: Vec<Source>,
    pub(crate) questions: Vec<Question>,
    /// The policy starter that answers the policy question for each profile this starter writes.
    pub(crate) policy: Option<String>,
}

/// One question of a starter.
#[derive(Debug, Clone)]
pub(crate) struct Question {
    pub(crate) id: String,
    pub(crate) prompt: String,
    default: Option<usize>,
    pub(crate) when: Option<(String, String)>,
    pub(crate) choices: Vec<Choice>,
}

/// One answer to a question.
#[derive(Debug, Clone)]
pub(crate) struct Choice {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) packs: Vec<String>,
    pub(crate) options: Vec<(String, String)>,
    pub(crate) detect: Option<Detect>,
}

impl Choice {
    fn is_none(&self) -> bool {
        self.packs.is_empty()
    }
}

impl Question {
    fn none_choice(&self) -> Option<usize> {
        self.choices.iter().position(Choice::is_none)
    }
}

impl Starter {
    /// The starter `name`, from its `starter.toml`.
    pub(crate) fn load(name: &str, lookup: &Lookup) -> Result<Self, String> {
        let folder = starter_folder(lookup, name).ok_or_else(|| {
            let shipped = lang::renamed(name).filter(|shipped| {
                starter_folder(lookup, shipped)
                    .is_some_and(|folder| folder.join(STARTER_FILE).is_file())
            });
            match shipped {
                Some(shipped) => {
                    format!(
                        "{name:?} is not a starter name; the starter that box ships is {shipped}"
                    )
                }
                None => format!("{name:?} is not a starter name"),
            }
        })?;
        let path = folder.join(STARTER_FILE);
        let text = match read_unlinked(&folder, &path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!(
                    "the starter {name} does not exist: {} is missing",
                    path.display()
                ));
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let table: toml::Table =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        Self::parse(name, &table, lookup)
            .map_err(|reason| format!("the starter {name}: {}: {reason}", path.display()))
    }

    /// The starter `name`, whose `starter.toml` is `table`.
    pub(crate) fn parse(name: &str, table: &toml::Table, lookup: &Lookup) -> Result<Self, String> {
        known_keys(table, "starter.toml", &["starter", "source", "question"])?;
        let starter = match table.get("starter") {
            None => return Err("a starter needs a `[starter]` table".to_string()),
            Some(toml::Value::Table(starter)) => starter,
            Some(_) => return Err("`starter` is not a table".to_string()),
        };
        known_keys(
            starter,
            "[starter]",
            &["name", "label", "packs", "options", "ask", "policy"],
        )?;
        let written = required_string(starter, "name", "[starter]")?;
        if written != name {
            return Err(format!(
                "`[starter] name` is {written:?}, and the folder holds {name}"
            ));
        }
        let label = required_string(starter, "label", "[starter]")?;
        let policy = match starter.get("policy") {
            None => None,
            Some(toml::Value::String(name)) => {
                let starter = crate::policy_starter::PolicyStarter::find(name, lookup)
                    .map_err(|reason| format!("`[starter] policy`: {reason}"))?;
                Some(starter.name)
            }
            Some(_) => return Err("`[starter] policy` is not a policy name".to_string()),
        };
        let sources = detect::parse_sources(table.get("source"), lookup)?;
        let packs = pack_list(
            starter
                .get("packs")
                .ok_or("`[starter]` has no `packs`; name the packs each profile starts with")?,
            "[starter] packs",
            lookup,
        )?;
        let ask = match starter.get("ask") {
            None => Vec::new(),
            Some(value) => strings(value, "[starter] ask")?,
        };
        if let Some(name) = ask
            .iter()
            .find(|name| !name.contains('.') || name.split('.').any(|part| part.is_empty()))
        {
            return Err(format!(
                "`[starter] ask` names {name:?}; name an input as <namespace>.<key>"
            ));
        }
        let mut questions: Vec<Question> = Vec::new();
        let items = match table.get("question") {
            None => Vec::new(),
            Some(toml::Value::Array(items)) => items.clone(),
            Some(_) => return Err("`[[question]]` is not a list of tables".to_string()),
        };
        for item in &items {
            let question = parse_question(item, &questions, &sources, lookup)?;
            questions.push(question);
        }
        Ok(Self {
            name: name.to_string(),
            label,
            packs,
            options: options(starter.get("options"), "[starter] options")?,
            ask,
            sources,
            questions,
            policy,
        })
    }
}

fn parse_question(
    item: &toml::Value,
    earlier: &[Question],
    sources: &[Source],
    lookup: &Lookup,
) -> Result<Question, String> {
    let table = item
        .as_table()
        .ok_or("`[[question]]` is not a list of tables")?;
    known_keys(
        table,
        "[[question]]",
        &["id", "prompt", "default", "when", "choice"],
    )?;
    let id = required_string(table, "id", "[[question]]")?;
    let owner = format!("question {id:?}");
    if earlier.iter().any(|question| question.id == id) {
        return Err(format!("two questions have the id {id:?}"));
    }
    let prompt = required_string(table, "prompt", &owner)?;
    let when = match table.get("when") {
        None => None,
        Some(value) => Some(parse_when(value, &owner, earlier)?),
    };
    let mut choices: Vec<Choice> = Vec::new();
    let items = match table.get("choice") {
        Some(toml::Value::Array(items)) => items.clone(),
        None => Vec::new(),
        Some(_) => return Err(format!("the choices of {owner} are not a list of tables")),
    };
    for item in &items {
        let choice = item
            .as_table()
            .ok_or_else(|| format!("the choices of {owner} are not a list of tables"))?;
        known_keys(
            choice,
            "[[question.choice]]",
            &["id", "label", "packs", "options", "detect"],
        )?;
        let choice_id = required_string(choice, "id", &owner)?;
        let at = format!("choice {choice_id:?} of {owner}");
        if choices.iter().any(|known| known.id == choice_id) {
            return Err(format!("two choices of {owner} have the id {choice_id:?}"));
        }
        let packs = pack_list(
            choice
                .get("packs")
                .ok_or_else(|| format!("{at} has no `packs`"))?,
            &format!("{at} packs"),
            lookup,
        )?;
        let options = options(choice.get("options"), &format!("{at} options"))?;
        let detect = match choice.get("detect") {
            None => None,
            Some(value) => Some(detect::parse_detect(value, &at, sources)?),
        };
        if packs.is_empty() && !options.is_empty() {
            return Err(format!(
                "{at} adds no pack, so it is the none choice, and the none choice sets no options"
            ));
        }
        if let Some((pack, other)) = packs.iter().find_map(|pack| {
            choices
                .iter()
                .find(|known| known.packs.contains(pack))
                .map(|known| (pack, known))
        }) {
            return Err(format!(
                "choices {:?} and {choice_id:?} of {owner} both add {pack}, so `--with` cannot \
                 tell them apart",
                other.id
            ));
        }
        choices.push(Choice {
            id: choice_id.clone(),
            label: match choice.get("label") {
                None => choice_id,
                Some(toml::Value::String(text)) => text.clone(),
                Some(_) => return Err(format!("the label of {at} is not a string")),
            },
            packs,
            options,
            detect,
        });
    }
    let nones = choices.iter().filter(|choice| choice.is_none()).count();
    if nones > 1 {
        return Err(format!(
            "{owner} has {nones} choices that add no pack; a question has at most one"
        ));
    }
    if choices.len() < 2 && choices.iter().all(Choice::is_none) {
        return Err(format!(
            "{owner} needs two choices, or one choice that adds a pack"
        ));
    }
    let default = if table.contains_key("default") {
        let id = required_string(table, "default", &owner)?;
        let Some(index) = choices.iter().position(|choice| choice.id == id) else {
            return Err(format!(
                "the `default` of {owner} names an unknown choice {id:?}"
            ));
        };
        Some(index)
    } else {
        None
    };
    Ok(Question {
        id,
        prompt,
        default,
        when,
        choices,
    })
}

fn parse_when(
    value: &toml::Value,
    owner: &str,
    earlier: &[Question],
) -> Result<(String, String), String> {
    let table = value
        .as_table()
        .ok_or_else(|| format!("the `when` of {owner} is not a table"))?;
    known_keys(table, "when", &["variable", "equals"])?;
    let variable = required_string(table, "variable", &format!("the `when` of {owner}"))?;
    let equals = required_string(table, "equals", &format!("the `when` of {owner}"))?;
    let target = variable.strip_prefix("answers.").ok_or_else(|| {
        format!("the `when` of {owner} reads {variable:?}; a starter reads answers.<question id>")
    })?;
    let question = earlier
        .iter()
        .find(|question| question.id == target)
        .ok_or_else(|| {
            format!("the `when` of {owner} reads {variable:?}, and no earlier question has that id")
        })?;
    if !question.choices.iter().any(|choice| choice.id == equals) {
        return Err(format!(
            "the `when` of {owner} compares with {equals:?}, which is not a choice of question \
             {target:?}; its choices are {}",
            question
                .choices
                .iter()
                .map(|choice| choice.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok((target.to_string(), equals))
}

fn known_keys(table: &toml::Table, owner: &str, known: &[&str]) -> Result<(), String> {
    match table.keys().find(|key| !known.contains(&key.as_str())) {
        Some(key) => Err(format!(
            "`{owner}` holds the unknown key `{key}`; it holds {}",
            known
                .iter()
                .map(|key| format!("`{key}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        None => Ok(()),
    }
}

fn required_string(table: &toml::Table, key: &str, owner: &str) -> Result<String, String> {
    match table.get(key) {
        Some(toml::Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(_) => Err(format!("the `{key}` of {owner} is not a string")),
        None => Err(format!("{owner} has no `{key}`")),
    }
}

fn strings(value: &toml::Value, owner: &str) -> Result<Vec<String>, String> {
    value
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| format!("`{owner}` is not a list of strings"))
}

fn pack_list(value: &toml::Value, owner: &str, lookup: &Lookup) -> Result<Vec<String>, String> {
    let mut packs = Vec::new();
    for pack in strings(value, owner)? {
        let pack = lookup.full_name(&pack)?;
        if !packs.contains(&pack) {
            packs.push(pack);
        }
    }
    Ok(packs)
}

fn options(value: Option<&toml::Value>, owner: &str) -> Result<Vec<(String, String)>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let table = value
        .as_table()
        .ok_or_else(|| format!("`{owner}` is not a table"))?;
    table
        .iter()
        .map(|(name, value)| {
            let value = match value {
                toml::Value::String(text) => text.clone(),
                toml::Value::Boolean(flag) => flag.to_string(),
                toml::Value::Integer(number) => number.to_string(),
                _ => {
                    return Err(format!(
                        "`{owner}` sets {name:?} to a value that is not a string, a number, or \
                         true or false"
                    ));
                }
            };
            Ok((name.clone(), value))
        })
        .collect()
}

/// The terminal the create step asks on.
pub struct Terminal<'a> {
    /// What the operator types.
    pub(crate) input: &'a mut dyn BufRead,
    /// Where the questions go.
    pub(crate) output: &'a mut dyn Write,
    pub(crate) choice_controls: bool,
    pub(crate) choice_color: bool,
    pub(crate) can_go_back: bool,
    pub(crate) content: Option<String>,
    pub(crate) session: Option<crate::prompt::Session>,
}

impl<'a> Terminal<'a> {
    /// A line-based prompt for the supplied input and output.
    pub fn new(input: &'a mut dyn BufRead, output: &'a mut dyn Write) -> Self {
        Self {
            input,
            output,
            choice_controls: false,
            choice_color: false,
            can_go_back: false,
            content: None,
            session: None,
        }
    }

    /// This prompt has a parent menu.
    pub fn with_back(mut self) -> Self {
        self.can_go_back = true;
        self
    }

    /// Keep the content above the choices, with scrolling on a capable terminal.
    pub fn with_content(mut self, content: String) -> Self {
        if self.choice_controls {
            self.content = Some(content);
        } else {
            let _ = write!(self.output, "{content}");
        }
        self
    }

    pub(crate) fn question(&mut self, text: &str) {
        if let Some(session) = &mut self.session {
            session.details = format!("{text}\n\n");
            session.feedback.clear();
            return;
        }
        if self.choice_controls {
            let title = if self.choice_color {
                format!(
                    "\x1b[1;{}mbox:\x1b[0m \x1b[1m{text}\x1b[0m",
                    crate::Report::ACCENT
                )
            } else {
                format!("box: {text}")
            };
            self.detail(&format!("\n  {title}\n\n"));
        } else {
            let _ = writeln!(self.output, "{text}");
        }
    }

    pub(crate) fn stage(&mut self, name: &str, stage: usize) {
        if let Some(session) = &mut self.session {
            session.name = name.to_string();
            session.stage = stage;
            session.section();
        }
    }

    pub(crate) fn detail(&mut self, text: &str) {
        if let Some(session) = &mut self.session {
            session.details.push_str(text);
        } else if let Some(content) = &mut self.content {
            content.push_str(text);
        } else {
            let _ = write!(self.output, "{text}");
        }
    }

    pub(crate) fn feedback(&mut self, text: &str) {
        if let Some(session) = &mut self.session {
            session.feedback = text.to_string();
        } else if let Some(content) = &mut self.content {
            content.insert_str(0, text);
        } else {
            let _ = write!(self.output, "{text}");
        }
    }

    fn accept(&mut self, value: String) {
        if let Some(session) = &mut self.session {
            session.accept(value);
        }
    }

    /// Ask for a destructive action, with Keep selected by default.
    pub fn confirm(&mut self, question: &str) -> Result<(), Error> {
        if !self.choice_controls {
            if self.can_go_back {
                let _ = write!(self.output, "{question} [y/N] (back to return) ");
                return match read_line(self)?
                    .map(|line| line.to_ascii_lowercase())
                    .as_deref()
                {
                    Some("y" | "yes") => Ok(()),
                    _ => Err(Error::Kept),
                };
            }
            return crate::run::confirm(question, true, &mut self.input, &mut self.output);
        }
        self.question(question);
        match crate::prompt::described(
            self,
            &["Keep", "Remove"],
            &["Cancel without changes.", "Delete the items listed above."],
            Some(0),
        )?
        .map(|answer| answer.to_ascii_lowercase())
        .as_deref()
        {
            Some("2" | "y" | "yes") => Ok(()),
            _ => Err(Error::Kept),
        }
    }

    /// Ask the operator to pick one of `choices`, the first by default. Cancel stops with
    /// [`Error::StarterAborted`].
    pub(crate) fn pick(&mut self, question: &str, choices: &[&str]) -> Result<usize, Error> {
        self.question(question);
        self.pick_choice(question, choices)
    }

    /// Introduce an interactive command and its help.
    pub fn intro(&mut self, title: &str, help: &str) {
        self.question(title);
        let tip = crate::Report::new(false, false)
            .wrap(&format!("Tip: Run {help} for all commands and options."), 2);
        if self.choice_controls && self.choice_color {
            self.detail(&format!("  \x1b[2m{tip}\x1b[0m\n\n"));
        } else {
            self.detail(&format!("  {tip}\n\n"));
        }
    }

    /// Pick a command or profile, with a help tip.
    pub fn menu(&mut self, title: &str, help: &str, choices: &[&str]) -> Result<usize, Error> {
        self.intro(title, help);
        self.pick_choice(title, choices)
    }

    /// Pick one of `choices` without a heading.
    pub fn pick_choice(&mut self, question: &str, choices: &[&str]) -> Result<usize, Error> {
        self.pick_described(question, choices, &[], 0)
    }

    /// Pick a choice with details, starting at the previously selected row.
    pub fn pick_described(
        &mut self,
        question: &str,
        choices: &[&str],
        descriptions: &[&str],
        selected: usize,
    ) -> Result<usize, Error> {
        for (number, choice) in choices.iter().enumerate() {
            if !self.choice_controls {
                let _ = writeln!(self.output, "  {}. {choice}", number + 1);
                if let Some(description) = descriptions.get(number) {
                    let _ = writeln!(self.output, "     {description}");
                }
            }
        }
        loop {
            let line = if self.choice_controls {
                crate::prompt::act(self, choices, descriptions, selected)?
            } else {
                let _ = write!(
                    self.output,
                    "{}> [{}] ",
                    if self.can_go_back {
                        "Type back to return. "
                    } else {
                        ""
                    },
                    selected + 1,
                );
                read_line(self)?
            };
            let Some(line) = line else {
                return Err(Error::StarterAborted {
                    question: question.to_string(),
                });
            };
            let picked = match line.parse::<usize>() {
                _ if line.is_empty() => selected + 1,
                Ok(number) if (1..=choices.len()).contains(&number) => number,
                _ => {
                    self.feedback(&format!("Type a number from 1 to {}.\n", choices.len()));
                    continue;
                }
            };
            self.accept(picked.to_string());
            return Ok(picked - 1);
        }
    }

    /// Ask the operator for one line of text. Cancel stops with [`Error::StarterAborted`].
    pub(crate) fn line(&mut self, question: &str) -> Result<String, Error> {
        self.question(question);
        let line = if self.choice_controls {
            crate::prompt::text(self)?
        } else {
            let _ = write!(self.output, "> ");
            read_line(self)?
        };
        let line = line.ok_or_else(|| Error::StarterAborted {
            question: question.to_string(),
        })?;
        self.accept(line.clone());
        Ok(line)
    }

    pub(crate) fn profile_name(
        &mut self,
        question: &str,
        names: &[&str],
        descriptions: &[&str],
    ) -> Result<String, Error> {
        if !self.choice_controls {
            let answer = self.line(question)?;
            return Ok(if names.contains(&answer.as_str()) {
                format!("\0{answer}")
            } else {
                answer
            });
        }
        self.question(question);
        let answer = crate::prompt::profile_name(self, names, descriptions)?.ok_or_else(|| {
            Error::StarterAborted {
                question: question.to_string(),
            }
        })?;
        self.accept(answer.clone());
        Ok(answer)
    }

    /// Prompts on standard input and standard error, with keys on a capable terminal.
    pub fn stdio(input: &'a mut std::io::StdinLock<'_>, output: &'a mut std::io::Stderr) -> Self {
        let choice_controls = input.is_terminal()
            && output.is_terminal()
            && std::env::var_os("TERM").is_some_and(|term| term != "dumb" && !term.is_empty());
        Self {
            input,
            output,
            choice_controls,
            choice_color: std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty()),
            can_go_back: false,
            content: None,
            session: None,
        }
    }
}

/// What a starter, the flags, and the operator's answers give a new profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answered {
    pub(crate) packs: Vec<String>,
    pub(crate) options: Vec<(String, String)>,
    /// The lines of the create report's `Detected` block.
    pub(crate) detected: Vec<Line>,
    /// The policy starter that `[starter] policy` names.
    pub(crate) policy: Option<String>,
}

/// The facts the create step answers a starter with.
pub(crate) struct Request<'a> {
    pub(crate) name: &'a str,
    pub(crate) with: &'a [String],
    pub(crate) options: &'a [(String, String)],
    pub(crate) lookup: &'a Lookup,
    pub(crate) path: &'a Path,
    /// Refuse before the first prompt: the profile exists, and `--force` is not given.
    pub(crate) exists: bool,
    /// The host that a starter's sources read.
    pub(crate) host: &'a Host,
    /// The current directory, which a source never reads.
    pub(crate) workspace: &'a Path,
}

/// The starter that a request selects: a `--with` entry that names a starter, else the profile
/// name.
pub(crate) fn select(menu: &Menu, request: &Request<'_>) -> Result<Option<String>, Error> {
    let mut selected: Option<String> = None;
    for entry in request.with {
        let Some(pack) = starter_entry(menu, request, entry)? else {
            continue;
        };
        if let Some(first) = &selected
            && *first != pack
        {
            return Err(profile_error(
                request,
                format!("`--with` names two starters, {first} and {pack}; name one"),
            ));
        }
        selected = Some(pack);
    }
    Ok(selected.or_else(|| menu.named(request.lookup, request.name).map(str::to_string)))
}

/// The starter that the `--with` entry `entry` names, when the menu holds it. Any other entry is
/// a pack, and must exist.
fn starter_entry(menu: &Menu, request: &Request<'_>, entry: &str) -> Result<Option<String>, Error> {
    if let Some(starter) = menu.named(request.lookup, entry) {
        return Ok(Some(starter.to_string()));
    }
    full(request, entry)?;
    Ok(None)
}

fn full(request: &Request<'_>, entry: &str) -> Result<String, Error> {
    request
        .lookup
        .full_name(entry)
        .map_err(|reason| profile_error(request, reason))
}

fn profile_error(request: &Request<'_>, reason: String) -> Error {
    Error::Profile {
        path: request.path.to_path_buf(),
        line: None,
        reason,
    }
}

/// Answer `starter` from the flags, then from the terminal.
pub(crate) fn answer(
    starter: &Starter,
    request: &Request<'_>,
    mut terminal: Option<&mut Terminal<'_>>,
    saved: Option<&crate::Profile>,
) -> Result<Answered, Error> {
    let command = format!("box profile create {}", request.name);
    let saved_declarations = match saved {
        Some(profile) => Some(lang::merge(&profile.layers(None, request.lookup)?)?.declarations),
        None => None,
    };
    for (index, (name, _)) in request.options.iter().enumerate() {
        if request.options[..index]
            .iter()
            .any(|(earlier, _)| earlier == name)
        {
            return Err(Error::OptionFlag {
                option: name.clone(),
                reason: "is given twice",
            });
        }
    }
    let mut extras: Vec<String> = Vec::new();
    for entry in request.with {
        if saved.is_none() && resolve(request.lookup, entry).as_ref() == Some(&starter.name) {
            continue;
        }
        let pack = full(request, entry)?;
        if !extras.contains(&pack) {
            extras.push(pack);
        }
    }
    let stands_for = |pack: &str, listed: &str| stands_for(request.lookup, pack, listed);
    let in_place = |listed: &String| {
        extras
            .iter()
            .find(|pack| stands_for(pack, listed))
            .unwrap_or(listed)
            .clone()
    };
    let mut answers: Vec<Option<usize>> = vec![None; starter.questions.len()];
    let inferred = if saved.is_some() {
        lang::imported(request.lookup, &extras).map_err(|reason| profile_error(request, reason))?
    } else {
        extras.clone()
    };
    for pack in &inferred {
        let matches: Vec<(usize, usize)> = starter
            .questions
            .iter()
            .enumerate()
            .filter_map(|(question, item)| {
                item.choices
                    .iter()
                    .position(|choice| choice.packs.iter().any(|listed| stands_for(pack, listed)))
                    .map(|choice| (question, choice))
            })
            .collect();
        match matches.as_slice() {
            [] => {}
            [(question, choice)] => match answers[*question] {
                Some(earlier) if earlier != *choice => {
                    let item = &starter.questions[*question];
                    return Err(profile_error(
                        request,
                        format!(
                            "`--with` answers {:?} twice, with {:?} and {:?}",
                            item.prompt, item.choices[earlier].id, item.choices[*choice].id
                        ),
                    ));
                }
                _ => answers[*question] = Some(*choice),
            },
            several => {
                return Err(profile_error(
                    request,
                    format!(
                        "`--with {}` answers more than one question: {}",
                        request.lookup.spelling(pack),
                        several
                            .iter()
                            .map(|(question, _)| format!(
                                "{:?}",
                                starter.questions[*question].prompt
                            ))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
        }
    }
    let saved_answers = answers.clone();
    let refuse_inherited_change = |index: usize, answer| {
        if saved_answers[index] != answer
            && let Some(previous) = saved_answers[index]
        {
            for root in &extras {
                let inherited = lang::imported(request.lookup, std::slice::from_ref(root))
                    .map_err(|reason| profile_error(request, reason))?;
                for pack in &starter.questions[index].choices[previous].packs {
                    if !stands_for(root, pack)
                        && inherited.iter().any(|name| stands_for(name, pack))
                    {
                        return Err(profile_error(
                            request,
                            format!(
                                "{pack} comes from a custom pack; change that pack before changing this answer"
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    };
    let mut saved_values = std::collections::BTreeMap::new();
    if let Some(values) = saved.and_then(|profile| profile.table.get("options")) {
        lang::collect_values(values, &mut Vec::new(), &mut saved_values)
            .map_err(|reason| profile_error(request, reason))?;
    }
    let readings = match terminal
        .as_ref()
        .and_then(|terminal| terminal.session.as_ref())
        .and_then(|session| session.readings.as_ref())
        .filter(|(name, _)| *name == starter.name)
        .map(|(_, readings)| readings.clone())
    {
        Some(readings) => readings,
        None => {
            let readings = read_sources(starter, &extras, request, saved)?;
            if let Some(session) = terminal
                .as_mut()
                .and_then(|terminal| terminal.session.as_mut())
            {
                session.readings = Some((starter.name.clone(), readings.clone()));
            }
            readings
        }
    };
    let reviewing = terminal
        .as_ref()
        .and_then(|terminal| terminal.session.as_ref())
        .is_some_and(|session| session.reviewing);
    let mut lines: Vec<(usize, Line)> = Vec::new();
    let mut asked = false;
    let refuse = |asked: &mut bool| -> Result<(), Error> {
        if !*asked && request.exists {
            return Err(Error::Exists {
                path: request.path.to_path_buf(),
            });
        }
        *asked = true;
        Ok(())
    };
    for index in 0..starter.questions.len() {
        let question = &starter.questions[index];
        if let Some((target, equals)) = &question.when {
            let holds = starter
                .questions
                .iter()
                .position(|earlier| earlier.id == *target)
                .and_then(|earlier| answers[earlier].map(|choice| (earlier, choice)))
                .is_some_and(|(earlier, choice)| {
                    starter.questions[earlier].choices[choice].id == *equals
                });
            if !holds {
                if saved.is_some() {
                    refuse_inherited_change(index, None)?;
                    answers[index] = None;
                    continue;
                }
                if let Some(choice) = answers[index] {
                    return Err(profile_error(
                        request,
                        format!(
                            "`--with {}` answers {:?}, which this starter asks only when \
                             question {target:?} is answered {equals:?}",
                            request.lookup.spelling(&question.choices[choice].packs[0]),
                            question.prompt
                        ),
                    ));
                }
                continue;
            }
        }
        if saved.is_some() {
            if let Some(terminal) = terminal.as_deref_mut() {
                let preset = answers[index].or_else(|| question.none_choice());
                answers[index] = Some(ask_question(question, terminal, preset)?);
                refuse_inherited_change(index, answers[index])?;
            }
            continue;
        }
        if answers[index].is_some() {
            continue;
        }
        // A detected choice is only the default: at a terminal the question still lists every
        // choice, so an answer that detection cannot see, such as an API key, stays in view.
        if let Some(choice) = detect_choice(starter, question, &readings, &mut lines) {
            answers[index] = Some(choice);
            if let Some(terminal) = terminal.as_deref_mut() {
                refuse(&mut asked)?;
                let choice = ask_question(question, terminal, Some(choice))?;
                answers[index] = Some(choice);
                if let Some((_, line)) = lines.last_mut() {
                    line.answer = Some(question.choices[choice].label.clone());
                }
            }
            continue;
        }
        if question.choices.len() == 1 {
            answers[index] = Some(0);
            continue;
        }
        if let Some(terminal) = terminal.as_deref_mut() {
            refuse(&mut asked)?;
            answers[index] = Some(ask_question(question, terminal, question.default)?);
            continue;
        }
        if let Some(choice) = question.default.or_else(|| question.none_choice()) {
            answers[index] = Some(choice);
            continue;
        }
        let rows: Vec<(String, String)> = question
            .choices
            .iter()
            .map(|choice| {
                (
                    format!("--with {}", request.lookup.spelling(&choice.packs[0])),
                    choice.label.clone(),
                )
            })
            .collect();
        return Err(Error::StarterUnanswered {
            command,
            question: question.prompt.clone(),
            flags: columns(&rows),
        });
    }
    let mut changed_options = Vec::new();
    for (index, question) in starter.questions.iter().enumerate() {
        if saved.is_none() || saved_answers[index] == answers[index] {
            continue;
        }
        for choice in saved_answers[index].into_iter().chain(answers[index]) {
            changed_options.extend(
                question.choices[choice]
                    .options
                    .iter()
                    .map(|(name, _)| name),
            );
        }
    }
    let mut packs = if saved.is_some() {
        Vec::new()
    } else {
        starter.packs.clone()
    };
    let mut options = if saved.is_some() {
        saved_values
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    } else {
        starter.options.clone()
    };
    options.retain(|(name, _)| !changed_options.contains(&name));
    for (index, question) in starter.questions.iter().enumerate() {
        let Some(choice) = answers[index] else {
            continue;
        };
        let choice = &question.choices[choice];
        if saved.is_none() || saved_answers[index] != answers[index] {
            for pack in choice.packs.iter().map(in_place) {
                if !packs.contains(&pack) {
                    packs.push(pack);
                }
            }
        }
        for (name, value) in &choice.options {
            if saved.is_none() || changed_options.contains(&name) {
                set(&mut options, name, value);
            }
        }
    }
    for pack in extras {
        if saved.is_some()
            && starter
                .questions
                .iter()
                .enumerate()
                .any(|(index, question)| {
                    saved_answers[index] != answers[index]
                        && question.choices.iter().any(|choice| {
                            choice.packs.iter().any(|listed| stands_for(&pack, listed))
                        })
                })
        {
            continue;
        }
        if !packs.contains(&pack) {
            packs.push(pack);
        }
    }
    if let Some(saved) = saved {
        let mut ordered = saved.packs();
        ordered.retain(|pack| packs.contains(pack));
        let inherited = lang::imported(request.lookup, &ordered)
            .map_err(|reason| profile_error(request, reason))?;
        for pack in packs {
            if !inherited.contains(&pack) && !ordered.contains(&pack) {
                ordered.push(pack);
            }
        }
        packs = ordered;
    }
    let flagged: Vec<&str> = request
        .options
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    let selected = layers(&packs, request, saved)?;
    let declarations = lang::merge(&selected)?.declarations;
    let applies = |source: &Source| {
        source.pack.as_ref().is_none_or(|pack| {
            selected
                .iter()
                .any(|layer| layer.shared && stands_for(&layer.name, pack))
        })
    };
    if saved.is_some() {
        options.retain(|(name, _)| declarations.contains_key(name));
    }
    let has_value = |name: &str, options: &[(String, String)]| {
        flagged.contains(&name) || options.iter().any(|(known, _)| known == name)
    };
    for (index, source) in starter.sources.iter().enumerate() {
        let Some(name) = &source.input else {
            continue;
        };
        let Some(declaration) = declarations.get(name) else {
            continue;
        };
        if !applies(source)
            || has_value(name, &options)
            || saved_declarations
                .as_ref()
                .is_some_and(|declarations| declarations.contains_key(name))
        {
            continue;
        }
        if let Some(mut value) = detect_input(source, name, declaration, &readings[index])
            .map_err(|reason| profile_error(request, reason))?
            .and_then(|(value, line)| {
                lines.push((index, line));
                value
            })
        {
            if reviewing && let Some(terminal) = terminal.as_deref_mut() {
                refuse(&mut asked)?;
                if let Some(answer) = ask_input(name, declaration, terminal, Some(&value))? {
                    value = answer;
                }
                if let Some((_, line)) = lines.last_mut() {
                    line.answer = Some(value.clone());
                }
            }
            set(&mut options, name, &value);
        }
    }
    let mut wanted: Vec<&str> = declarations
        .iter()
        .filter(|(_, declaration)| {
            declaration.default_value().is_none() && !declaration.reads_host()
        })
        .map(|(name, _)| name.as_str())
        .collect();
    for name in &starter.ask {
        if declarations
            .get(name)
            .is_some_and(|declaration| !declaration.reads_host())
            && !wanted.contains(&name.as_str())
        {
            wanted.push(name);
        }
    }
    for (name, declaration) in &declarations {
        if !declaration.warnings().is_empty() && !wanted.contains(&name.as_str()) {
            wanted.push(name);
        }
    }
    for name in saved_values.keys() {
        if declarations
            .get(name)
            .is_some_and(|declaration| !declaration.reads_host())
            && !wanted.contains(&name.as_str())
            && !starter
                .questions
                .iter()
                .flat_map(|question| &question.choices)
                .any(|choice| choice.options.iter().any(|(option, _)| option == name))
        {
            wanted.push(name);
        }
    }
    for name in wanted {
        if saved.is_some()
            && !flagged.contains(&name)
            && let Some(terminal) = terminal.as_deref_mut()
        {
            let preset = options
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone());
            if let Some(value) = ask_input(name, &declarations[name], terminal, preset.as_deref())?
            {
                set(&mut options, name, &value);
            }
            continue;
        }
        if has_value(name, &options) {
            continue;
        }
        let declaration = &declarations[name];
        if let Some(terminal) = terminal.as_deref_mut() {
            refuse(&mut asked)?;
            if let Some(value) = ask_input(name, declaration, terminal, None)? {
                set(&mut options, name, &value);
            }
            continue;
        }
        if let Some(default) = declaration.default_value() {
            if !declaration.warnings().is_empty() {
                set(&mut options, name, default);
            }
            continue;
        }
        if declaration.reads_host() {
            continue;
        }
        let allowed = declaration.allowed();
        let rows: Vec<(String, String)> = if allowed.is_empty() {
            vec![(
                format!("--option {name}=<value>"),
                declaration.description().unwrap_or_default().to_string(),
            )]
        } else {
            allowed
                .iter()
                .map(|value| (format!("--option {name}={value}"), String::new()))
                .collect()
        };
        return Err(Error::StarterUnanswered {
            command,
            question: declaration.description().unwrap_or(name).to_string(),
            flags: columns(&rows),
        });
    }
    for (name, value) in request.options {
        set(&mut options, name, value);
    }
    for (index, reading) in readings.iter().enumerate() {
        if !applies(&starter.sources[index]) {
            continue;
        }
        for reason in &reading.skipped {
            lines.push((
                index,
                Line {
                    label: starter.sources[index].label.clone(),
                    answer: None,
                    text: reason.clone(),
                },
            ));
        }
    }
    lines.sort_by_key(|(index, _)| *index);
    Ok(Answered {
        packs,
        options,
        policy: starter.policy.clone(),
        detected: lines.into_iter().map(|(_, line)| line).collect(),
    })
}

/// Whether the `--with` pack `pack` takes the place of the choice pack `listed`: it is that pack,
/// or the operator's own pack of the same short name.
fn stands_for(lookup: &Lookup, pack: &str, listed: &str) -> bool {
    pack == listed || (lookup.shadows(pack) && listed.strip_prefix(lang::VENDORED) == Some(pack))
}

/// Read each source once, after checking credentials and write grants in every candidate layer.
fn read_sources(
    starter: &Starter,
    extras: &[String],
    request: &Request<'_>,
    saved: Option<&crate::Profile>,
) -> Result<Vec<Reading>, Error> {
    if starter.sources.is_empty() {
        return Ok(Vec::new());
    }
    let mut candidates = saved.map_or_else(|| starter.packs.clone(), crate::Profile::packs);
    for pack in starter
        .questions
        .iter()
        .flat_map(|question| &question.choices)
        .flat_map(|choice| &choice.packs)
        .map(|listed| {
            extras
                .iter()
                .find(|pack| stands_for(request.lookup, pack, listed))
                .unwrap_or(listed)
        })
        .chain(extras)
    {
        if !candidates.contains(pack) {
            candidates.push(pack.clone());
        }
    }
    let mut credentials = crate::reference::Credentials::default();
    let mut refusals = crate::storage_files::Refusals {
        home: request.host.home.clone(),
        roots: Vec::new(),
        shipped: None,
        protected: Vec::new(),
    };
    for layer in layers(&candidates, request, saved)? {
        let mut table = layer.table;
        for key in ["pack", "packs", "extends", "inputs", "policies"] {
            table.remove(key);
        }
        let denied = detect::refusals(
            &table,
            &request.host.home,
            &request.host.box_home,
            request.workspace,
        );
        for root in denied.roots {
            if !refusals.roots.contains(&root) {
                refusals.roots.push(root);
            }
        }
        credentials = credentials.join(crate::reference::Credentials::of_file(&table, &layer.name));
    }
    refusals.protected = credentials.protected(&request.host.home);
    if let Some(reason) = detect::credential_place(&starter.sources, &credentials) {
        return Err(profile_error(request, reason));
    }
    Ok(starter
        .sources
        .iter()
        .map(|source| detect::read(source, request.host, &refusals))
        .collect())
}

/// The one choice of `question` whose `detect` holds, if exactly one holds. A source that gives a
/// value which picks no choice, or more than one, adds a line that names only its place.
fn detect_choice(
    starter: &Starter,
    question: &Question,
    readings: &[Reading],
    lines: &mut Vec<(usize, Line)>,
) -> Option<usize> {
    let source_of = |id: &str| starter.sources.iter().position(|source| source.id == id);
    let mut held: Vec<(usize, usize)> = Vec::new();
    let mut read: Vec<usize> = Vec::new();
    for (index, choice) in question.choices.iter().enumerate() {
        let Some(detect) = &choice.detect else {
            continue;
        };
        let Some(source) = source_of(&detect.source) else {
            continue;
        };
        let Some((value, _)) = &readings[source].value else {
            continue;
        };
        if !read.contains(&source) {
            read.push(source);
        }
        if detect.equals.contains(value) {
            held.push((index, source));
        }
    }
    if let [(choice, source)] = held.as_slice() {
        let place = readings[*source]
            .value
            .as_ref()
            .map(|(_, place)| place.clone())
            .unwrap_or_default();
        lines.push((
            *source,
            Line {
                label: starter.sources[*source].label.clone(),
                answer: Some(question.choices[*choice].label.clone()),
                text: place,
            },
        ));
        return Some(*choice);
    }
    let why = match held.len() {
        0 => "matches no choice",
        _ => "matches more than one choice",
    };
    for source in read {
        if let Some((_, place)) = &readings[source].value {
            lines.push((
                source,
                Line {
                    label: starter.sources[source].label.clone(),
                    answer: None,
                    text: format!("{place} {why}"),
                },
            ));
        }
    }
    None
}

/// The value `source` gives the input `name`, with its report line, or why the step stops. A
/// `bool` input is `true` when the value is one of `equals`, else `false`. A `string` input takes
/// the value only when `check_value` accepts it. The value itself is never in a line.
fn detect_input(
    source: &Source,
    name: &str,
    declaration: &Declaration,
    reading: &Reading,
) -> Result<Option<(Option<String>, Line)>, String> {
    let owner = format!("source {:?}", source.id);
    if declaration.kind == "bool" {
        if source.equals.is_empty() {
            return Err(format!(
                "{owner} fills the `bool` input {name}, so it has `equals`"
            ));
        }
    } else if !source.equals.is_empty() {
        return Err(format!(
            "{owner} has `equals`, but {name} is not `bool`; `equals` is only for a `bool` input"
        ));
    } else if declaration.kind != "string" || !declaration.is_bounded() {
        return Err(format!(
            "{owner} fills {name}, which has no `pattern` or `values`; detection fills only a \
             bounded `string` input or a `bool` input"
        ));
    }
    let Some((value, place)) = &reading.value else {
        return Ok(None);
    };
    let line = |answer: Option<String>, text: String| Line {
        label: source.label.clone(),
        answer,
        text,
    };
    if declaration.kind == "bool" {
        let value = source.equals.contains(value).to_string();
        return Ok(Some((
            Some(value.clone()),
            line(Some(value), place.clone()),
        )));
    }
    if lang::check_value(name, declaration, value).is_err() {
        return Ok(Some((
            None,
            line(None, format!("{place} is not a valid {name}")),
        )));
    }
    Ok(Some((
        Some(value.clone()),
        line(Some(value.clone()), place.clone()),
    )))
}

/// The answer to each input of `packs` that has a `warning` and no `--option` value, for a profile
/// that no starter answers. At a terminal the step asks; without one, it records the default.
pub(crate) fn answer_warnings(
    packs: &[String],
    request: &Request<'_>,
    mut terminal: Option<&mut Terminal<'_>>,
) -> Result<Vec<(String, String)>, Error> {
    let declarations = merged(packs, request, None)?.declarations;
    let mut options = Vec::new();
    for (name, declaration) in &declarations {
        if declaration.warnings().is_empty()
            || request.options.iter().any(|(known, _)| known == name)
        {
            continue;
        }
        match terminal.as_deref_mut() {
            Some(terminal) => {
                if options.is_empty() && request.exists {
                    return Err(Error::Exists {
                        path: request.path.to_path_buf(),
                    });
                }
                if let Some(value) = ask_input(name, declaration, terminal, None)? {
                    set(&mut options, name, &value);
                }
            }
            None => {
                if let Some(default) = declaration.default_value() {
                    set(&mut options, name, default);
                }
            }
        }
    }
    Ok(options)
}

/// Set `name` to `value`, in place of an earlier value.
fn set(options: &mut Vec<(String, String)>, name: &str, value: &str) {
    match options.iter_mut().find(|(known, _)| known == name) {
        Some((_, old)) => *old = value.to_string(),
        None => options.push((name.to_string(), value.to_string())),
    }
}

/// The merged `packs`, with the inputs they declare.
fn merged(
    packs: &[String],
    request: &Request<'_>,
    saved: Option<&crate::Profile>,
) -> Result<lang::Merged, Error> {
    lang::merge(&layers(packs, request, saved)?)
}

fn layers(
    packs: &[String],
    request: &Request<'_>,
    saved: Option<&crate::Profile>,
) -> Result<Vec<lang::Layer>, Error> {
    let mut table = saved
        .map(|profile| profile.table.clone())
        .unwrap_or_default();
    table.remove("options");
    table.insert(
        "packs".to_string(),
        toml::Value::Array(packs.iter().cloned().map(toml::Value::String).collect()),
    );
    lang::chain(&table, "", request.path, None, request.lookup)
}

/// Two aligned columns, one row for each line, each line indented by two spaces.
pub(crate) fn columns(rows: &[(String, String)]) -> String {
    let width = rows.iter().map(|(left, _)| left.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(left, right)| {
            if right.is_empty() {
                format!("  {left}")
            } else {
                format!("  {left:<width$}   {right}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One line from the operator, or `None` for Esc or Back.
fn read_line(terminal: &mut Terminal<'_>) -> Result<Option<String>, Error> {
    let _ = terminal.output.flush();
    let mut line = String::new();
    let read = terminal
        .input
        .read_line(&mut line)
        .map_err(|source| io_error("read", Path::new("stdin"), source))?;
    if read == 0 || line.contains(['\x03', '\x04']) {
        return Err(Error::Interrupted);
    }
    let line = line.trim();
    Ok((line != "\x1b" && !(terminal.can_go_back && line == "back")).then(|| line.to_string()))
}

/// Ask `question` until the operator picks a choice. The none choice is listed first. Enter
/// answers `preset`, else the none choice.
fn ask_question(
    question: &Question,
    terminal: &mut Terminal<'_>,
    preset: Option<usize>,
) -> Result<usize, Error> {
    let none = question.none_choice();
    let order: Vec<usize> = none
        .into_iter()
        .chain((0..question.choices.len()).filter(|index| Some(*index) != none))
        .collect();
    let default = preset
        .or(none)
        .and_then(|choice| order.iter().position(|index| *index == choice));
    terminal.question(&question.prompt);
    for (number, index) in order
        .iter()
        .enumerate()
        .filter(|_| !terminal.choice_controls)
    {
        let _ = writeln!(
            terminal.output,
            "  {}. {}",
            number + 1,
            question.choices[*index].label
        );
    }
    let labels: Vec<&str> = order
        .iter()
        .map(|index| question.choices[*index].label.as_str())
        .collect();
    let number = loop {
        let line = if terminal.choice_controls {
            crate::prompt::choose(terminal, &labels, default)?
        } else {
            match default {
                Some(default) => write!(terminal.output, "> [{}] ", default + 1),
                None => write!(terminal.output, "> "),
            }
            .ok();
            read_line(terminal)?
        };
        let Some(line) = line else {
            return Err(Error::StarterAborted {
                question: question.prompt.clone(),
            });
        };
        if line.is_empty()
            && let Some(default) = default
        {
            break default + 1;
        }
        match line.parse::<usize>() {
            Ok(number) if (1..=order.len()).contains(&number) => break number,
            _ => {
                terminal.feedback(&format!("Type a number from 1 to {}.\n", order.len()));
            }
        }
    };
    terminal.accept(number.to_string());
    Ok(order[number - 1])
}

/// Ask for the input `name` until the answer is valid. Enter keeps the default, and returns
/// `None`, so the profile does not repeat what a pack says. An input with a `warning` returns
/// each answer, the default included, so the profile records it.
fn ask_input(
    name: &str,
    declaration: &Declaration,
    terminal: &mut Terminal<'_>,
    preset: Option<&str>,
) -> Result<Option<String>, Error> {
    let default = preset.or(declaration.default_value());
    let record = !declaration.warnings().is_empty();
    let kept = |value: &str| record.then(|| value.to_string());
    let allowed = declaration.allowed();
    let boolean = declaration.kind == "bool";
    let label = |value: &str| match (boolean, value) {
        (true, "true") => "Yes".to_string(),
        (true, "false") => "No".to_string(),
        _ => value.to_string(),
    };
    let description = declaration.description().unwrap_or_default();
    let heading = if description.is_empty() {
        name.to_string()
    } else if boolean {
        description.trim_end_matches('.').to_string()
    } else {
        format!("{} ({name})", description.trim_end_matches('.'))
    };
    terminal.question(&heading);
    if record && !terminal.choice_controls {
        let _ = writeln!(terminal.output);
    }
    for warning in declaration.warnings() {
        for line in warning.lines() {
            let marker = if terminal.choice_controls
                && terminal.choice_color
                && terminal.session.is_none()
            {
                "\x1b[33m!\x1b[0m"
            } else {
                "!"
            };
            terminal.detail(&format!("  {marker} {line}\n"));
        }
    }
    if record {
        terminal.detail("\n");
    }
    if !terminal.choice_controls {
        for (number, value) in allowed.iter().enumerate() {
            let _ = writeln!(terminal.output, "  {}. {}", number + 1, label(value));
        }
    }
    let labels: Vec<&str> = allowed.iter().map(String::as_str).collect();
    if terminal.choice_controls
        && allowed.is_empty()
        && let Some(default) = default
    {
        terminal.detail(&format!("  Default: {}\n\n", label(default)));
    }
    let answer = loop {
        let line = if terminal.choice_controls && !allowed.is_empty() {
            let selected =
                default.and_then(|default| allowed.iter().position(|value| value == default));
            if boolean {
                crate::prompt::choose(terminal, &["Yes", "No"], selected)?
            } else {
                crate::prompt::choose(terminal, &labels, selected)?
            }
        } else if terminal.choice_controls {
            crate::prompt::text(terminal)?
        } else {
            match default {
                Some(default) => {
                    let _ = write!(terminal.output, "> [{}] ", label(default));
                }
                None => {
                    let _ = write!(terminal.output, "> ");
                }
            }
            read_line(terminal)?
        };
        let Some(line) = line else {
            return Err(Error::StarterAborted {
                question: heading.clone(),
            });
        };
        if line.is_empty() {
            if let Some(default) = default {
                break kept(default);
            }
            terminal.feedback(&format!("{name} has no default; type a value.\n"));
            continue;
        }
        let line = if boolean {
            match line.to_ascii_lowercase().as_str() {
                "yes" | "y" => "true".to_string(),
                "no" | "n" => "false".to_string(),
                _ => line,
            }
        } else {
            line
        };
        let value = match line.parse::<usize>() {
            Ok(number) if !allowed.is_empty() && (1..=allowed.len()).contains(&number) => {
                allowed[number - 1].clone()
            }
            _ => line,
        };
        match lang::check_value(name, declaration, &value) {
            Ok(()) if Some(value.as_str()) == default => break kept(&value),
            Ok(()) => break Some(value),
            Err(reason) => {
                terminal.feedback(&format!("{reason}\n"));
            }
        }
    };
    let value = answer.as_deref().or(default).unwrap_or_default();
    let saved = allowed
        .iter()
        .position(|allowed| allowed == value)
        .map(|index| (index + 1).to_string())
        .unwrap_or_else(|| answer.clone().unwrap_or_default());
    terminal.accept(saved);
    Ok(answer)
}

#[cfg(test)]
#[path = "starter_tests.rs"]
mod tests;
