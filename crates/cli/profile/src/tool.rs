//! `[tool.<name>]` tables that name a `program`: found on the operator's `PATH`, checked, and
//! composed with the tool that runs them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::host::{canonical, unique, utf8};
use crate::lang::{self, OPEN, TOOL_KEYS, lies_under};
use crate::profile::{Process, Resolved};
pub(crate) use crate::program::Writable;
use crate::program::{self, Interpreter, Refused};
use crate::reference::Sources;

/// The `PATH` of a tool table that names a `program` and sets none.
const BASE_PATH: &str = "/usr/bin:/bin";

/// The programs whose Apple stub `box` runs past, to the file in the developer folder.
const PAST_APPLE_STUBS: &[&str] = &["git"];

/// One tool that the host has, and what its table runs.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    /// The installation layouts that can hold the program.
    pub(crate) installation: Vec<crate::install_layout::Layout>,
    pub(crate) installation_sources: Vec<String>,
    /// What a script that this tool runs reads of its installation, under every layout.
    pub(crate) script_reads: crate::install_layout::Requirements,
    /// The table name.
    pub name: String,
    /// The pack that declares the table's `program`.
    pub pack: String,
    /// The name the agent types.
    pub(crate) program: String,
    /// Where the lookup on `PATH` found it.
    pub spelling: PathBuf,
    /// The real file its table runs and its permit names.
    pub identity: PathBuf,
    /// The table of the tool that runs this one's `#!` line.
    pub(crate) interpreter: Option<String>,
    /// The real `env` file that the `#!` line runs the interpreter through.
    pub(crate) env: Option<PathBuf>,
    /// The real file of each helper the host has.
    pub(crate) helpers: Vec<PathBuf>,
    /// The `PATH` name of each helper, which the box grants as a read-only link to its real file.
    pub(crate) helper_names: Vec<PathBuf>,
    /// The tools of the tool packs its tool pack extends, nearest first, whose tables it inherits.
    pub(crate) bases: Vec<String>,
    /// The package hosts its permit reaches.
    pub hosts: Vec<String>,
    /// Each of its hosts whose plain `http://` request the gateway sends as `https://`.
    pub(crate) upgrade_http: Vec<String>,
    /// Every path its compiled table reads.
    pub read: Vec<PathBuf>,
    /// The policy namespace of its tool grammar, such as `Tool::git`.
    pub(crate) grammar: Option<String>,
}

/// The tools of one run: those the host has, those it skips, and each path it drops.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tools {
    pub found: Vec<Found>,
    /// Each skipped tool as `(label, reason)`, where the label names the tool and its pack.
    pub skipped: Vec<(String, String)>,
    /// Each absent path or helper of a kept tool, as `(tool, path)`.
    pub dropped: Vec<(String, String)>,
    /// The tools that only a tool pack's `extend` brings in, which the compose step leaves out
    /// of the box once the tools that extend them have their tables.
    pub(crate) hidden: Vec<String>,
}

/// A tool table's `program`, as written.
struct Declared {
    installation: Vec<crate::install_layout::Layout>,
    name: String,
    pack: String,
    program: String,
    helpers: Vec<String>,
    hosts: Vec<String>,
    upgrade_http: Vec<String>,
    /// Whether the table names `macos.developer_dir`.
    reads_developer_dir: bool,
}

/// Resolve each tool table of `table` that names a `program`, and replace it with its Box Core
/// table, or remove it when the host cannot run it.
pub(crate) fn prepare(
    table: &mut toml::Table,
    packs: &BTreeMap<String, String>,
    bases: &BTreeMap<String, Vec<String>>,
    hidden: &BTreeSet<String>,
    sources: &mut impl Sources,
    writable: &Writable<'_>,
    os: &str,
) -> Result<(Tools, BTreeMap<String, PathBuf>), String> {
    let Some(toml::Value::Table(tables)) = table.get("tool") else {
        return Ok((Tools::default(), BTreeMap::new()));
    };
    let mut declared = Vec::new();
    for (name, entry) in tables {
        if let Some(found) = declaration(name, entry, packs)? {
            declared.push(found);
        }
    }
    let mut tools = Tools::default();
    let mut kept: Vec<(Declared, Found, Option<Interpreter>)> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    for tool in declared {
        match locate(&tool, sources, writable, os) {
            Ok((found, interpreter, absent)) => {
                tools
                    .dropped
                    .extend(absent.into_iter().map(|helper| (tool.name.clone(), helper)));
                kept.push((tool, found, interpreter));
            }
            Err(why) => skipped.push((tool.name.clone(), why)),
        }
    }
    for (name, why) in &skipped {
        tools.skipped.push((label(name, packs), why.clone()));
    }
    let skipped_names: Vec<String> = skipped.into_iter().map(|(name, _)| name).collect();
    let identities: Vec<(String, String, PathBuf)> = kept
        .iter()
        .map(|(tool, found, _)| {
            (
                tool.name.clone(),
                tool.program.clone(),
                found.identity.clone(),
            )
        })
        .collect();
    let mut gone = skipped_names.clone();
    let mut survivors = Vec::new();
    for (tool, mut found, interpreter) in kept {
        let named = match &interpreter {
            None => Ok(None),
            Some(Interpreter::Named(_, program)) => identities
                .iter()
                .find(|(_, other, _)| other == program)
                .map(|(name, _, _)| Some(name.clone()))
                .ok_or_else(|| {
                    let skipped = skipped_names.iter().any(|name| {
                        tables
                            .get(name)
                            .and_then(|entry| entry.get("program"))
                            .and_then(toml::Value::as_str)
                            == Some(program.as_str())
                    });
                    if skipped {
                        format!("it runs {program}, and {program} was skipped")
                    } else {
                        format!(
                            "it runs {program}, and no tool table in the profile has \
                             `program = \"{program}\"`"
                        )
                    }
                }),
            Some(Interpreter::Path(path)) => identities
                .iter()
                .find(|(_, _, identity)| identity == path)
                .map(|(name, _, _)| Some(name.clone()))
                .ok_or_else(|| {
                    format!(
                        "it runs {}, which is the command of no tool table",
                        path.display()
                    )
                }),
        };
        match named {
            Ok(interpreter) => {
                found.interpreter = interpreter;
                survivors.push((tool, found));
            }
            Err(why) => {
                tools.skipped.push((label(&tool.name, packs), why));
                gone.push(tool.name.clone());
            }
        }
    }
    while let Some(index) = survivors.iter().position(|(_, found)| {
        found
            .interpreter
            .as_ref()
            .is_some_and(|interpreter| gone.contains(interpreter))
    }) {
        let (tool, found) = survivors.remove(index);
        let interpreter = found.interpreter.unwrap_or_default();
        tools.skipped.push((
            label(&tool.name, packs),
            format!("it runs {interpreter}, and {interpreter} was skipped"),
        ));
        gone.push(tool.name);
    }
    let Some(toml::Value::Table(tables)) = table.get_mut("tool") else {
        unreachable!("the tool tables were read above");
    };
    for name in &gone {
        tables.remove(name);
    }
    let mut roots = BTreeMap::new();
    for (tool, found) in survivors {
        let entry = tables
            .get_mut(&tool.name)
            .and_then(toml::Value::as_table_mut)
            .expect("a declared tool table");
        for key in TOOL_KEYS {
            entry.remove(*key);
        }
        let mut command = toml::Value::Array(vec![toml::Value::String(
            utf8(&found.identity).map_err(|error| error.to_string())?,
        )]);
        lang::escape_all(&mut command);
        entry.insert("command".into(), command);
        roots.insert(tool.name.clone(), root(&found.identity));
        tools.found.push(found);
    }
    let missing: Vec<String> = gone.iter().map(|name| format!("tool.{name}")).collect();
    if !missing.is_empty() {
        crate::reference::drop_dependencies(table, &missing);
    }
    for found in &mut tools.found {
        found.bases = bases.get(&found.name).cloned().unwrap_or_default();
    }
    tools.hidden = hidden.iter().cloned().collect();
    Ok((tools, roots))
}

/// Give `process` the resolved table of each tool that `found`'s tool pack extends: @box/go extends
/// @box/git, so go gets `[tool.git]`'s variables and its whole filesystem, writes too, and git's
/// folder on its `PATH`, so go can start git as git's own table runs it. `before` holds the tables
/// after every skip, so a skipped base gives nothing and the tool is kept. The tool's own variable
/// wins, a nearer base wins over a farther one, and `PATH` and `TMPDIR` stay the tool's own.
fn inherit_bases(
    found: &Found,
    before: &BTreeMap<String, Process>,
    process: &mut Process,
    read: &mut Vec<String>,
    folders: &mut Vec<String>,
) {
    for base in &found.bases {
        let Some(table) = before.get(base).filter(|_| *base != found.name) else {
            continue;
        };
        for (key, value) in &table.env {
            if key != "PATH" && key != "TMPDIR" && !process.env.contains_key(key) {
                process.env.insert(key.clone(), value.clone());
            }
        }
        if let Some(program) = table.command.first() {
            if !table.filesystem.read_file.contains(program)
                && !process.filesystem.read_file.contains(program)
            {
                read.push(program.clone());
            }
            folders.extend(
                Path::new(program)
                    .parent()
                    .map(|folder| folder.display().to_string()),
            );
        }
        read.extend(table.filesystem.read.iter().cloned());
        let lists = [
            (&mut process.filesystem.write, &table.filesystem.write),
            (
                &mut process.filesystem.read_file,
                &table.filesystem.read_file,
            ),
            (
                &mut process.filesystem.write_file,
                &table.filesystem.write_file,
            ),
            (&mut process.filesystem.list, &table.filesystem.list),
            (&mut process.filesystem.metadata, &table.filesystem.metadata),
            (&mut process.filesystem.exec, &table.filesystem.exec),
            (&mut process.filesystem.deny, &table.filesystem.deny),
        ];
        for (own, given) in lists {
            for entry in given {
                if !own.contains(entry) {
                    own.push(entry.clone());
                }
            }
        }
    }
}

/// `name (pack)`, as a skip line names a tool.
fn label(name: &str, packs: &BTreeMap<String, String>) -> String {
    match packs.get(name) {
        Some(pack) => format!("{name} ({pack})"),
        None => name.to_string(),
    }
}

/// The folder that holds `identity`, the tool's real file.
pub fn root(identity: &Path) -> PathBuf {
    identity
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn declaration(
    name: &str,
    entry: &toml::Value,
    packs: &BTreeMap<String, String>,
) -> Result<Option<Declared>, String> {
    let Some(table) = entry.as_table() else {
        return Ok(None);
    };
    if table.contains_key("detect") {
        return Err(format!(
            "`[tool.{name}] detect` is not a key; name the tool's program with `program`, or use \
             the pack `{}{name}`",
            lang::VENDORED
        ));
    }
    if table.contains_key("program") && !is_tool_name(name) {
        return Err(format!(
            "`[tool.{name}]` names a program, so its name is letters, digits, `_`, and `-`"
        ));
    }
    let Some(program) = table.get("program") else {
        if let Some(key) = TOOL_KEYS.iter().find(|key| table.contains_key(**key)) {
            return Err(format!("`[tool.{name}] {key}` needs `program`"));
        }
        return Ok(None);
    };
    let program = program
        .as_str()
        .filter(|program| is_program_name(program))
        .ok_or_else(|| format!("`[tool.{name}] program` is not a program name, such as \"git\""))?;
    if let Some(key) = lang::TOOL_PACK_TOP
        .iter()
        .find(|key| table.contains_key(**key))
    {
        return Err(format!(
            "`[tool.{name}] {key}` is a key of a pack, not of a tool, so no tool \
             table holds it"
        ));
    }
    if table.contains_key("command") {
        return Err(format!(
            "`[tool.{name}]` holds `program` and `command`; box writes the command of a tool \
             that names its program"
        ));
    }
    let names = |key: &str, check: fn(&str) -> bool| -> Result<Vec<String>, String> {
        match table.get(key) {
            None => Ok(Vec::new()),
            Some(toml::Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().filter(|text| check(text)).map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| format!("`[tool.{name}] {key}` holds a value that is not a name")),
            Some(_) => Err(format!("`[tool.{name}] {key}` is not a list")),
        }
    };
    let hosts = names("hosts", is_host_name)?;
    // A host the tool does not reach is dropped, so a profile that narrows `hosts` narrows the
    // upgrade with it, and a tool never widens what the gateway upgrades.
    let upgrade_http: Vec<String> = names("upgrade_http", is_host_name)?
        .into_iter()
        .filter(|host| hosts.contains(host))
        .collect();
    Ok(Some(Declared {
        installation: installation(name, table)?,
        name: name.to_string(),
        pack: packs.get(name).cloned().unwrap_or_default(),
        program: program.to_string(),
        helpers: names("helpers", is_program_name)?,
        hosts,
        upgrade_http,
        reads_developer_dir: names_developer_dir(entry),
    }))
}

/// Whether `name` can name a tool table that names a `program`: letters, digits, `_`, and `-`.
pub(crate) fn is_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

pub(crate) fn is_program_name(text: &str) -> bool {
    !text.is_empty()
        && !text.contains('/')
        && !text.contains(OPEN)
        && !matches!(text, "." | "..")
        && !text.chars().any(char::is_control)
}

/// Whether `text` is a lowercase host name of 1 to 63 character labels, at most 253 in all.
pub fn is_host_name(text: &str) -> bool {
    text.len() <= 253
        && text.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// Find `tool`'s program and helpers, and refuse what a box could have planted.
fn locate(
    tool: &Declared,
    sources: &mut impl Sources,
    writable: &Writable<'_>,
    os: &str,
) -> Result<(Found, Option<Interpreter>, Vec<String>), String> {
    let (spelling, identity) = find(&tool.program, sources, writable)?;
    let (spelling, identity) =
        past_apple_stub(tool, &spelling, sources, writable, os)?.unwrap_or((spelling, identity));
    let interpreter = interpreter(&identity)?;
    let env = match &interpreter {
        Some(Interpreter::Named(env, _)) => match writable.root(env) {
            Some(what) => return Err(planted(env, what)),
            None => Some(env.clone()),
        },
        _ => None,
    };
    let mut helpers = Vec::new();
    let mut helper_names = Vec::new();
    let mut absent = Vec::new();
    for helper in &tool.helpers {
        if sources.search(helper).is_none() {
            absent.push(format!("helper {helper}"));
            continue;
        }
        let (spelling, real) =
            find(helper, sources, writable).map_err(|why| format!("its helper {helper}: {why}"))?;
        // The name in its real folder: `/bin/cc` is `/usr/bin/cc` where `/bin` is a link.
        let name = spelling
            .parent()
            .and_then(canonical)
            .zip(spelling.file_name())
            .map_or_else(|| real.clone(), |(folder, file)| folder.join(file));
        helpers.push(real);
        helper_names.push(name);
    }
    Ok((
        Found {
            installation: tool.installation.clone(),
            installation_sources: Vec::new(),
            script_reads: crate::install_layout::Requirements::default(),
            name: tool.name.clone(),
            pack: tool.pack.clone(),
            program: tool.program.clone(),
            spelling,
            identity,
            interpreter: None,
            env,
            helpers,
            helper_names,
            bases: Vec::new(),
            hosts: tool.hosts.clone(),
            upgrade_http: tool.upgrade_http.clone(),
            read: Vec::new(),
            grammar: None,
        },
        interpreter,
        absent,
    ))
}

/// The file in the developer folder that the Apple stub `spelling` runs, and its real file.
fn past_apple_stub(
    tool: &Declared,
    spelling: &Path,
    sources: &mut impl Sources,
    writable: &Writable<'_>,
    os: &str,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    if os != "macos"
        || !tool.reads_developer_dir
        || !PAST_APPLE_STUBS.contains(&tool.program.as_str())
        || spelling.parent() != Some(sources.apple_stubs().as_path())
    {
        return Ok(None);
    }
    let Ok(developer) = sources.developer_dir() else {
        return Ok(None);
    };
    let direct = Path::new(&developer).join("usr/bin").join(&tool.program);
    if std::fs::symlink_metadata(&direct).is_err() {
        return Err(format!(
            "the developer folder {developer} holds no usr/bin/{}",
            tool.program
        ));
    }
    checked(&direct, writable).map(Some)
}

/// Whether a string in `value` names `macos.developer_dir`.
fn names_developer_dir(value: &toml::Value) -> bool {
    match value {
        toml::Value::String(text) => text.contains(crate::lang::DEVELOPER_DIR),
        toml::Value::Array(items) => items.iter().any(names_developer_dir),
        toml::Value::Table(table) => table.values().any(names_developer_dir),
        _ => false,
    }
}

/// Why box runs nothing from `path`, which lies in `what`.
fn planted(path: &Path, what: &str) -> String {
    format!(
        "{} lies in {what}, which a box can write; box runs no program from there",
        path.display()
    )
}

/// The first `name` on the operator's `PATH`, and its real file.
fn find(
    name: &str,
    sources: &impl Sources,
    writable: &Writable<'_>,
) -> Result<(PathBuf, PathBuf), String> {
    let spelling = sources
        .search(name)
        .ok_or_else(|| format!("{name} is not on PATH"))?;
    checked(&spelling, writable)
}

/// `spelling` and its real file, or why box runs neither.
fn checked(spelling: &Path, writable: &Writable<'_>) -> Result<(PathBuf, PathBuf), String> {
    let checked = program::check(spelling, writable).map_err(|refused| match refused {
        Refused::Planted { path, what } => planted(&path, what),
        Refused::Dangling => format!("{} does not resolve", spelling.display()),
        Refused::NotExecutable => format!("{} is not an executable file", spelling.display()),
    })?;
    Ok((checked.spelling, checked.real))
}

/// The tool interpreter of `identity`: a `program` name, or the real file of a `#!` path.
fn interpreter(identity: &Path) -> Result<Option<Interpreter>, String> {
    match program::interpreter(identity) {
        Ok(Some(Interpreter::Named(env, program))) if is_program_name(&program) => {
            let env = canonical(&env)
                .ok_or_else(|| format!("it runs {}, which does not exist", env.display()))?;
            Ok(Some(Interpreter::Named(env, program)))
        }
        Ok(Some(Interpreter::Named(..))) | Err(_) => Err(format!(
            "its #! line `{}` names no program after env",
            program::shebang(identity).join(" ")
        )),
        Ok(Some(Interpreter::Path(first))) => canonical(&first)
            .map(|real| Some(Interpreter::Path(real)))
            .ok_or_else(|| format!("it runs {}, which does not exist", first.display())),
        Ok(None) => Ok(None),
    }
}

/// A tool table's `installation`: the layouts that can hold its program.
fn installation(
    name: &str,
    table: &toml::Table,
) -> Result<Vec<crate::install_layout::Layout>, String> {
    let known = || {
        crate::install_layout::Layout::ALL
            .iter()
            .map(|layout| format!("\"{}\"", layout.name()))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match table.get("installation") {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|item| {
                let text = item.as_str().ok_or_else(|| {
                    format!("`[tool.{name}] installation` holds a value that is not a layout name")
                })?;
                crate::install_layout::Layout::named(text).ok_or_else(|| {
                    format!(
                        "`[tool.{name}] installation` names {text:?}, which is not a layout; use {}",
                        known()
                    )
                })
            })
            .collect(),
        Some(_) => Err(format!(
            "`[tool.{name}] installation` is a list of layouts, such as [\"node\", \"homebrew\"]"
        )),
    }
}

pub(crate) fn installation_reads(
    resolved: &mut Resolved,
    tools: &mut Tools,
    inputs: &lang::Inputs<'_>,
    sources: &impl Sources,
) -> Result<(), String> {
    let grant = |path: &Path| sources.read_grant(path);
    let mut skipped = Vec::new();
    let interpreters: Vec<String> = tools
        .found
        .iter()
        .filter_map(|found| found.interpreter.clone())
        .collect();
    let keep = |path: &PathBuf| {
        !matches!(
            grant(path),
            Err((
                strands_box::GrantRefusal::Forbidden(strands_box::ForbiddenClass::SystemTree),
                _
            ))
        )
    };
    for found in &mut tools.found {
        if interpreters.contains(&found.name) {
            let check = |path: &Path| {
                crate::install_layout::check_path(
                    path,
                    inputs.home,
                    inputs.workspace,
                    &resolved.storage.refusals,
                    &grant,
                )
            };
            match crate::install_layout::resolve(
                &found.spelling,
                crate::install_layout::Layout::ALL,
                inputs.os,
                &check,
            ) {
                Ok(mut reads) => {
                    reads.read.retain(keep);
                    reads.list.retain(keep);
                    found.script_reads = reads;
                }
                Err(reason) => {
                    skipped.push(found.name.clone());
                    tools
                        .skipped
                        .push((format!("{} ({})", found.name, found.pack), reason));
                    continue;
                }
            }
        }
        let mut programs: Vec<(&Path, &[crate::install_layout::Layout])> = Vec::new();
        if !found.installation.is_empty() {
            programs.push((&found.spelling, &found.installation));
        }
        for helper in &found.helpers {
            programs.push((helper, crate::install_layout::Layout::ALL));
        }
        if programs.is_empty() {
            continue;
        }
        let check = |path: &Path| {
            crate::install_layout::check_path(
                path,
                inputs.home,
                inputs.workspace,
                &resolved.storage.refusals,
                &grant,
            )
        };
        let requirements = programs.into_iter().try_fold(
            crate::install_layout::Requirements::default(),
            |mut requirements, (program, layouts)| {
                requirements.extend(crate::install_layout::resolve(
                    program, layouts, inputs.os, &check,
                )?);
                Ok::<_, String>(requirements)
            },
        );
        let requirements = match requirements {
            Ok(mut requirements) => {
                requirements.read.retain(keep);
                requirements.list.retain(keep);
                requirements
            }
            Err(reason) => {
                skipped.push(found.name.clone());
                tools
                    .skipped
                    .push((format!("{} ({})", found.name, found.pack), reason));
                continue;
            }
        };
        let Some(process) = resolved.tool.get_mut(&found.name) else {
            continue;
        };
        process.filesystem.read.extend(
            requirements
                .read
                .iter()
                .map(|path| path.display().to_string()),
        );
        process.filesystem.read_file.extend(
            requirements
                .read_file
                .iter()
                .map(|path| path.display().to_string()),
        );
        process.filesystem.list.extend(
            requirements
                .list
                .iter()
                .map(|path| path.display().to_string()),
        );
        found.installation_sources = requirements.sources;
    }
    for name in skipped {
        resolved.tool.remove(&name);
    }
    Ok(())
}

/// Skip each kept tool whose program, `env`, interpreter, or a helper lies under a write grant of the run,
/// and each tool whose interpreter that skips.
pub(crate) fn refuse_under_writes(resolved: &mut Resolved, tools: &mut Tools, home: &Path) {
    let expand = |entry: &String| match entry.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(entry),
    };
    let mut grants: Vec<PathBuf> = resolved
        .processes()
        .flat_map(|(_, process)| {
            process
                .filesystem
                .write
                .iter()
                .chain(&process.filesystem.write_file)
                .map(expand)
                .collect::<Vec<_>>()
        })
        .chain(resolved.storage.directories.iter().cloned())
        .collect();
    let mcp =
        toml::Table::from_iter([("mcp".to_string(), toml::Value::Table(resolved.mcp.clone()))]);
    grants.extend(lang::write_grants(&mcp, home));
    loop {
        let identities: BTreeMap<String, PathBuf> = tools
            .found
            .iter()
            .map(|found| (found.name.clone(), found.identity.clone()))
            .collect();
        let refusal =
            tools.found.iter().enumerate().find_map(|(index, found)| {
                if let Some(interpreter) = &found.interpreter
                    && !identities.contains_key(interpreter)
                {
                    return Some((
                        index,
                        format!("it runs {interpreter}, and {interpreter} was skipped"),
                    ));
                }
                [&found.spelling, &found.identity]
                    .into_iter()
                    .chain(&found.helpers)
                    .chain(&found.helper_names)
                    .chain(&found.env)
                    .chain(
                        found
                            .interpreter
                            .as_ref()
                            .and_then(|interpreter| identities.get(interpreter)),
                    )
                    .find_map(|program| {
                        grants.iter().find(|grant| lies_under(program, grant)).map(|grant| {
                        (
                            index,
                            format!(
                                "{} lies under the write grant {}, which a box can write; box \
                                 runs no program from there",
                                program.display(),
                                grant.display()
                            ),
                        )
                    })
                    })
            });
        let Some((index, why)) = refusal else {
            break;
        };
        let found = tools.found.remove(index);
        resolved.tool.remove(&found.name);
        tools
            .skipped
            .push((format!("{} ({})", found.name, found.pack), why));
    }
}

/// The folder where `PATH` found a program through a link, as `PATH` spells it and as the kernel
/// resolves it.
fn spelling_folder(found: &Found) -> Option<(String, String)> {
    if found.spelling == found.identity {
        return None;
    }
    let folder = found.spelling.parent()?;
    let canonical = std::fs::canonicalize(folder).ok()?;
    Some((
        folder.display().to_string(),
        canonical.display().to_string(),
    ))
}

/// The folder of a run's directory that holds each tool's own `TMPDIR`, beside `box`.
pub(crate) const SCRATCH: &str = "tool-tmp";

/// The `TMPDIR` that `tool` gets when it sets none: its own folder in the run's directory.
pub fn scratch(run: &Path, tool: &str) -> PathBuf {
    run.join(SCRATCH).join(tool)
}

/// Give each kept tool the base `PATH` and `TMPDIR` it does not set, what its interpreter,
/// helpers, and the tools its tool pack extends need, and the workspace as far as
/// `[project] access` allows; drop a tool whose
/// interpreter a `when` removed.
pub(crate) fn compose(resolved: &mut Resolved, tools: &mut Tools, workspace: &Path, run: &Path) {
    let access = resolved.project_access();
    tools
        .found
        .retain(|found| resolved.tool.contains_key(&found.name));
    let before: BTreeMap<String, Process> = resolved.tool.clone();
    let writes: Vec<PathBuf> = std::iter::once(&resolved.agent)
        .chain(before.values())
        .flat_map(|process| {
            process
                .filesystem
                .write
                .iter()
                .chain(&process.filesystem.write_file)
        })
        .map(PathBuf::from)
        .collect();
    let workspace = workspace.display().to_string();
    let mut gone = Vec::new();
    for found in &tools.found {
        if let Some(interpreter) = &found.interpreter
            && !before.contains_key(interpreter)
        {
            gone.push((found.name.clone(), interpreter.clone()));
        }
    }
    for (name, interpreter) in &gone {
        resolved.tool.remove(name);
        let label = tools
            .found
            .iter()
            .find(|found| &found.name == name)
            .map(|found| format!("{name} ({})", found.pack))
            .unwrap_or_else(|| name.clone());
        tools.skipped.push((
            label,
            format!("it runs {interpreter}, and {interpreter} was skipped"),
        ));
    }
    tools
        .found
        .retain(|found| resolved.tool.contains_key(&found.name));
    let script_reads: BTreeMap<String, crate::install_layout::Requirements> = tools
        .found
        .iter()
        .map(|found| (found.name.clone(), found.script_reads.clone()))
        .collect();
    let hops: BTreeMap<String, (Option<PathBuf>, Option<String>)> = tools
        .found
        .iter()
        .map(|found| {
            (
                found.name.clone(),
                (found.env.clone(), found.interpreter.clone()),
            )
        })
        .collect();
    for found in &mut tools.found {
        let process = resolved
            .tool
            .get_mut(&found.name)
            .expect("a kept tool has a table");
        process
            .env
            .entry("PATH".into())
            .or_insert_with(|| BASE_PATH.into());
        if !process.env.contains_key("TMPDIR") {
            let folder = scratch(run, &found.name).display().to_string();
            process.env.insert("TMPDIR".into(), folder.clone());
            for list in [&mut process.filesystem.read, &mut process.filesystem.write] {
                if !list.contains(&folder) {
                    list.push(folder.clone());
                }
            }
        }
        let mut interpreters: Vec<String> = Vec::new();
        let mut folders: Vec<String> = Vec::new();
        let mut read: Vec<String> = Vec::new();
        read.extend(found.env.iter().map(|env| env.display().to_string()));
        let mut seen = vec![found.name.clone()];
        let mut hop = found.interpreter.clone();
        while let Some(name) = hop.take().filter(|name| !seen.contains(name)) {
            let (Some(interpreter), Some((env, next))) = (before.get(&name), hops.get(&name))
            else {
                break;
            };
            read.extend(env.iter().map(|env| env.display().to_string()));
            if let Some(program) = interpreter.command.first() {
                if !interpreter.filesystem.read_file.contains(program)
                    && !process.filesystem.read_file.contains(program)
                {
                    read.push(program.clone());
                }
                interpreters.extend(
                    Path::new(program)
                        .parent()
                        .map(|folder| folder.display().to_string()),
                );
            }
            read.extend(interpreter.filesystem.read.iter().cloned());
            if let Some(reads) = script_reads.get(&name) {
                read.extend(reads.read.iter().map(|path| path.display().to_string()));
                for path in &reads.list {
                    let entry = path.display().to_string();
                    if !process.filesystem.list.contains(&entry) {
                        process.filesystem.list.push(entry);
                    }
                }
            }
            for entry in &interpreter.filesystem.read_file {
                if !process.filesystem.read_file.contains(entry) {
                    process.filesystem.read_file.push(entry.clone());
                }
            }
            for entry in &interpreter.filesystem.list {
                if !process.filesystem.list.contains(entry) {
                    process.filesystem.list.push(entry.clone());
                }
            }
            for entry in &interpreter.filesystem.deny {
                if !process.filesystem.deny.contains(entry) {
                    process.filesystem.deny.push(entry.clone());
                }
            }
            seen.push(name);
            hop = next.clone();
        }
        for helper in &found.helper_names {
            read.push(helper.display().to_string());
            folders.extend(helper.parent().map(|folder| folder.display().to_string()));
        }
        inherit_bases(found, &before, process, &mut read, &mut folders);
        let mut path: Vec<String> = process
            .env
            .get("PATH")
            .map(|path| {
                path.split(':')
                    .filter(|part| !part.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        for folder in folders.into_iter().rev() {
            if !path.contains(&folder) {
                path.insert(0, folder);
            }
        }
        for folder in interpreters.into_iter().rev() {
            path.retain(|part| part != &folder);
            path.insert(0, folder);
        }
        if let Some((spelled, real)) = spelling_folder(found)
            && !writes.iter().any(|write| {
                [&spelled, &real].iter().any(|folder| {
                    write.starts_with(folder.as_str())
                        || Path::new(folder.as_str()).starts_with(write)
                })
            })
            && !path.contains(&spelled)
        {
            path.push(spelled);
        }
        if !path.is_empty() {
            process.env.insert("PATH".into(), path.join(":"));
        }
        let entries = access
            .reads()
            .then(|| workspace.clone())
            .into_iter()
            .chain(process.filesystem.read.iter().cloned())
            .chain(read)
            .map(PathBuf::from)
            .collect();
        let mut kept = unique(entries);
        let targets: Vec<_> = kept
            .iter()
            .map(PathBuf::as_path)
            .chain(process.filesystem.read_file.iter().map(Path::new))
            .filter(|path| path.is_symlink())
            .filter_map(canonical)
            .collect();
        kept.retain(|entry| !targets.contains(entry));
        // A `read_file` that a kept `read` covers, as for a helper's Python.
        // A helper read names a link, so a `read_file` of its real file is the same grant.
        process.filesystem.read_file.retain(|file| {
            !targets.iter().any(|target| target == Path::new(file))
                && !kept.iter().any(|root| {
                    Path::new(file) == root
                        || (Path::new(file).starts_with(root)
                            && crate::host::resolved(Path::new(file)).starts_with(root))
                })
        });
        found.read = kept.clone();
        process.filesystem.read = kept.iter().map(|path| path.display().to_string()).collect();
        if access.writes() && !process.filesystem.write.contains(&workspace) {
            process.filesystem.write.insert(0, workspace.clone());
        }
    }
    let names: Vec<String> = tools.found.iter().map(|found| found.name.clone()).collect();
    tools
        .dropped
        .retain(|(tool, _)| names.iter().any(|name| name == tool));
}

/// Leave each hidden tool out of the box: @box/go extends @box/git, so go already has `[tool.git]`'s
/// table, and git is not a tool of its own unless the profile names @box/git or a pack includes it.
/// Its package hosts stay, on the tools that extend it, since a tool's hosts are the whole box's.
pub(crate) fn hide_bases(resolved: &mut Resolved, tools: &mut Tools) {
    let hidden: Vec<Found> = tools
        .found
        .iter()
        .filter(|found| tools.hidden.contains(&found.name))
        .cloned()
        .collect();
    if hidden.is_empty() {
        return;
    }
    for found in &mut tools.found {
        for base in hidden
            .iter()
            .filter(|base| found.bases.contains(&base.name))
        {
            for host in &base.hosts {
                if !found.hosts.contains(host) {
                    found.hosts.push(host.clone());
                }
            }
            for host in &base.upgrade_http {
                if !found.upgrade_http.contains(host) {
                    found.upgrade_http.push(host.clone());
                }
            }
        }
    }
    for base in &hidden {
        resolved.tool.remove(&base.name);
    }
    tools
        .found
        .retain(|found| !tools.hidden.contains(&found.name));
}

#[cfg(test)]
mod tests {
    use crate::install_layout::Layout;

    fn parse(text: &str) -> Result<Vec<Layout>, String> {
        super::installation("node", &toml::from_str(text).unwrap())
    }

    #[test]
    fn installation_names_layouts_and_refuses_anything_else() {
        assert_eq!(
            parse(r#"installation = ["node", "homebrew"]"#),
            Ok(vec![Layout::Node, Layout::Homebrew])
        );
        assert_eq!(parse(""), Ok(Vec::new()));
        let unknown = parse(r#"installation = ["conda"]"#).unwrap_err();
        assert!(
            unknown.contains(r#"names "conda", which is not a layout"#),
            "{unknown}"
        );
        assert!(unknown.contains(r#""homebrew""#), "{unknown}");
        assert!(
            parse(r#"installation = "@box/node""#)
                .unwrap_err()
                .contains("is a list of layouts")
        );
        assert!(
            parse("installation = [1]")
                .unwrap_err()
                .contains("not a layout name")
        );
    }
}
