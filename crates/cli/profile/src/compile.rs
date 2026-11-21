use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::Error;
use crate::host::unique;
use crate::host::{expand_home, find_on, is_executable_file, tilde, utf8, within};
use crate::lang::Storage;
use crate::mcp::Servers;
use crate::profile::{PROJECT_CONFIGURATION, Process, ProjectAccess, RECORDS, Resolved};
use crate::render::{Rules, SIGNAL_GROUPS, any_of, literal, pattern_below};

/// The names and directories of one run.
#[derive(Debug, Clone)]
pub struct Instance {
    pub name: String,
    pub directory: PathBuf,
    pub box_directory: PathBuf,
}

/// Everything one compile reads.
pub struct Run<'a> {
    pub profile: &'a Resolved,
    pub policy: Option<&'a str>,
    pub tool_rules: &'a Rules,
    pub workspace: &'a Path,
    pub instance: &'a Instance,
    pub home: &'a Path,
    /// The box home first, then `~/.strands/box` when it is another folder.
    pub box_homes: &'a [PathBuf],
    /// Files outside every box home that a later run reads again: a profile file and its policies.
    pub trusted: &'a [PathBuf],
    pub protected: &'a [PathBuf],
    /// `box`'s resources directory, which `box profile create` and later runs read.
    pub resources: Option<&'a Path>,
    pub search_path: &'a OsStr,
    pub resolve: &'a dyn Fn(&Path) -> PathBuf,
    /// Whether the box runs with effective user ID 0.
    pub root: bool,
}

/// One run's `box.toml`, `policy.dw`, and the storage `box run` prepares before the launch.
#[derive(Debug, Clone)]
pub struct Compiled {
    pub box_toml: String,
    pub policy: String,
    /// The `@id` of each rule that `box` writes into `policy`.
    pub generated_ids: Vec<String>,
    pub journal: PathBuf,
    pub storage: Storage,
    /// Each stdio MCP server that gets no permit to start, with the reason.
    pub unstarted: Vec<(String, String)>,
    /// Each entry of the operator's `PATH` that is not a full path, which `box` drops from each
    /// stdio server that inherits that `PATH`, as the end of its `dropped` line.
    pub path_dropped: Vec<String>,
}

/// The profile's limits with `shell.timeout = false` (no Shell timeout) when the profile leaves it out.
fn with_default_shell_timeout(mut limits: toml::Table) -> toml::Table {
    if let toml::Value::Table(shell) = limits
        .entry("shell")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
    {
        shell
            .entry("timeout")
            .or_insert(toml::Value::Boolean(false));
    }
    limits
}

#[derive(Serialize)]
struct EngineConfig<'a> {
    name: &'a str,
    box_dir: String,
    policy: &'static str,
    #[serde(rename = "file-attributes")]
    file_attributes: bool,
    #[serde(skip_serializing_if = "toml::Table::is_empty")]
    limits: toml::Table,
    agent: Process,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    tool: BTreeMap<String, Process>,
    #[serde(skip_serializing_if = "toml::Table::is_empty")]
    egress: toml::Table,
    #[serde(skip_serializing_if = "toml::Table::is_empty")]
    mcp: toml::Table,
    #[serde(skip_serializing_if = "toml::Table::is_empty")]
    gateway: toml::Table,
    telemetry: toml::Table,
    #[serde(
        rename = "secret-source",
        skip_serializing_if = "toml::Table::is_empty"
    )]
    secret_source: toml::Table,
    #[serde(
        rename = "experimental-features",
        skip_serializing_if = "toml::Table::is_empty"
    )]
    experimental_features: toml::Table,
}

/// Compile a resolved profile for one run in `workspace`.
pub fn compile(run: &Run<'_>) -> Result<Compiled, Error> {
    let workspace = utf8(run.workspace)?;
    if within(run.home, run.workspace) {
        return Err(Error::ProjectHoldsHome {
            path: run.workspace.to_path_buf(),
        });
    }
    for held in [&run.instance.directory, &run.instance.box_directory] {
        if within(held, run.workspace) || within(run.workspace, held) {
            return Err(Error::ProjectHoldsBox {
                path: run.workspace.to_path_buf(),
                holds: held.clone(),
            });
        }
    }
    let mut profile = run.profile.clone();
    let access = profile.project_access();
    let deny = utf8(&run.workspace.join(PROJECT_CONFIGURATION))?;
    let resolve = |entry: &str| (run.resolve)(&expand_home(run.home, Path::new(entry)));
    let everywhere = std::mem::take(&mut profile.filesystem.deny_write);
    refuse_file_protections("[filesystem] deny_write", &everywhere, &resolve)?;
    let denied_everywhere = std::mem::take(&mut profile.filesystem.deny);
    for process in profile.processes_mut() {
        for entry in &everywhere {
            add(&mut process.filesystem.deny_write, entry);
        }
        for entry in &denied_everywhere {
            add(&mut process.filesystem.deny, entry);
        }
    }
    profile.agent.workspace = Some(workspace.clone());
    let storage: Vec<String> = profile
        .storage
        .directories
        .iter()
        .map(|directory| utf8(directory))
        .collect::<Result<_, _>>()?;
    let filesystem = &mut profile.agent.filesystem;
    filesystem.read.extend(storage.iter().cloned());
    filesystem.write.extend(storage.iter().cloned());
    filesystem.read = first(access.reads().then_some(&workspace), &filesystem.read);
    filesystem.write = first(access.writes().then_some(&workspace), &filesystem.write);
    for list in [
        &mut filesystem.read_file,
        &mut filesystem.write_file,
        &mut filesystem.list,
        &mut filesystem.metadata,
        &mut filesystem.exec,
        &mut filesystem.deny_write,
    ] {
        let mut seen = Vec::new();
        list.retain(|entry| {
            let fresh = !seen.contains(entry);
            seen.push(entry.clone());
            fresh
        });
    }
    let writes: Vec<PathBuf> = filesystem
        .write
        .iter()
        .map(|entry| resolve(entry))
        .collect();
    refuse_file_protections(
        "[agent.filesystem] deny_write",
        &filesystem.deny_write,
        &resolve,
    )?;
    filesystem
        .deny_write
        .retain(|entry| writes.iter().any(|write| within(&resolve(entry), write)));
    for process in profile.processes_mut() {
        add(&mut process.filesystem.deny, &deny);
    }
    for (name, tool) in &mut profile.tool {
        refuse_file_protections(
            &format!("[tool.{name}.filesystem] deny_write"),
            &tool.filesystem.deny_write,
            &resolve,
        )?;
        let writes: Vec<PathBuf> = tool
            .filesystem
            .write
            .iter()
            .map(|entry| resolve(entry))
            .collect();
        tool.filesystem
            .deny_write
            .retain(|entry| writes.iter().any(|write| within(&resolve(entry), write)));
    }
    let agent_deny = profile.agent.filesystem.deny.clone();
    let servers = profile.servers.clone();
    for (name, entry) in stdio_servers(&mut profile.mcp) {
        let refuse = |reason: &str| Error::Profile {
            path: PathBuf::from(format!("[mcp.{name}]")),
            line: None,
            reason: reason.to_string(),
        };
        if let Some(program) = entry
            .get("command")
            .and_then(|command| command.get(0))
            .and_then(toml::Value::as_str)
            .filter(|program| {
                !Path::new(program).is_absolute()
                    && (program.contains('/') || program.starts_with('~'))
            })
        {
            return Err(Error::Profile {
                path: PathBuf::from(format!("[mcp.{name}] command")),
                line: None,
                reason: format!(
                    "{program:?} is not an absolute path; use a program name on PATH or an \
                     absolute executable path"
                ),
            });
        }
        let filesystem = entry
            .entry("filesystem")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(|| refuse("`filesystem` is not a table"))?;
        if !everywhere.is_empty() {
            let list = filesystem
                .entry("deny_write")
                .or_insert_with(|| toml::Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| refuse("`filesystem.deny_write` is not a list"))?;
            for entry in &everywhere {
                if !list.iter().any(|item| item.as_str() == Some(entry)) {
                    list.push(toml::Value::String(entry.clone()));
                }
            }
        }
        let protections: Vec<String> = strings_in(filesystem.get("deny_write"))
            .into_iter()
            .map(str::to_string)
            .collect();
        refuse_file_protections(
            &format!("[mcp.{name}.filesystem] deny_write"),
            &protections,
            &resolve,
        )?;
        let writes: Vec<PathBuf> = strings_in(filesystem.get("write"))
            .into_iter()
            .map(resolve)
            .collect();
        if let Some(toml::Value::Array(list)) = filesystem.get_mut("deny_write") {
            list.retain(|item| {
                item.as_str()
                    .is_some_and(|entry| writes.iter().any(|write| within(&resolve(entry), write)))
            });
            if list.is_empty() {
                filesystem.remove("deny_write");
            }
        }
        let list = filesystem
            .entry("deny")
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| refuse("`filesystem.deny` is not a list"))?;
        let denied = if servers.is_detected_stdio(&name) {
            agent_deny.clone()
        } else {
            std::iter::once(deny.clone())
                .chain(denied_everywhere.iter().cloned())
                .collect()
        };
        for entry in denied {
            if !list
                .iter()
                .any(|item| item.as_str() == Some(entry.as_str()))
            {
                list.push(toml::Value::String(entry));
            }
        }
    }
    refuse_reach(&profile, run)?;
    let journal = run.instance.directory.join("records.jsonl");
    let mut telemetry = profile.telemetry.clone();
    telemetry.insert(
        RECORDS.to_string(),
        toml::Value::Table(toml::Table::from_iter([
            ("kind".to_string(), toml::Value::from("file")),
            (
                "destination".to_string(),
                toml::Value::from(utf8(&journal)?),
            ),
            (
                "include".to_string(),
                toml::Value::Array(SIGNAL_GROUPS.iter().map(|group| (*group).into()).collect()),
            ),
        ])),
    );
    let (generated, unstarted) = generated_policy(&profile, run)?;
    let path_dropped = inherit_path(&mut profile.mcp, &profile.servers, run.search_path);
    let mut around = project_rules(&tilde(run.home, run.workspace), access);
    let with_parents = |entry: &String| {
        let folder = resolve(entry);
        let mut parents: Vec<String> = Vec::new();
        for write in writes.iter().filter(|write| within(&folder, write)) {
            for parent in folder
                .ancestors()
                .skip(1)
                .take_while(|parent| *parent != write.as_path() && within(parent, write))
            {
                let parent = tilde(run.home, parent);
                if !parents.contains(&parent) {
                    parents.push(parent);
                }
            }
        }
        (tilde(run.home, &folder), parents)
    };
    let protected_folders: Vec<(String, Vec<String>)> = profile
        .agent
        .filesystem
        .deny_write
        .iter()
        .map(with_parents)
        .collect();
    deny_write_rules(&mut around, &protected_folders);
    let denied_paths: Vec<(String, Vec<String>)> =
        denied_everywhere.iter().map(with_parents).collect();
    deny_rules(&mut around, &denied_paths);
    let egress: toml::Table = profile
        .egress
        .into_iter()
        .filter(|(_, route)| !is_open_route(route))
        .collect();
    let mut experimental_features = toml::Table::new();
    if let Some(enabled) = profile.experimental_features.native_filesystem_policy {
        experimental_features.insert("native-filesystem-policy".into(), enabled.into());
    }
    if profile.tool.values().any(|tool| tool.grammar.is_some()) {
        experimental_features.insert("tool-grammars".into(), true.into());
    }
    if !profile.agent.ingress.is_empty() {
        experimental_features.insert("ingress".into(), true.into());
    }
    if !profile.secret_source.is_empty()
        || names_secret_env(&egress)
        || names_secret_env(&profile.mcp)
    {
        experimental_features.insert("secret-sources".into(), true.into());
    }
    let mut upgrade_http: Vec<toml::Value> = Vec::new();
    for host in profile
        .tools
        .found
        .iter()
        .flat_map(|tool| &tool.upgrade_http)
    {
        if !upgrade_http.iter().any(|seen| seen.as_str() == Some(host)) {
            upgrade_http.push(host.as_str().into());
        }
    }
    let mut gateway = toml::Table::new();
    if !upgrade_http.is_empty() {
        gateway.insert("upgrade_http".into(), toml::Value::Array(upgrade_http));
    }
    let config = EngineConfig {
        name: &run.instance.name,
        box_dir: utf8(&run.instance.box_directory)?,
        policy: "policy.dw",
        file_attributes: profile.file_attributes.unwrap_or(!run.root),
        limits: with_default_shell_timeout(profile.limits),
        agent: profile.agent,
        tool: profile.tool,
        egress,
        mcp: profile.mcp,
        gateway,
        telemetry,
        secret_source: profile.secret_source,
        experimental_features,
    };
    let tool_text = run.tool_rules.text();
    let generated_text = generated.text();
    let joined = [
        run.policy.unwrap_or_default(),
        tool_text.trim_end(),
        generated_text.trim_end(),
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join("\n\n");
    let rendered = policy(Some(&joined), &around.text());
    let mut generated_ids = run.tool_rules.ids.clone();
    generated_ids.extend(generated.ids);
    generated_ids.extend(around.ids);
    Ok(Compiled {
        box_toml: format!(
            "{}{}",
            installation_sources(run.profile),
            toml::to_string(&config)?
        ),
        policy: rendered,
        generated_ids,
        journal,
        storage: profile.storage.clone(),
        unstarted,
        path_dropped,
    })
}

/// The permits each route, each MCP server, each storage directory, and each imported hook's
/// script needs, and the forbids on the box home, with each stdio server that gets no permit to
/// start and the reason.
///
/// Every permit here comes from a table that a pack or the profile declares. The rules that no
/// table declares, such as the shell's commands, are in the policy starters that
/// `box profile create` copies into the profile.
fn generated_policy(
    profile: &Resolved,
    run: &Run<'_>,
) -> Result<(Rules, Vec<(String, String)>), Error> {
    let home = run.home;
    let mut rules = Rules::default();
    let mut unstarted = Vec::new();
    for (name, route) in &profile.egress {
        let destinations = strings_in(route.get("destinations"));
        if is_open_route(route) {
            refuse_open_destinations(name, &destinations)?;
        }
        for (id, rule) in reach_rules(
            &format!("[egress.{name}]"),
            &format!("route_{name}"),
            &destinations,
        )? {
            rules.add(&id, &rule);
        }
    }
    for (name, entry) in &profile.mcp {
        let Some(entry) = entry.as_table() else {
            continue;
        };
        let id = |kind: &str| format!("mcp_{name}_{kind}");
        rules.add(
            &id("call"),
            &format!(
                "permit (principal, action == Box::Action::\"mcp:call\", resource) when {{ context.input.server == {} }};",
                literal(name)
            ),
        );
        match entry.get("type").and_then(toml::Value::as_str) {
            Some("stdio") => {
                let Some(program) = entry
                    .get("command")
                    .and_then(|command| command.get(0))
                    .and_then(toml::Value::as_str)
                else {
                    continue;
                };
                let found = match profile.servers.spawns(name, program) {
                    Some(path) => Some(path.to_path_buf()),
                    None => server_program(program, entry, run),
                };
                let Some(path) = found else {
                    let reason = if Path::new(program).is_absolute() {
                        format!("box finds no executable at {program}")
                    } else {
                        let place = if server_path(entry).is_some() {
                            "its env.PATH"
                        } else {
                            "your PATH"
                        };
                        format!("box finds no {program} on {place}")
                    };
                    unstarted.push((name.clone(), reason));
                    continue;
                };
                let native = entry
                    .get("native-filesystem-policy")
                    .and_then(toml::Value::as_bool)
                    .or(profile.experimental_features.native_filesystem_policy)
                    .unwrap_or(false);
                if native && profile.servers.launcher(name).is_some() {
                    unstarted.push((
                        name.clone(),
                        format!(
                            "native filesystem policy would refuse its writes to its launcher \
                             cache; set `native-filesystem-policy = false` in `[mcp.{name}]`"
                        ),
                    ));
                    continue;
                }
                rules.add(
                    &id("spawn"),
                    &format!(
                        "permit (principal, action == Box::Action::\"shell:spawn\", resource) when {{ context.input.program_path == {} && context.input.program == {} }};",
                        literal(&tilde(home, &path)),
                        literal(program.rsplit('/').next().unwrap_or(program))
                    ),
                );
                if let Some(launcher) = profile.servers.launcher(name) {
                    let hosts: Vec<&str> = launcher.hosts.iter().map(String::as_str).collect();
                    for (id, rule) in
                        reach_rules(&launcher.pack, &format!("launcher_{name}_registry"), &hosts)?
                    {
                        rules.add(&id, &rule);
                    }
                }
            }
            Some("http") => {
                for (id, rule) in reach_rules(
                    &format!("[mcp.{name}]"),
                    &format!("mcp_{name}"),
                    &strings_in(entry.get("destinations")),
                )? {
                    rules.add(&id, &rule);
                }
            }
            _ => {}
        }
    }
    let within = |path: &str| {
        format!(
            "context.input.path == {} || context.input.path like {}",
            literal(path),
            pattern_below(path),
        )
    };
    let storage: Vec<String> = profile
        .storage
        .directories
        .iter()
        .map(|directory| tilde(home, directory))
        .collect();
    for (index, directory) in storage.iter().enumerate() {
        for (action, verb) in [
            ("fs:read", "read"),
            ("fs:write", "write"),
            ("fs:delete", "delete"),
            ("fs:move", "move"),
        ] {
            rules.add(
                &format!("storage_{index}_{verb}"),
                &format!(
                    "permit (principal, action == Box::Action::{action:?}, resource) when {{ {} }};",
                    within(directory)
                ),
            );
        }
    }
    for (index, script) in profile.storage.hook_scripts.iter().enumerate() {
        rules.add(
            &format!("hook_script_{index}_read"),
            &format!(
                "permit (principal, action == Box::Action::\"fs:read\", resource) when {{ context.input.path == {} }};",
                literal(&tilde(home, script))
            ),
        );
    }
    let writable: Vec<String> = profile
        .storage
        .directories
        .iter()
        .chain(&profile.storage.tool_states)
        .map(|directory| format!("({})", within(&tilde(home, directory))))
        .collect();
    let except = if writable.is_empty() {
        String::new()
    } else {
        format!(" && !({})", any_of(&writable))
    };
    for (index, box_home) in run.box_homes.iter().enumerate() {
        let box_home = tilde(home, box_home);
        let prefix = match index {
            0 => "box_home".to_string(),
            index => format!("box_home_{index}"),
        };
        for (action, verb) in [
            ("fs:write", "write"),
            ("fs:delete", "delete"),
            ("fs:move", "move"),
        ] {
            rules.add(
                &format!("{prefix}_{verb}"),
                &format!(
                    "forbid (principal, action == Box::Action::{action:?}, resource) when {{ ({}){except} }};",
                    within(&box_home)
                ),
            );
        }
    }
    protected_root_rules(&mut rules, run);
    trusted_file_rules(&mut rules, run);
    Ok((rules, unstarted))
}

/// The forbids on each protected root, so the Shell and Monty cannot change a pack, a policy
/// starter, or a program that a later run trusts: `box`'s resources directory as
/// `resources_*`, and each other protected root that a write grant may not reach as
/// `protected_<n>_*`. A box home, the resources directory, and a trusted file have rules of their
/// own, and a root that resolves into a box home keeps only the rules on the links to it.
fn protected_root_rules(rules: &mut Rules, run: &Run<'_>) {
    if let Some(resources) = run.resources {
        directory_rules(rules, run, "resources", resources);
    }
    let mut index = 0;
    for root in run.protected {
        if run.resources == Some(root.as_path())
            || run.trusted.contains(root)
            || run.box_homes.contains(root)
        {
            continue;
        }
        if directory_rules(rules, run, &format!("protected_{index}"), root) {
            index += 1;
        }
    }
}

/// A `forbid` on writing, deleting, and moving `directory` and everything in it, and on moving or
/// deleting each folder above it and each link on its written path. The rules name each path as a
/// decision reports it, and leave out what a box home's forbids already cover. Whether it wrote any.
fn directory_rules(rules: &mut Rules, run: &Run<'_>, prefix: &str, directory: &Path) -> bool {
    let home = (run.resolve)(run.home);
    let box_homes: Vec<PathBuf> = run
        .box_homes
        .iter()
        .map(|box_home| (run.resolve)(box_home))
        .collect();
    let in_a_box_home = |path: &Path| box_homes.iter().any(|box_home| within(path, box_home));
    let real = (run.resolve)(directory);
    let mut folders: Vec<PathBuf> = Vec::new();
    let mut keep = |folder: PathBuf| {
        if folder != real && !in_a_box_home(&folder) && !folders.contains(&folder) {
            folders.push(folder);
        }
    };
    let protected = !in_a_box_home(&real);
    if protected {
        for parent in real
            .ancestors()
            .skip(1)
            .take_while(|parent| *parent != home && parent.parent().is_some())
        {
            keep(parent.to_path_buf());
        }
    }
    // A link on the written path, such as a `BOX_RESOURCES` that names a link, is removed or moved
    // without being followed, and a later run reads through whatever replaces it. So each folder
    // on the written path is kept too, as a decision reports it: its parent resolved, then its own
    // name.
    let written = std::path::absolute(directory).unwrap_or_else(|_| directory.to_path_buf());
    if written != real {
        for step in written.ancestors() {
            if (run.resolve)(step) == home {
                break;
            }
            let (Some(parent), Some(name)) = (step.parent(), step.file_name()) else {
                break;
            };
            keep((run.resolve)(parent).join(name));
        }
    }
    if !protected && folders.is_empty() {
        return false;
    }
    rules.gap();
    if protected {
        let named = tilde(&home, &real);
        let below = format!(
            "context.input.path == {} || context.input.path like {}",
            literal(&named),
            pattern_below(&named),
        );
        for (action, verb) in [
            ("fs:write", "write"),
            ("fs:delete", "delete"),
            ("fs:move", "move"),
        ] {
            rules.add(
                &format!("{prefix}_{verb}"),
                &format!(
                    "forbid (principal, action == Box::Action::{action:?}, resource) when {{ {below} }};"
                ),
            );
        }
    }
    if folders.is_empty() {
        return true;
    }
    let folders = folders
        .iter()
        .map(|folder| format!("context.input.path == {}", literal(&tilde(&home, folder))))
        .collect::<Vec<_>>()
        .join(" || ");
    for (action, verb) in [("fs:move", "move"), ("fs:delete", "delete")] {
        rules.add(
            &format!("{prefix}_folder_{verb}"),
            &format!(
                "forbid (principal, action == Box::Action::{action:?}, resource) when {{ {folders} }};"
            ),
        );
    }
    true
}

/// A `forbid` on writing, deleting, and moving each trusted file, and on moving or deleting each
/// folder above it, so the Shell and Monty cannot change a file that a later run reads.
fn trusted_file_rules(rules: &mut Rules, run: &Run<'_>) {
    if run.trusted.is_empty() {
        return;
    }
    let files: Vec<String> = run
        .trusted
        .iter()
        .map(|file| tilde(run.home, file))
        .collect();
    let mut parents: Vec<String> = Vec::new();
    for file in run.trusted {
        for parent in file
            .ancestors()
            .skip(1)
            .take_while(|parent| *parent != run.home && parent.parent().is_some())
        {
            let parent = tilde(run.home, parent);
            if !parents.contains(&parent) {
                parents.push(parent);
            }
        }
    }
    let exactly = |paths: &[String]| {
        paths
            .iter()
            .map(|path| format!("context.input.path == {}", literal(path)))
            .collect::<Vec<_>>()
            .join(" || ")
    };
    rules.gap();
    for (action, verb) in [
        ("fs:write", "write"),
        ("fs:delete", "delete"),
        ("fs:move", "move"),
    ] {
        rules.add(
            &format!("profile_file_{verb}"),
            &format!(
                "forbid (principal, action == Box::Action::{action:?}, resource) when {{ {} }};",
                exactly(&files)
            ),
        );
    }
    if parents.is_empty() {
        return;
    }
    for (action, verb) in [("fs:move", "move"), ("fs:delete", "delete")] {
        rules.add(
            &format!("profile_folder_{verb}"),
            &format!(
                "forbid (principal, action == Box::Action::{action:?}, resource) when {{ {} }};",
                exactly(&parents)
            ),
        );
    }
}

/// The strings of the list `value`, if it is one.
fn strings_in(value: Option<&toml::Value>) -> Vec<&str> {
    value
        .and_then(toml::Value::as_array)
        .map(|items| items.iter().filter_map(toml::Value::as_str).collect())
        .unwrap_or_default()
}

/// The most hosts that one route or server names.
const MAX_HOSTS_PER_RULE: usize = 100;

/// The `net:connect` and `http:request` permits for each of `destinations`, as `(@id, rule)`, with
/// `@id`s that start with `prefix`.
fn reach_rules(
    owner: &str,
    prefix: &str,
    destinations: &[&str],
) -> Result<Vec<(String, String)>, Error> {
    if destinations.is_empty() {
        return Ok(Vec::new());
    }
    if destinations.len() > MAX_HOSTS_PER_RULE {
        return Err(Error::Profile {
            path: PathBuf::from(owner),
            line: None,
            reason: format!(
                "`{owner}` names {} hosts, and it holds at most {MAX_HOSTS_PER_RULE}",
                destinations.len()
            ),
        });
    }
    let mut connect = Vec::new();
    let mut request = Vec::new();
    for destination in destinations {
        if destination.contains("://") {
            return Err(Error::Profile {
                path: PathBuf::from(owner),
                line: None,
                reason: format!(
                    "destination {destination:?} is a URL; write the host, with an optional \
                     port and path"
                ),
            });
        }
        let (host, port) = authority(destination);
        let port = port.unwrap_or("443");
        if !port.parse::<u16>().is_ok_and(|port| port > 0) {
            return Err(Error::Profile {
                path: PathBuf::from(format!("{owner} destinations")),
                line: None,
                reason: format!(
                    "destination {destination:?} names the port {port:?}; a port is 1 to 65535"
                ),
            });
        }
        let matches = if host.starts_with("*.") {
            format!("context.input.host like {}", literal(host))
        } else {
            format!("context.input.host == {}", literal(host))
        };
        connect.push(format!("({matches} && context.input.port == {port})"));
        request.push(matches);
    }
    Ok(vec![
        (
            format!("{prefix}_connect"),
            format!(
                "permit (principal, action == Box::Action::\"net:connect\", resource) when {{ {} }};",
                any_of(&connect)
            ),
        ),
        (
            format!("{prefix}_request"),
            format!(
                "permit (principal, action == Box::Action::\"http:request\", resource) when {{ {} }};",
                any_of(&request)
            ),
        ),
    ])
}

/// Whether `route` holds only `destinations`, a non-empty list of strings.
pub(crate) fn is_open_route(route: &toml::Value) -> bool {
    let Some(table) = route.as_table() else {
        return false;
    };
    let destinations = table.get("destinations").and_then(toml::Value::as_array);
    table.len() == 1
        && destinations
            .is_some_and(|items| !items.is_empty() && items.iter().all(toml::Value::is_str))
}

/// Each route that holds only `destinations`, as `(name, its destinations)`.
pub fn open_routes(egress: &toml::Table) -> Vec<(String, Vec<String>)> {
    egress
        .iter()
        .filter(|(_, route)| is_open_route(route))
        .map(|(name, route)| {
            (
                name.clone(),
                strings_in(route.get("destinations"))
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            )
        })
        .collect()
}

/// Refuse a destination of the open route `name` that is not a host name with an optional port.
fn refuse_open_destinations(name: &str, destinations: &[&str]) -> Result<(), Error> {
    for destination in destinations {
        let (host, _) = authority(destination);
        if destination.contains('/') || !crate::tool::is_host_name(host) {
            return Err(Error::Profile {
                path: PathBuf::from(format!("[egress.{name}] destinations")),
                line: None,
                reason: format!(
                    "`[egress.{name}]` has no secret, so each destination is a host name with an \
                     optional port, such as \"login.example.com\" or \"build.example.com:8443\"; \
                     {destination:?} is not"
                ),
            });
        }
    }
    Ok(())
}

/// The host of a destination and its port, if it names one, without its path.
pub(crate) fn authority(destination: &str) -> (&str, Option<&str>) {
    let authority = destination.split('/').next().unwrap_or(destination);
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => (host, Some(port)),
        _ => (authority, None),
    }
}

/// A stdio server's own `env.PATH`, if it sets one.
fn server_path(entry: &toml::Table) -> Option<&str> {
    entry
        .get("env")
        .and_then(|env| env.get("PATH"))
        .and_then(toml::Value::as_str)
}

/// The selected executable of a stdio server.
fn server_program(program: &str, entry: &toml::Table, run: &Run<'_>) -> Option<PathBuf> {
    let path = Path::new(program);
    if path.is_absolute() {
        return is_executable_file(path).then(|| (run.resolve)(path));
    }
    let search_path = Some(server_path(entry).map_or(run.search_path, OsStr::new))
        .filter(|path| !path.is_empty())
        .unwrap_or(OsStr::new("/usr/bin:/bin"));
    find_on(search_path, program).map(|found| (run.resolve)(&found))
}

/// `entries` with `workspace`, when given, first, and every entry at or below another dropped.
fn first(workspace: Option<&String>, entries: &[String]) -> Vec<String> {
    let paths = workspace
        .map(String::as_str)
        .into_iter()
        .chain(entries.iter().map(String::as_str))
        .map(PathBuf::from)
        .collect();
    unique(paths)
        .into_iter()
        .map(|path| path.display().to_string())
        .collect()
}

fn add(list: &mut Vec<String>, entry: &str) {
    if !list.iter().any(|existing| existing == entry) {
        list.push(entry.to_string());
    }
}

/// Every `[mcp.<name>]` table the engine starts as a contained child, with its name.
fn stdio_servers(mcp: &mut toml::Table) -> impl Iterator<Item = (String, &mut toml::Table)> {
    mcp.iter_mut()
        .filter_map(|(name, entry)| Some((name.clone(), entry.as_table_mut()?)))
        .filter(|(_, entry)| entry.get("type").and_then(toml::Value::as_str) == Some("stdio"))
}

/// Write the operator's full `PATH` entries into each stdio table with no `env.PATH`, when that
/// `PATH` holds an entry that is not a full path and at least one full entry, and return each such
/// entry's `dropped` line when a server inherits that `PATH`. A detected launcher's `PATH` holds
/// only the full entries already.
fn inherit_path(mcp: &mut toml::Table, servers: &Servers, search_path: &OsStr) -> Vec<String> {
    let mut full = Vec::new();
    let mut dropped: Vec<String> = Vec::new();
    for directory in std::env::split_paths(search_path) {
        let entry = directory.display().to_string();
        if directory.is_absolute() {
            full.push(entry);
        } else if !dropped.contains(&entry) {
            dropped.push(entry);
        }
    }
    if dropped.is_empty() || search_path.is_empty() {
        return Vec::new();
    }
    let inherited = if full.is_empty() {
        "/usr/bin:/bin".to_string()
    } else {
        full.join(":")
    };
    let mut inherits = false;
    for (name, entry) in stdio_servers(mcp) {
        if full.is_empty()
            && !entry
                .get("command")
                .and_then(|command| command.get(0))
                .and_then(toml::Value::as_str)
                .is_some_and(|program| Path::new(program).is_absolute())
        {
            continue;
        }
        let launcher = servers
            .launcher(&name)
            .and_then(|launcher| launcher.env.get("PATH"));
        let Some(env) = entry
            .entry("env")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
        else {
            continue;
        };
        match env.get("PATH") {
            None => {
                env.insert("PATH".into(), toml::Value::from(inherited.clone()));
                inherits = true;
            }
            Some(path) => inherits |= launcher.is_some_and(|own| path.as_str() == Some(own)),
        }
    }
    if !inherits {
        return Vec::new();
    }
    dropped
        .iter()
        .map(|entry| {
            format!(
                "{entry:?} from the PATH of each MCP server that inherits your PATH: it is not a \
                 full path, so it finds programs in the project"
            )
        })
        .collect()
}

/// One contained process, or the program of a secret source, as the reach check reads it.
struct Reach {
    /// The table the process comes from, as `agent`, `tool.<name>`, or `mcp.<name>`.
    table: String,
    command: Vec<String>,
    arguments: Vec<String>,
    exec: Vec<String>,
    write: Vec<String>,
    /// The `deny_write` folders that the process's own write grants cannot change.
    write_protected: Vec<String>,
    search_path: Option<String>,
    operator_path: bool,
}

fn reaches(profile: &mut Resolved) -> Vec<Reach> {
    let mut found: Vec<Reach> = profile
        .processes()
        .map(|(table, process)| Reach {
            table,
            command: process.command.clone(),
            arguments: Vec::new(),
            exec: process.filesystem.exec.clone(),
            write: process
                .filesystem
                .write
                .iter()
                .chain(&process.filesystem.write_file)
                .cloned()
                .collect(),
            write_protected: process.filesystem.deny_write.clone(),
            search_path: process.env.get("PATH").cloned(),
            operator_path: !process.env.contains_key("PATH"),
        })
        .collect();
    let owned = |value: Option<&toml::Value>| -> Vec<String> {
        strings_in(value).into_iter().map(str::to_string).collect()
    };
    let detected: BTreeMap<String, bool> = profile
        .servers
        .detected
        .iter()
        .map(|server| (server.name.clone(), server.extended))
        .collect();
    for (name, entry) in stdio_servers(&mut profile.mcp) {
        let filesystem = entry.get("filesystem");
        let list = |key: &str| owned(filesystem.and_then(|filesystem| filesystem.get(key)));
        let mut command = owned(entry.get("command"));
        let mut arguments = Vec::new();
        if let Some(extended) = detected.get(&name) {
            if *extended {
                let wildcards = entry
                    .get("argument_wildcards")
                    .and_then(toml::Value::as_bool)
                    == Some(true);
                arguments.extend(
                    command
                        .iter()
                        .skip(1)
                        .filter(|arg| !wildcards || *arg != "*")
                        .cloned(),
                );
            }
            command.truncate(1);
        }
        found.push(Reach {
            table: format!("mcp.{name}"),
            command,
            arguments,
            exec: list("exec"),
            write: list("write")
                .into_iter()
                .chain(list("write_file"))
                .collect(),
            search_path: entry
                .get("env")
                .and_then(|env| env.get("PATH"))
                .and_then(toml::Value::as_str)
                .map(str::to_string),
            write_protected: list("deny_write"),
            operator_path: true,
        });
    }
    for (scheme, source) in &profile.secret_source {
        let mut command = with_flag_values(owned(source.get("command")));
        let interpreters: Vec<String> = command
            .first()
            .and_then(|program| source_interpreters(Path::new(program)).ok())
            .unwrap_or_default()
            .iter()
            .filter_map(|path| path.to_str().map(str::to_string))
            .collect();
        command.extend(interpreters);
        found.push(Reach {
            table: format!("secret-source.{scheme}"),
            command,
            arguments: Vec::new(),
            exec: Vec::new(),
            write: Vec::new(),
            write_protected: Vec::new(),
            search_path: None,
            operator_path: false,
        });
    }
    found
}

/// `command`, and after it the value of each `<flag>=<value>` element whose value is a full path
/// or a path under the home, such as `/etc/vault.hcl` in `-config=/etc/vault.hcl`, which the
/// program reads as a file or a folder.
fn with_flag_values(mut command: Vec<String>) -> Vec<String> {
    let values: Vec<String> = command
        .iter()
        .skip(1)
        .filter_map(|element| element.split_once('=').map(|(_, value)| value))
        .filter(|value| names_a_host_path(value))
        .map(str::to_string)
        .collect();
    command.extend(values);
    command
}

/// Whether `element` of a secret source's `command` is a full path, the home, or a path under the
/// home, which the reach check reads as a path whether or not something is there.
fn names_a_host_path(element: &str) -> bool {
    element.starts_with('/') || element == "~" || element.starts_with("~/")
}

/// The search path that Box Core gives the program of a secret source.
const SOURCE_PATH: [&str; 2] = ["/usr/bin", "/bin"];

/// The `#!` interpreters that the program of a secret source starts, as each `#!` line writes
/// them, the nearest first: a path, or `env` and the program that it finds on Box Core's fixed
/// search path. A `#!` line that box cannot follow to a full path is an error: an `env` line
/// other than `env <program>` or `env -S <program>` with the program's own arguments after it, a
/// program that `env` does not find on that search path, or a relative path. So is a chain of more
/// than 8 `#!` lines.
fn source_interpreters(program: &Path) -> Result<Vec<PathBuf>, String> {
    use crate::program::Interpreter;
    let mut found: Vec<PathBuf> = Vec::new();
    let mut current = program.to_path_buf();
    for _ in 0..=8 {
        let Some(real) = crate::host::canonical(&current) else {
            return Ok(found);
        };
        let next = match crate::program::interpreter(&real) {
            Ok(None) => return Ok(found),
            Ok(Some(Interpreter::Path(path))) if path.is_absolute() => path,
            Ok(Some(Interpreter::Named(env, name)))
                if env.is_absolute()
                    && crate::tool::is_program_name(&name)
                    && crate::program::plain_env(&real).as_deref() == Some(name.as_str()) =>
            {
                found.push(env);
                match SOURCE_PATH
                    .iter()
                    .map(|folder| Path::new(folder).join(&name))
                    .find(|path| is_executable_file(path))
                {
                    Some(path) => path,
                    None => return Err(unfollowed(&real)),
                }
            }
            _ => return Err(unfollowed(&real)),
        };
        if found.contains(&next) {
            return Ok(found);
        }
        found.push(next.clone());
        current = next;
    }
    Err(format!(
        "{} starts more than 8 #! interpreters, which box does not follow",
        program.display()
    ))
}

/// The refusal of the program `real`, whose `#!` line box cannot follow to a full path.
fn unfollowed(real: &Path) -> String {
    format!(
        "{} has the #! line `{}`, which names no interpreter that box can check",
        real.display(),
        crate::program::shebang(real).join(" ")
    )
}

/// Existing files named by an extended detected server's arguments.
fn argument_files(arguments: &[String], run: &Run<'_>) -> Vec<PathBuf> {
    arguments
        .iter()
        .flat_map(|argument| {
            let value = argument
                .strip_prefix('-')
                .and_then(|flag| flag.split_once('='))
                .map(|(_, value)| value);
            let path = (!argument.starts_with('-')).then_some(argument.as_str());
            path.into_iter().chain(value)
        })
        .filter(|value| !value.is_empty())
        .map(|value| {
            let path = expand_home(run.home, Path::new(value));
            (run.resolve)(&run.workspace.join(path))
        })
        .filter(|path| path.is_file())
        .collect()
}

/// Refuse a write grant over a protected directory, a write grant in a launcher cache from any
/// process but the servers that its launcher starts, a program under any write grant, an `exec`
/// folder that holds one, and a part of a secret source in a place that a box can write.
fn refuse_reach(profile: &Resolved, run: &Run<'_>) -> Result<(), Error> {
    let mut profile = profile.clone();
    let reaches = reaches(&mut profile);
    let expand = |entry: &str| (run.resolve)(&expand_home(run.home, Path::new(entry)));
    let protected: Vec<PathBuf> = run
        .protected
        .iter()
        .map(|directory| (run.resolve)(directory))
        .collect();
    let grants: Vec<PathBuf> = reaches
        .iter()
        .flat_map(|reach| reach.write.iter().map(|entry| expand(entry)))
        .collect();
    let storage: Vec<PathBuf> = profile
        .storage
        .directories
        .iter()
        .chain(&profile.storage.tool_states)
        .map(|directory| (run.resolve)(directory))
        .collect();
    let launcher_caches: Vec<PathBuf> = profile
        .storage
        .launcher_caches
        .iter()
        .map(|cache| (run.resolve)(cache))
        .collect();
    let scratch = (run.resolve)(&run.instance.directory.join(crate::tool::SCRATCH));
    for reach in &reaches {
        let own_cache = reach
            .table
            .strip_prefix("mcp.")
            .and_then(|name| profile.servers.launcher(name))
            .map(|launcher| (run.resolve)(&launcher.cache));
        for grant in reach.write.iter().map(|entry| expand(entry)) {
            if let Some(cache) = launcher_caches.iter().find(|cache| within(&grant, cache)) {
                if own_cache.as_ref() == Some(cache) {
                    continue;
                }
                return Err(Error::WriteOverProtected {
                    grant,
                    protected: cache.clone(),
                });
            }
            if storage.iter().any(|directory| within(&grant, directory))
                || grant.parent() == Some(scratch.as_path())
            {
                continue;
            }
            if let Some(protected) = protected
                .iter()
                .find(|protected| within(protected, &grant) || within(&grant, protected))
            {
                return Err(Error::WriteOverProtected {
                    grant,
                    protected: protected.clone(),
                });
            }
        }
    }
    for reach in &reaches {
        for exec in reach.exec.iter().map(|entry| expand(entry)) {
            if let Some(grant) = grants.iter().find(|grant| within(grant, &exec)) {
                return Err(Error::WriteUnderExec {
                    exec,
                    grant: grant.clone(),
                });
            }
        }
        let search_path = reach
            .search_path
            .as_deref()
            .map(OsStr::new)
            .into_iter()
            .chain(reach.operator_path.then_some(run.search_path))
            .flat_map(std::env::split_paths);
        let source = reach.table.starts_with("secret-source.");
        let programs = reach
            .command
            .iter()
            .enumerate()
            .filter(|(index, program)| {
                (program.starts_with('/') || program.starts_with('~'))
                    && (*index == 0
                        || (source && names_a_host_path(program))
                        || expand(program).is_file())
            })
            .map(|(_, program)| program)
            .chain(&reach.exec)
            .map(|entry| expand(entry))
            .chain(argument_files(&reach.arguments, run))
            .chain(
                search_path
                    .filter(|directory| directory.is_absolute())
                    .map(|directory| (run.resolve)(&directory)),
            );
        for program in programs {
            let writer = grants
                .iter()
                .filter(|grant| within(&program, grant) || (source && within(grant, &program)))
                .find_map(|grant| {
                    reaches
                        .iter()
                        .find(|owner| {
                            owner.write.iter().any(|entry| expand(entry) == *grant)
                                && (source
                                    || !owner
                                        .write_protected
                                        .iter()
                                        .any(|tree| within(&program, &expand(tree))))
                        })
                        .map(|owner| (grant, owner))
                });
            if let Some((grant, owner)) = writer
                && source
            {
                return Err(Error::SourceProgramUnderWrite {
                    holds: !within(&program, grant),
                    program,
                    grant: grant.clone(),
                    writer: owner.table.clone(),
                });
            }
            if let Some((grant, owner)) = writer {
                let folder = if program.is_dir() {
                    program.clone()
                } else {
                    program
                        .parent()
                        .map_or_else(|| program.clone(), Path::to_path_buf)
                };
                return Err(Error::ProgramUnderWrite {
                    folder,
                    program,
                    grant: grant.clone(),
                    writer: owner.table.clone(),
                });
            }
        }
    }
    for (name, entry) in stdio_servers(&mut profile.mcp) {
        let Some(program) = entry
            .get("command")
            .and_then(|command| command.get(0))
            .and_then(toml::Value::as_str)
            .map(Path::new)
            .filter(|path| path.is_absolute())
        else {
            continue;
        };
        let Some(real) = crate::host::canonical(program) else {
            continue;
        };
        crate::mcp::check_links(program, &real, "its program", run.home, &grants).map_err(
            |reason| Error::Profile {
                path: PathBuf::from(format!("[mcp.{name}] command")),
                line: None,
                reason,
            },
        )?;
    }
    for (scheme, source) in &profile.secret_source {
        let command = with_flag_values(
            strings_in(source.get("command"))
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
        let interpreters = command
            .first()
            .map(|program| source_interpreters(Path::new(program)))
            .transpose()
            .map_err(|reason| Error::Profile {
                path: PathBuf::from(crate::plugin::command_name(
                    scheme,
                    profile.source_owners.get(scheme),
                )),
                line: None,
                reason: format!("its program {reason}; a secret source runs outside every sandbox"),
            })?
            .unwrap_or_default();
        let files = command
            .into_iter()
            .enumerate()
            .map(|(index, file)| {
                let what = if index == 0 {
                    "its program"
                } else {
                    "its file"
                };
                (what, expand_home(run.home, Path::new(&file)))
            })
            .chain(
                interpreters
                    .into_iter()
                    .map(|interpreter| ("its interpreter", interpreter)),
            )
            .filter(|(_, file)| file.is_absolute());
        for (what, file) in files {
            let refused = |reason: String| Error::Profile {
                path: PathBuf::from(crate::plugin::command_name(
                    scheme,
                    profile.source_owners.get(scheme),
                )),
                line: None,
                reason,
            };
            if let Some(root) = writable_root(&file, &profile, run) {
                return Err(refused(format!(
                    "{what} {} lies in {root}, which a box can write; a secret source runs \
                     outside every sandbox",
                    file.display()
                )));
            }
            let Some(real) = crate::host::canonical(&file) else {
                continue;
            };
            crate::mcp::check_links(&file, &real, what, run.home, &grants).map_err(refused)?;
        }
    }
    Ok(())
}

/// The place that a box can write on any run that `path`, as written or real, lies in: the
/// workspace, the run's storage, or a box home.
fn writable_root(path: &Path, profile: &Resolved, run: &Run<'_>) -> Option<&'static str> {
    [
        (run.workspace, "the workspace"),
        (profile.storage.root.as_path(), "the run's storage"),
    ]
    .into_iter()
    .chain(
        run.box_homes
            .iter()
            .map(|box_home| (box_home.as_path(), "the box home")),
    )
    .filter(|(root, _)| !root.as_os_str().is_empty())
    .find(|(root, _)| crate::lang::lies_under(path, root))
    .map(|(_, what)| what)
}

/// Whether a route or an MCP server of `entries` names its placeholder variable in `secret.env`,
/// which Box Core reads only with the `secret-sources` switch.
fn names_secret_env(entries: &toml::Table) -> bool {
    entries.values().any(|entry| {
        entry
            .get("secret")
            .and_then(|secret| secret.get("env"))
            .is_some()
    })
}

/// The permits that `access` gives on the project `workspace`, and the project configuration
/// forbids.
fn project_rules(workspace: &str, access: ProjectAccess) -> Rules {
    let within = |path: &str| {
        format!(
            "context.input.path == {} || context.input.path like {}",
            literal(path),
            pattern_below(path),
        )
    };
    let configuration = format!("{workspace}/{PROJECT_CONFIGURATION}");
    let mut rules = Rules::default();
    let permits: &[(&str, &str)] = match access {
        ProjectAccess::None => &[],
        ProjectAccess::Read => &[("fs:read", "project_read")],
        ProjectAccess::Write => &[
            ("fs:read", "project_read"),
            ("fs:write", "project_write"),
            ("fs:delete", "project_delete"),
            ("fs:move", "project_move"),
        ],
    };
    for (action, id) in permits {
        rules.add(
            id,
            &format!(
                "permit (principal, action == Box::Action::{action:?}, resource) when {{ {} }};",
                within(workspace)
            ),
        );
    }
    if !permits.is_empty() {
        rules.gap();
    }
    for (action, id) in [
        ("fs:write", "project_configuration_write"),
        ("fs:delete", "project_configuration_delete"),
        ("fs:move", "project_configuration_move"),
    ] {
        rules.add(
            id,
            &format!(
                "forbid (principal, action == Box::Action::{action:?}, resource) when {{ {} }};",
                within(&configuration)
            ),
        );
    }
    rules
}

/// Refuse each `deny_write` entry at `at` that exists and is not a folder, which Box Core refuses.
fn refuse_file_protections(
    at: &str,
    entries: &[String],
    resolve: &dyn Fn(&str) -> PathBuf,
) -> Result<(), Error> {
    for entry in entries {
        let path = resolve(entry);
        if path.exists() && !path.is_dir() {
            return Err(Error::Profile {
                path: PathBuf::from(at),
                line: None,
                reason: format!(
                    "{} is not a folder; `deny_write` names a folder, so list the folder that \
                     holds it",
                    path.display()
                ),
            });
        }
    }
    Ok(())
}

/// The `@description` of each rule that a `deny_write` folder writes.
const DENY_WRITE_DESCRIPTION: &str =
    "A deny_write entry in the profile or a pack keeps this folder read-only.";

/// The `@description` of each rule that a profile's `[filesystem] deny` writes.
const DENY_DESCRIPTION: &str = "The profile's [filesystem] deny keeps this path out of the box.";

/// A `forbid` on each write, delete, and move below each `deny_write` folder, and on moving or
/// deleting each folder between it and its write grant.
fn deny_write_rules(rules: &mut Rules, folders: &[(String, Vec<String>)]) {
    for (index, (folder, parents)) in folders.iter().enumerate() {
        let within = format!(
            "context.input.path == {} || context.input.path like {}",
            literal(folder),
            pattern_below(folder),
        );
        rules.gap();
        for (action, id) in [
            ("fs:write", "deny_write_write"),
            ("fs:delete", "deny_write_delete"),
            ("fs:move", "deny_write_move"),
        ] {
            rules.add_described(
                &format!("{id}_{index}"),
                DENY_WRITE_DESCRIPTION,
                &format!(
                    "forbid (principal, action == Box::Action::{action:?}, resource) when {{ {within} }};"
                ),
            );
        }
        if parents.is_empty() {
            continue;
        }
        let parents = parents
            .iter()
            .map(|parent| format!("context.input.path == {}", literal(parent)))
            .collect::<Vec<_>>()
            .join(" || ");
        for (action, id) in [
            ("fs:move", "deny_write_parent_move"),
            ("fs:delete", "deny_write_parent_delete"),
        ] {
            rules.add_described(
                &format!("{id}_{index}"),
                DENY_WRITE_DESCRIPTION,
                &format!(
                    "forbid (principal, action == Box::Action::{action:?}, resource) when {{ {parents} }};"
                ),
            );
        }
    }
}

/// A `forbid` on each read, write, delete, and move of each path in a profile's `[filesystem] deny`
/// and below it, and on moving or deleting each folder between it and the agent's write grant.
fn deny_rules(rules: &mut Rules, paths: &[(String, Vec<String>)]) {
    for (index, (path, parents)) in paths.iter().enumerate() {
        let within = format!(
            "context.input.path == {} || context.input.path like {}",
            literal(path),
            pattern_below(path),
        );
        rules.gap();
        for (action, id) in [
            ("fs:read", "filesystem_deny_read"),
            ("fs:write", "filesystem_deny_write"),
            ("fs:delete", "filesystem_deny_delete"),
            ("fs:move", "filesystem_deny_move"),
        ] {
            rules.add_described(
                &format!("{id}_{index}"),
                DENY_DESCRIPTION,
                &format!(
                    "forbid (principal, action == Box::Action::{action:?}, resource) when {{ {within} }};"
                ),
            );
        }
        if parents.is_empty() {
            continue;
        }
        let parents = parents
            .iter()
            .map(|parent| format!("context.input.path == {}", literal(parent)))
            .collect::<Vec<_>>()
            .join(" || ");
        for (action, id) in [
            ("fs:move", "filesystem_deny_parent_move"),
            ("fs:delete", "filesystem_deny_parent_delete"),
        ] {
            rules.add_described(
                &format!("{id}_{index}"),
                DENY_DESCRIPTION,
                &format!(
                    "forbid (principal, action == Box::Action::{action:?}, resource) when {{ {parents} }};"
                ),
            );
        }
    }
}

/// The profile's policy, then `around`.
fn policy(profile: Option<&str>, around: &str) -> String {
    match profile.filter(|text| !text.trim().is_empty()) {
        Some(text) => format!("{}\n\n{around}", text.trim_end()),
        None => around.to_string(),
    }
}

fn installation_sources(profile: &Resolved) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    for (name, sources) in profile
        .tools
        .found
        .iter()
        .map(|tool| (format!("tool.{}", tool.name), &tool.installation_sources))
        .chain(
            profile
                .servers
                .detected
                .iter()
                .map(|server| (format!("mcp.{}", server.name), &server.installations)),
        )
    {
        for source in sources {
            let _ = writeln!(
                text,
                "# installation {name} {}",
                source.replace(['\n', '\r'], " ")
            );
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_interpreter_through_env_is_found_on_box_cores_search_path() {
        let directory = tempfile::tempdir().expect("a temporary folder");
        let script = directory.path().join("vault");
        let sh = SOURCE_PATH
            .iter()
            .map(|folder| Path::new(folder).join("sh"))
            .find(|path| is_executable_file(path))
            .expect("a sh on /usr/bin:/bin");
        for line in ["#!/usr/bin/env sh", "#!/usr/bin/env -S sh -o errexit=1"] {
            crate::fixtures::write(&script, &format!("{line}\nexit 0\n"));
            crate::fixtures::executable(&script);
            assert_eq!(
                source_interpreters(&script),
                Ok(vec![PathBuf::from("/usr/bin/env"), sh.clone()]),
                "{line}"
            );
        }
        crate::fixtures::write(&script, "#!/usr/bin/env -P /tmp python3\nexit 0\n");
        assert!(source_interpreters(&script).is_err());
    }

    #[test]
    fn a_source_interpreter_that_box_cannot_follow_to_a_full_path_is_an_error() {
        let directory = tempfile::tempdir().expect("a temporary folder");
        let script = directory.path().join("vault");
        for line in [
            "#!python3",
            "#!./python3",
            "#!env sh",
            "#!/usr/bin/env ./sh",
            "#!/usr/bin/env",
            "#!/usr/bin/env PATH=/tmp sh",
            "#!/usr/bin/env -S PATH=/tmp sh",
            "#!/usr/bin/env -S ${TOOL}",
            "#!/usr/bin/env -S -u sh PATH=/tmp sh",
            "#!/usr/bin/env -u sh PATH=/tmp sh",
            "#!/usr/bin/env --split-string=PATH=/tmp sh",
            "#!/usr/bin/env -SBASH_ENV=/tmp/x bash",
            "#!/usr/bin/env -i sh",
            "#!/usr/bin/env -S \"-P\" /tmp python3",
            "#!/usr/bin/env -S '-C' /tmp ./python3",
            "#!/usr/bin/env no-such-program-in-usr-bin",
        ] {
            crate::fixtures::write(&script, &format!("{line}\nexit 0\n"));
            crate::fixtures::executable(&script);
            let real = crate::host::canonical(&script).expect("the script");
            assert_eq!(
                source_interpreters(&script),
                Err(format!(
                    "{} has the #! line `{}`, which names no interpreter that box can check",
                    real.display(),
                    line.trim_start_matches("#!")
                )),
                "{line}"
            );
        }
        let chain = |length: usize| {
            let mut next = PathBuf::from("/bin/sh");
            for step in 0..length {
                let link = directory.path().join(format!("step-{length}-{step}"));
                crate::fixtures::write(&link, &format!("#!{}\nexit 0\n", next.display()));
                crate::fixtures::executable(&link);
                next = link;
            }
            next
        };
        assert_eq!(
            source_interpreters(&chain(8)).map(|found| found.len()),
            Ok(8)
        );
        let long = chain(9);
        assert_eq!(
            source_interpreters(&long),
            Err(format!(
                "{} starts more than 8 #! interpreters, which box does not follow",
                long.display()
            ))
        );
    }
}
