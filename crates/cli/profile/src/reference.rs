use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::lang::{self, Inputs};
use crate::mcp;
use crate::plugin::SECRET_SOURCE;
use crate::profile::Resolved;
use crate::program::Writable;
use crate::storage_files::Protected;
use crate::tool;

/// Where `box run` finds each value a reference names.
pub trait Sources {
    /// The variable `name` of the shell that ran `box run`.
    fn env(&self, name: &str) -> Option<String>;

    /// Each variable of the shell that ran `box run` whose name starts with `prefix`, with its
    /// value.
    fn env_with_prefix(&self, prefix: &str) -> Vec<(String, String)>;

    /// The program `name` on the operator's `PATH`, outside the workspace.
    fn program(&mut self, name: &str) -> Option<PathBuf>;

    /// The first executable `name` on the operator's `PATH`, wherever it lies.
    fn search(&self, name: &str) -> Option<PathBuf>;

    /// The Apple developer folder that `/usr/bin/xcode-select -p` reports.
    fn developer_dir(&mut self) -> Result<String, String>;

    /// The folder of Apple's `xcode-select` stubs.
    fn apple_stubs(&self) -> PathBuf {
        PathBuf::from(crate::host::APPLE_STUBS)
    }

    /// Each directory on the operator's `PATH`.
    fn search_path(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    /// Box Core's judgment of a read grant on `path`: whether it lies in a credential store, or
    /// why a box refuses it.
    fn read_grant(&self, path: &Path) -> Result<bool, (strands_box::GrantRefusal, String)> {
        strands_box::check_read_grant(path).map_err(|error| (error.kind(), error.to_string()))
    }
}

/// `table`, which `lang::merge` produced, with each tool table that names a `program` resolved
/// and every placeholder filled in.
pub(crate) fn resolve(
    merged: lang::Merged,
    launchers: &std::collections::BTreeMap<String, lang::LauncherPack>,
    sources: &mut impl Sources,
    inputs: &Inputs<'_>,
    path: &Path,
) -> Result<Resolved, Error> {
    let credentials = Credentials::of(&merged.table, &merged.sources);
    let additions = merged.mcp_packs.clone();
    let (mut resolved, mcp_sources) = resolve_tools(merged, sources, inputs, path, &credentials)?;
    let programs: Vec<(String, String)> = resolved
        .processes()
        .filter_map(|(label, process)| {
            let label = match label.strip_prefix("tool.") {
                Some(tool) => format!("the tool {tool}"),
                None => "the agent".to_string(),
            };
            Some((label, process.command.first()?.clone()))
        })
        .collect();
    let mut prepared = std::collections::BTreeMap::new();
    let cache_root = inputs.storage.join("mcp-cache");
    let launcher_inputs = Inputs {
        tool_cache: Some(&cache_root),
        ..*inputs
    };
    let mut launcher = |program: &str, command: &str, sources: &mut dyn Sources| {
        let Some(pack) = launchers.get(program) else {
            return Ok(None);
        };
        prepared
            .entry((program.to_string(), command.to_string()))
            .or_insert_with(|| {
                let mut sources = LauncherSources {
                    sources,
                    program,
                    command,
                };
                resolve_launcher(
                    program,
                    &pack.name,
                    pack.merged.clone(),
                    &mut sources,
                    &launcher_inputs,
                    path,
                    &credentials,
                )
            })
            .clone()
    };
    let project = resolved.project_access();
    let stand_ins = mcp::stand_ins(&resolved.egress, &resolved.mcp);
    resolved.servers = mcp::detect(
        &mcp_sources,
        &mut resolved.mcp,
        sources,
        &mcp::Context {
            os: inputs.os,
            home: inputs.home,
            workspace: inputs.workspace,
            project,
            profile: path,
            additions: &additions,
            refusals: &resolved.storage.refusals,
            egress: &resolved.egress,
            programs: &programs,
            agent_env: &resolved.agent.env,
            credentials: &credentials,
            stand_ins: &stand_ins,
        },
        &mut launcher,
    );
    resolved
        .storage
        .launcher_caches
        .extend(resolved.servers.caches());
    Ok(resolved)
}

/// Host sources with one launcher's explicit executable.
struct LauncherSources<'a> {
    sources: &'a mut dyn Sources,
    program: &'a str,
    command: &'a str,
}

impl LauncherSources<'_> {
    fn selects(&self, name: &str) -> bool {
        name == self.program && Path::new(self.command).is_absolute()
    }

    fn selected(&self) -> Option<PathBuf> {
        let path = PathBuf::from(self.command);
        crate::host::is_executable_file(&path).then_some(path)
    }
}

impl Sources for LauncherSources<'_> {
    fn env(&self, name: &str) -> Option<String> {
        self.sources.env(name)
    }

    fn env_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        self.sources.env_with_prefix(prefix)
    }

    fn program(&mut self, name: &str) -> Option<PathBuf> {
        if self.selects(name) {
            self.selected()
        } else {
            self.sources.program(name)
        }
    }

    fn search(&self, name: &str) -> Option<PathBuf> {
        if self.selects(name) {
            self.selected()
        } else {
            self.sources.search(name)
        }
    }

    fn developer_dir(&mut self) -> Result<String, String> {
        self.sources.developer_dir()
    }

    fn search_path(&self) -> Vec<PathBuf> {
        self.sources.search_path()
    }

    fn read_grant(&self, path: &Path) -> Result<bool, (strands_box::GrantRefusal, String)> {
        self.sources.read_grant(path)
    }
}

/// One launcher pack's MCP grants, resolved against its selected executable.
fn resolve_launcher(
    program: &str,
    pack: &str,
    merged: lang::Merged,
    sources: &mut impl Sources,
    inputs: &Inputs<'_>,
    path: &Path,
    credentials: &Credentials,
) -> Result<Option<mcp::Launcher>, String> {
    let (requirements, _) = resolve_tools(merged, sources, inputs, path, credentials)
        .map_err(|error| format!("its launcher pack {pack} is unavailable: {error}"))?;
    let Some(process) = requirements.tool.get(program) else {
        let reason = requirements
            .tools
            .skipped
            .iter()
            .map(|(name, reason)| format!("{name}: {reason}"))
            .collect::<Vec<_>>()
            .join("; ");
        let reason = if reason.is_empty() {
            "not enabled on this host".into()
        } else {
            reason
        };
        return Err(format!("its launcher pack {pack} is unavailable: {reason}"));
    };
    // The server's cache replaces the tool's temporary folder.
    let scratch = crate::tool::scratch(inputs.box_dir.parent().unwrap_or(inputs.box_dir), program);
    if !process.filesystem.write_file.is_empty()
        || process
            .filesystem
            .write
            .iter()
            .any(|entry| Path::new(entry) != inputs.workspace && Path::new(entry) != scratch)
        || !process.filesystem.metadata.is_empty()
        || !process.filesystem.exec.is_empty()
    {
        return Err(format!(
            "its launcher pack {pack} needs filesystem grants that MCP discovery does not import; declare the server in the profile"
        ));
    }
    let Some(found) = requirements
        .tools
        .found
        .iter()
        .find(|tool| tool.name == program)
    else {
        return Ok(None);
    };
    if !found.upgrade_http.is_empty() {
        return Err(format!(
            "its launcher pack {pack} sets `upgrade_http`, which MCP discovery does not import; \
             declare the server in the profile"
        ));
    }
    let cache = inputs.tool_cache.expect("MCP launcher cache").join(program);
    let read = process
        .filesystem
        .read
        .iter()
        .chain(&process.filesystem.read_file)
        .map(PathBuf::from)
        .filter(|entry| entry != inputs.workspace && entry != &cache && entry != &scratch)
        .collect();
    let mut env = process.env.clone();
    if env
        .get("TMPDIR")
        .is_some_and(|value| Path::new(value) == scratch)
    {
        env.insert("TMPDIR".into(), cache.display().to_string());
    }
    let search_path: Vec<PathBuf> = sources
        .search_path()
        .into_iter()
        .filter(|entry| entry.is_absolute())
        .collect();
    if !search_path.is_empty() {
        let mut path: Vec<String> = search_path
            .iter()
            .map(|entry| entry.display().to_string())
            .collect();
        for folder in process
            .env
            .get("PATH")
            .into_iter()
            .flat_map(|value| value.split(':'))
        {
            if !path.iter().any(|entry| entry == folder) {
                path.push(folder.to_string());
            }
        }
        env.insert("PATH".into(), path.join(":"));
    }
    Ok(Some(mcp::Launcher {
        pack: pack.to_string(),
        hosts: found.hosts.clone(),
        env,
        read,
        list: process.filesystem.list.iter().map(PathBuf::from).collect(),
        deny: process.filesystem.deny.clone(),
        cache,
    }))
}

/// Resolve tool requirements without detecting MCP servers or adding another consumer's tools.
fn resolve_tools(
    merged: lang::Merged,
    sources: &mut impl Sources,
    inputs: &Inputs<'_>,
    path: &Path,
    reserved_credentials: &Credentials,
) -> Result<(Resolved, Vec<mcp::Source>), Error> {
    let invalid = |reason: String| Error::Profile {
        path: path.to_path_buf(),
        line: None,
        reason,
    };
    let lang::Merged {
        mut table,
        policy,
        declarations,
        values,
        tool_packs,
        tool_bases,
        hidden_tools,
        grammars,
        mcp_packs: _,
        sources: owners,
    } = merged;
    refuse_hidden_dependencies(&table, &hidden_tools).map_err(invalid)?;
    let writable = Writable {
        workspace: inputs.workspace,
        storage: inputs.storage,
        home: inputs.home,
        box_home: inputs.box_home,
    };
    let (mut tools, roots) = tool::prepare(
        &mut table,
        &tool_packs,
        &tool_bases,
        &hidden_tools,
        sources,
        &writable,
        inputs.os,
    )
    .map_err(invalid)?;
    let credentials = reserved_credentials
        .clone()
        .join(Credentials::of(&table, &owners));
    let expanded = loop {
        let attempt = lang::expand(
            table.clone(),
            declarations.clone(),
            values.clone(),
            sources,
            inputs,
            credentials.clone(),
            roots.clone(),
        );
        match attempt {
            Ok(expanded) => break expanded,
            Err(lang::Unresolved {
                tool: Some((name, why)),
                ..
            }) if table
                .get("tool")
                .and_then(|tools| tools.get(&name))
                .is_some() =>
            {
                if let Some(toml::Value::Table(tables)) = table.get_mut("tool") {
                    tables.remove(&name);
                }
                drop_dependencies(&mut table, &[format!("tool.{name}")]);
                let label = match tool_packs.get(&name) {
                    Some(pack) => format!("{name} ({pack})"),
                    None => name.clone(),
                };
                tools.found.retain(|found| found.name != name);
                tools.skipped.push((label, why));
            }
            Err(unresolved) if unresolved.absent => {
                return Err(Error::NotOnHost {
                    path: path.to_path_buf(),
                    reason: crate::plugin::shown(unresolved.reason, &owners),
                });
            }
            Err(unresolved) => {
                return Err(invalid(crate::plugin::shown(unresolved.reason, &owners)));
            }
        }
    };
    let mut table = expanded.table;
    if let Some(toml::Value::Table(tables)) = table.get_mut("tool") {
        for (name, grammar) in grammars {
            if let Some(toml::Value::Table(tool)) = tables.get_mut(&name) {
                tool.insert("grammar".into(), toml::Value::Table(grammar));
            }
        }
    }
    let mut resolved: Resolved = toml::Value::Table(table)
        .try_into()
        .map_err(|error: toml::de::Error| invalid(error.to_string()))?;
    for found in &mut tools.found {
        found.grammar = resolved
            .tool
            .get(&found.name)
            .and_then(|process| process.grammar.as_ref())
            .and_then(lang::grammar_namespace);
    }
    resolved.storage = expanded.storage;
    resolved.inputs = expanded.inputs;
    resolved.policy = policy;
    resolved.source_owners = owners;
    tools.dropped.extend(expanded.dropped);
    tool::installation_reads(&mut resolved, &mut tools, inputs, &*sources).map_err(invalid)?;
    let run = inputs.box_dir.parent().unwrap_or(inputs.box_dir);
    tool::compose(&mut resolved, &mut tools, inputs.workspace, run);
    tool::refuse_under_writes(&mut resolved, &mut tools, inputs.home);
    // After the checks that need every tool, so a script whose interpreter only `extend` brings
    // in still finds that interpreter's table.
    tool::hide_bases(&mut resolved, &mut tools);
    resolved.tools = tools;
    Ok((resolved, expanded.mcp_sources))
}

/// Refuse a `dependency` on a tool that only a tool pack's `extend` brings in: that tool's table
/// is merged into the tool that extends it and is not a tool of its own, so nothing would meet
/// the dependency.
fn refuse_hidden_dependencies(
    table: &toml::Table,
    hidden: &std::collections::BTreeSet<String>,
) -> Result<(), String> {
    let mut owners: Vec<(String, &toml::Value)> = Vec::new();
    owners.extend(
        table
            .get("agent")
            .map(|agent| ("[agent]".to_string(), agent)),
    );
    for section in ["tool", "mcp"] {
        if let Some(entries) = table.get(section).and_then(toml::Value::as_table) {
            owners.extend(
                entries
                    .iter()
                    .map(|(name, entry)| (format!("[{section}.{name}]"), entry)),
            );
        }
    }
    for (owner, entry) in owners {
        for item in entry
            .get("dependency")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
        {
            if let Some(tool) = item.strip_prefix("tool.")
                && hidden.contains(tool)
            {
                return Err(format!(
                    "`{owner} dependency` names {item}, but only a tool pack's `extend` brings in \
                     that tool, so it is not a tool of its own; name its pack in `packs`, or in a \
                     pack's `include`"
                ));
            }
        }
    }
    Ok(())
}

/// Remove each of `names` from every `dependency` list.
pub(crate) fn drop_dependencies(table: &mut toml::Table, names: &[String]) {
    let mut lists: Vec<&mut toml::Value> = Vec::new();
    for (key, value) in table.iter_mut() {
        match key.as_str() {
            "agent" => lists.extend(value.get_mut("dependency")),
            "tool" | "mcp" => {
                if let Some(entries) = value.as_table_mut() {
                    for (_, entry) in entries.iter_mut() {
                        lists.extend(entry.get_mut("dependency"));
                    }
                }
            }
            _ => {}
        }
    }
    for list in lists {
        if let Some(items) = list.as_array_mut() {
            items.retain(|item| {
                !item
                    .as_str()
                    .is_some_and(|item| names.iter().any(|n| n == item))
            });
        }
    }
}

/// The host variables whose value is a credential, which no input and no `env` entry copies into
/// the box, and the host paths that a secret source protects, which no storage row brings in.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    /// Each variable that an `env://` reference reads or a `secret.env` names.
    routed: Vec<String>,
    /// Each `pass-secret-env` entry of a secret source, with the source that passes it.
    passed: Vec<(String, String)>,
    /// Each `reads` and `deny` entry of a secret source, as `(entry, key, source)`.
    paths: Vec<(String, &'static str, String)>,
}

impl Credentials {
    /// The credentials of `table`, whose secret sources `owners` names by scheme.
    pub fn of(table: &toml::Table, owners: &BTreeMap<String, String>) -> Self {
        let mut routed = Vec::new();
        credential_variables(&toml::Value::Table(table.clone()), &mut routed);
        let mut passed = Vec::new();
        let mut paths = Vec::new();
        let sources = table.get(SECRET_SOURCE).and_then(toml::Value::as_table);
        for (scheme, source) in sources.into_iter().flatten() {
            let owner = owners.get(scheme).map_or(lang::THE_PROFILE, String::as_str);
            let named = crate::plugin::source_name(scheme, owner);
            let strings = |key: &str| {
                source
                    .get(key)
                    .and_then(toml::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(toml::Value::as_str)
            };
            for entry in strings("pass-secret-env") {
                passed.push((entry.to_string(), named.clone()));
            }
            for key in ["reads", "deny"] {
                for entry in strings(key) {
                    paths.push((
                        entry.to_string(),
                        crate::plugin::list_name(key, owner),
                        named.clone(),
                    ));
                }
            }
        }
        Self {
            routed,
            passed,
            paths,
        }
    }

    /// The credentials of the file `owner`, whose table is `table`.
    pub fn of_file(table: &toml::Table, owner: &str) -> Self {
        let owners = table
            .get(SECRET_SOURCE)
            .and_then(toml::Value::as_table)
            .into_iter()
            .flat_map(toml::Table::keys)
            .map(|scheme| (scheme.clone(), owner.to_string()))
            .collect();
        Self::of(table, &owners)
    }

    /// `self` with each credential of `other`.
    pub fn join(mut self, other: Self) -> Self {
        self.routed.extend(other.routed);
        self.passed.extend(other.passed);
        self.paths.extend(other.paths);
        self
    }

    /// Who holds the host's `variable` as a credential, as the end of a refusal, where a
    /// `pass-secret-env` entry that ends with `*` holds each variable with that prefix.
    pub fn holder(&self, variable: &str) -> Option<String> {
        if self.routed.iter().any(|name| name == variable) {
            return Some("a route or a server names as its credential".to_string());
        }
        self.passing(variable)
    }

    /// The secret source that passes the host's `variable` to its program as a credential, as the
    /// end of a sentence, where a `pass-secret-env` entry that ends with `*` covers each variable
    /// with that prefix.
    pub fn passing(&self, variable: &str) -> Option<String> {
        self.passed
            .iter()
            .find(|(entry, _)| match entry.strip_suffix('*') {
                Some(prefix) => variable.starts_with(prefix),
                None => entry == variable,
            })
            .map(|(_, source)| format!("{source} passes to its program as a credential"))
    }

    /// Each `pass-secret-env` entry that names one variable, not a prefix, with its source as the
    /// end of a sentence.
    pub(crate) fn passed_names(&self) -> impl Iterator<Item = (&str, String)> {
        self.passed
            .iter()
            .filter(|(entry, _)| !entry.ends_with('*'))
            .map(|(entry, source)| {
                (
                    entry.as_str(),
                    format!("{source} passes to its program as a credential"),
                )
            })
    }

    /// Each `pass-secret-env` entry that ends with `*`, as its prefix, with its source as the end of
    /// a sentence.
    pub(crate) fn passed_prefixes(&self) -> impl Iterator<Item = (&str, String)> {
        self.passed.iter().filter_map(|(entry, source)| {
            Some((
                entry.strip_suffix('*')?,
                format!("{source} passes to its program as a credential"),
            ))
        })
    }

    /// Each absolute path that a secret source lists in `reads` or `deny`, with `~` as `home`,
    /// once each.
    pub fn protected(&self, home: &Path) -> Vec<Protected> {
        let mut found: Vec<Protected> = Vec::new();
        for (entry, key, source) in &self.paths {
            let path = crate::host::expand_home(home, Path::new(entry));
            if !path.is_absolute() {
                continue;
            }
            let protected = Protected {
                path,
                key,
                source: source.clone(),
            };
            if !found.contains(&protected) {
                found.push(protected);
            }
        }
        found
    }
}

/// Every variable that a credential names: the variable an `env://NAME` reference in `value` reads,
/// or the `secret://NAME` alias of a telemetry reference, after its white space as Box Core reads a
/// telemetry reference, and the placeholder variable that a `secret.env` names.
pub fn credential_variables(value: &toml::Value, found: &mut Vec<String>) {
    match value {
        toml::Value::String(text) => {
            let text = text.trim();
            if let Some(name) = text
                .strip_prefix("env://")
                .or_else(|| text.strip_prefix("secret://"))
            {
                found.push(name.to_string());
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                credential_variables(item, found);
            }
        }
        toml::Value::Table(table) => {
            if let Some(name) = table
                .get("secret")
                .map(lang::unwrapped)
                .and_then(|secret| secret.get("env"))
                .map(lang::unwrapped)
                .and_then(toml::Value::as_str)
            {
                found.push(name.to_string());
            }
            for (_, item) in table {
                credential_variables(item, found);
            }
        }
        _ => {}
    }
}
