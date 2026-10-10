//! The complete configuration that a caller passes to Box.
//!
//! | Input | Kind | Arrives on | What it decides |
//! |---|---|---|---|
//! | `policy` | authority | the configured policy source | which effects are permitted |
//! | `credentials` | authority | the configuration's `[egress.a]` | which secret is attached |
//! | `name` and `box_dir` | state | the configuration | which box this is, and where it keeps private state |
//! | `workload` | selection | `[agent] command`, plus `run`'s trailing argv | which process runs |
//!
//! `run` reads one selected configuration path.
//!
//! | Module | Owns |
//! |---|---|
//! | [`process`] | `[agent]` and `[tool.<name>]`: one `ProcessSpec` each |
//! | [`egress`] | `[egress.a]`: which secret attaches to which request |
//! | [`filesystem`] | the translation of a `ProcessSpec`'s eight lists into containment cells |
//! | `env` | which environment names a process may set, and which Core owns |
//! | [`mcp`] | `[mcp.<name>]`: which local MCP servers exist, and how each starts |
//! | [`telemetry`] | `[telemetry.<label>]`: where a box's decision records go |
//!
//! One module per key that carries a vocabulary. `mod.rs` keeps only the two wire records and the
//! reconciliation of the inputs.

pub(crate) mod egress;
pub(crate) mod env;
pub(crate) mod filesystem;
pub(crate) mod isolation;
pub(crate) mod mcp;
pub(crate) mod process;
pub(crate) mod telemetry;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use policy::{Policy, PolicyEngine};
use serde::{Deserialize, Serialize};

use crate::error::{BoxError, ConfigError};

#[cfg(test)]
use self::egress::routes_for;
use self::egress::{
    EgressEntry, EgressRoute, Protocol, host_of, routes_for_and_remote, validate_egress,
    validate_egress_and_remote,
};
#[cfg(test)]
use self::env::{LOADER_HOOK_PREFIXES, LOADER_HOOKS};
#[cfg(test)]
use self::env::{reserved_workload_environment, valid_environment_name};
use self::process::{ContainedMcp, ProcessSpec};

/// The default credential header, and the one whose convention carries a prefix.
pub(super) const DEFAULT_HEADER: &str = "Authorization";

/// The prefix `Authorization` conventionally carries.
pub(super) const BEARER_PREFIX: &str = "Bearer ";

/// The locator scheme that signs in-boundary rather than attaching at one location.
pub(super) const AWS_SCHEME: &str = "aws";

/// The locator scheme naming a credsd credential source, whose type the daemon reports per request.
pub(super) const CREDSD_SCHEME: &str = "credsd";

/// The locator scheme that provisions a phantom into the workload's environment.
pub(super) const ENV_SCHEME: &str = "env://";

/// The `secret.placement` values an operator may write.
pub(super) const HEADER_PLACEMENT: &str = "header";
pub(super) const BASIC_AUTH_PLACEMENT: &str = "basic_auth";
pub(super) const QUERY_PARAM_PLACEMENT: &str = "query_param";

/// The placement that exists in the vault's vocabulary but has no config spelling.
pub(super) const URL_PATH_PLACEMENT: &str = "url_path";

/// The `secret.inject` values an operator may write. `phantom` is the default: the real secret goes
/// only on a request that carries the route's phantom. `always` attaches it to every request to the
/// destinations, and warns when the phantom is absent or mismatched.
pub(super) const INJECT_PHANTOM: &str = "phantom";
pub(super) const INJECT_ALWAYS: &str = "always";

/// Read the MCP servers declared in one workspace config.
pub(crate) fn read_mcp_servers(path: &Path) -> Result<Vec<mcp::McpServer>, BoxError> {
    let file = ConfigFile::read(path)?;
    mcp::from_entries(&file.mcp)
}

/// A remote MCP server: an `[egress.<name>]` entry speaking `mcp`, resolved to a discovery URL.
pub(crate) struct RemoteMcpServer {
    /// The entry key, which is the server name a rule reads as `context.input.server`.
    pub(crate) name: String,
    /// The Streamable-HTTP endpoint to discover, derived from the destination.
    pub(crate) url: String,
    /// The credential to attach, if the entry names one.
    pub(crate) secret: Option<egress::EgressSecret>,
}

/// Read the remote MCP servers (egress entries speaking `mcp`) from one workspace config.
pub(crate) fn read_remote_mcp_servers(path: &Path) -> Result<Vec<RemoteMcpServer>, BoxError> {
    let file = ConfigFile::read(path)?;
    let (_, remote_mcp) = mcp::partition(&file.mcp)?;
    let mut servers = Vec::new();
    for remote in remote_mcp {
        let Some(destination) = remote.destinations.first() else {
            continue;
        };
        servers.push(RemoteMcpServer {
            name: remote.name,
            url: remote_mcp_url(destination),
            secret: remote.secret,
        });
    }
    Ok(servers)
}

/// Derive the Streamable-HTTP endpoint from an egress destination: `scheme://host[:port]/mcp`.
/// No port or port 443 is HTTPS; port 80 or any other explicit port is plain HTTP, which is how a
/// local fixture on a custom port is reached. `/mcp` is the de-facto endpoint for these servers.
fn remote_mcp_url(destination: &str) -> String {
    let after_scheme = destination
        .split_once("://")
        .map_or(destination, |(_, rest)| rest);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = host_of(destination);
    let port = authority
        .strip_prefix(host)
        .and_then(|rest| rest.strip_prefix(':'))
        .and_then(|port| port.parse::<u16>().ok());
    match port {
        None | Some(443) => format!("https://{host}/mcp"),
        Some(80) => format!("http://{host}/mcp"),
        Some(other) => format!("http://{host}:{other}/mcp"),
    }
}

/// One loaded authority source and the filesystem identity that supplied its bytes.
#[derive(Debug, Clone)]
pub(crate) struct AuthoritySource {
    path: PathBuf,
    opened: Arc<std::fs::File>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl AuthoritySource {
    pub(crate) fn read(path: &Path, kind: &'static str) -> Result<(Self, String), ConfigError> {
        let canonical = path
            .canonicalize()
            .map_err(|source| ConfigError::AuthorityRead {
                kind,
                path: path.to_path_buf(),
                source,
            })?;
        let mut file =
            crate::record::layout::open_without_following(&canonical).map_err(|source| {
                ConfigError::AuthorityRead {
                    kind,
                    path: canonical.clone(),
                    source,
                }
            })?;
        let metadata = file
            .metadata()
            .map_err(|source| ConfigError::AuthorityRead {
                kind,
                path: canonical.clone(),
                source,
            })?;
        if !metadata.is_file() {
            return Err(ConfigError::Contract {
                reason: format!(
                    "{kind} source {} is not a regular file",
                    canonical.display()
                ),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 {
                return Err(ConfigError::Contract {
                    reason: format!(
                        "{kind} source {} has more than one filesystem name",
                        canonical.display()
                    ),
                });
            }
        }
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|source| ConfigError::AuthorityRead {
                kind,
                path: canonical.clone(),
                source,
            })?;
        let source = Self {
            path: canonical,
            opened: Arc::new(file),
            #[cfg(unix)]
            device: {
                use std::os::unix::fs::MetadataExt as _;
                metadata.dev()
            },
            #[cfg(unix)]
            inode: {
                use std::os::unix::fs::MetadataExt as _;
                metadata.ino()
            },
        };
        source.verify(kind)?;
        Ok((source, text))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn opened(&self) -> &std::fs::File {
        &self.opened
    }

    pub(crate) fn matches(&self, candidate: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(candidate)
                .map(|metadata| metadata.dev() == self.device && metadata.ino() == self.inode)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            self.path == candidate
        }
    }

    pub(crate) fn verify(&self, kind: &'static str) -> Result<(), ConfigError> {
        #[cfg(unix)]
        let has_one_name = {
            use std::os::unix::fs::MetadataExt as _;
            self.opened
                .metadata()
                .map(|metadata| metadata.nlink() == 1)
                .unwrap_or(false)
        };
        #[cfg(not(unix))]
        let has_one_name = true;
        if has_one_name && self.matches(&self.path) {
            return Ok(());
        }
        Err(ConfigError::AuthorityChanged {
            kind,
            path: self.path.clone(),
        })
    }
}

/// One complete run configuration, before the box directory supplies its identity.
pub(crate) struct RunContract {
    source: AuthoritySource,
    box_directory: PathBuf,
    workspace: PathBuf,
    file: ConfigFile,
}

impl RunContract {
    /// Read the selected configuration and settle the agent's workspace against `invocation`.
    pub(crate) fn read(path: &Path, invocation: &Path) -> Result<Self, BoxError> {
        let (source, text) = AuthoritySource::read(path, "configuration")?;
        let file = ConfigFile::parse(&text, source.path())?;
        let box_directory = file.box_dir.clone();
        if !box_directory.is_absolute() {
            return Err(ConfigError::Contract {
                reason: format!("`box_dir` must be absolute: {}", box_directory.display()),
            }
            .into());
        }
        crate::record::layout::create_box_directory_if_absent(&box_directory)?;
        let workspace = file
            .agent
            .as_ref()
            .and_then(|agent| agent.workspace.as_deref())
            .unwrap_or(invocation);
        let workspace = workspace
            .canonicalize()
            .map_err(|source| ConfigError::Workspace {
                reason: format!("cannot resolve {}: {source}", workspace.display()),
            })?;
        if !workspace.is_dir() {
            return Err(ConfigError::Workspace {
                reason: format!("{} is not a directory", workspace.display()),
            }
            .into());
        }
        crate::record::workspace::refuse_operator_home(&workspace)?;
        // Every spec's declared home, before anything starts: the box directory holds no home, and a
        // home inside it would be state one box's own interpreters could name.
        for (table, spec) in file.declared_specs() {
            if let Some(home) = spec.env.get("HOME") {
                crate::record::layout::refuse_home_in_box_state(
                    Path::new(home),
                    &box_directory,
                    &table,
                )?;
            }
        }
        Ok(Self {
            source,
            box_directory,
            workspace,
            file,
        })
    }

    pub(crate) fn box_directory(&self) -> &Path {
        &self.box_directory
    }

    /// The agent's effective working directory, canonical.
    pub(crate) fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub(crate) fn validate_declared_directory(&self) -> Result<(), BoxError> {
        self.validate_directory(&self.box_directory)
    }

    pub(crate) fn validate_directory(&self, root: &Path) -> Result<(), BoxError> {
        let root = root
            .canonicalize()
            .map_err(|source| ConfigError::Contract {
                reason: format!("cannot resolve `box_dir` {}: {source}", root.display()),
            })?;
        if root == self.workspace || root.starts_with(&self.workspace) {
            return Err(ConfigError::Contract {
                reason: format!(
                    "`box_dir` {} is equal to or below the agent's workspace {}",
                    root.display(),
                    self.workspace.display()
                ),
            }
            .into());
        }
        if self.source.path().starts_with(&root) {
            return Err(ConfigError::Contract {
                reason: format!(
                    "configuration source {} is inside `box_dir` {}",
                    self.source.path().display(),
                    root.display()
                ),
            }
            .into());
        }
        if let Some(policy_path) = self.file.policy_path(self.source.path()) {
            let canonical =
                policy_path
                    .canonicalize()
                    .map_err(|source| ConfigError::AuthorityRead {
                        kind: "policy",
                        path: policy_path,
                        source,
                    })?;
            if canonical.starts_with(&root) {
                return Err(ConfigError::Contract {
                    reason: format!(
                        "policy source {} is inside `box_dir` {}",
                        canonical.display(),
                        root.display()
                    ),
                }
                .into());
            }
        }
        Ok(())
    }

    pub(crate) fn into_request(
        self,
        root: &crate::record::layout::BoxRoot,
    ) -> Result<ConfigureRequest, BoxError> {
        let policy_path = self.file.policy_path(self.source.path());
        let (mcp_servers, http_mcp) = crate::record::config::mcp::partition(&self.file.mcp)?;
        let contained_mcp = crate::record::config::mcp::contained_specs(&self.file.mcp);
        let (policy, policy_source) = read_authored_policy(
            policy_path.as_deref(),
            mcp_servers.is_empty(),
            &policy_operator()?,
        )?;
        if let Some(source) = &policy_source
            && source.path().starts_with(root.root())
        {
            return Err(ConfigError::Contract {
                reason: format!(
                    "policy source {} is inside `box_dir` {}",
                    source.path().display(),
                    root.root().display()
                ),
            }
            .into());
        }
        // Remote MCP is now declared as `[mcp.<name>] type = "http"`; the retired
        // `[egress.<name>] protocol = "mcp"` spelling is refused so there is one way to name one.
        if let Some((name, _)) = self
            .file
            .egress
            .iter()
            .find(|(_, entry)| entry.protocol == Protocol::Mcp)
        {
            return Err(ConfigError::Contract {
                reason: format!(
                    "`[egress.{name}]` sets `protocol = \"mcp\"`, which is no longer supported; \
                     declare a remote MCP server as `[mcp.{name}]` with `type = \"http\"`"
                ),
            }
            .into());
        }
        // Remote MCP keeps its own collection, separate from the operator's `[egress.*]` entries.
        // A name shared between `[mcp.foo]` and `[egress.foo]` therefore cannot silently overwrite an
        // operator credential binding; the two are validated together so a shared HOST is still
        // refused. Internally each remote server is an egress entry with `protocol = "mcp"`.
        let egress = self.file.egress.clone();
        let remote_mcp: BTreeMap<String, EgressEntry> = http_mcp
            .into_iter()
            .map(|remote| {
                (
                    remote.name,
                    EgressEntry {
                        destinations: remote.destinations,
                        protocol: Protocol::Mcp,
                        secret: remote.secret,
                    },
                )
            })
            .collect();
        validate_egress_and_remote(&egress, &remote_mcp)?;
        let _ = routes_for_and_remote(&egress, &remote_mcp)?;
        let mut sources = vec![self.source];
        if let Some(source) = policy_source {
            sources.push(source);
        }
        Ok(ConfigureRequest {
            record: Record {
                version: RECORD_VERSION,
                box_id: root.box_id().to_string(),
                box_dir: root.root().to_path_buf(),
                name: self.file.name.clone(),
                policy: policy.as_ref().map(|source| source.origin.clone()),
                agent: self.file.agent.clone(),
                tool: self.file.tool.clone(),
                egress,
                remote_mcp,
                mcp: mcp_servers,
                contained_mcp,
                telemetry: telemetry::checked(&self.file.telemetry, root.root())?,
                containment: self.file.containment,
            },
            policy,
            sources,
        })
    }
}

/// What `configure` was given, validated.
pub(crate) struct ConfigureRequest {
    /// The authored Dogwood text, or `None` for a box that grants nothing.
    pub(crate) policy: Option<Policy>,

    /// The record to store, from which every later verb rebuilds the above.
    pub(crate) record: Record,

    /// The loaded source identities that the interpreters protect from mutation.
    pub(crate) sources: Vec<AuthoritySource>,
}

impl ConfigureRequest {
    pub(crate) fn verify_sources(&self) -> Result<(), BoxError> {
        for source in &self.sources {
            source.verify("authority")?;
        }
        Ok(())
    }
}

/// What `configure` stores, and every later verb reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    /// The record format's version.
    pub(crate) version: u32,

    /// The immutable identity that Box generated for this directory.
    pub(crate) box_id: String,

    /// The caller-selected directory that holds this box's private state.
    pub(crate) box_dir: PathBuf,

    /// The operator's name for this box.
    pub(crate) name: String,

    /// Where the operator's policy came from. Diagnostics only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) policy: Option<PathBuf>,

    /// The agent this box runs, as `[agent]` declared it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) agent: Option<ProcessSpec>,

    /// The tools the hosted Shell may start, as `[tool.<name>]` declared them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) tool: BTreeMap<String, ProcessSpec>,

    /// The credential declarations, verbatim.
    #[serde(default, rename = "egress", skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) egress: BTreeMap<String, EgressEntry>,

    /// The remote (HTTP) MCP servers, from `box.toml`'s `[mcp.<name>] type = "http"` tables. Kept in
    /// its own collection rather than folded into `egress`: a name shared between `[mcp.foo]` and
    /// `[egress.foo]` must not let one silently overwrite the other's credential binding. Each entry
    /// is an egress entry with `protocol = "mcp"`, and the gateway routes it beside the plain-HTTP
    /// egress.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) remote_mcp: BTreeMap<String, EgressEntry>,

    /// The MCP servers this box declares, from `box.toml`'s `[mcp.<name>]` tables. See the box
    /// contract in `box/AGENTS.md`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) mcp: Vec<crate::record::config::mcp::McpServer>,

    /// The local MCP servers that run contained, keyed by server name → the `ProcessSpec` their
    /// `[mcp.<name>]` grants describe. Every stdio server has one — containment is not optional —
    /// so this holds exactly the stdio servers in `mcp`. Kept beside `mcp` (which stays
    /// identity-only) so the broker can look up a server's containment at spawn without threading it
    /// through `McpServer`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) contained_mcp: BTreeMap<String, ContainedMcp>,

    /// The telemetry targets this box declares, verbatim.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) telemetry: BTreeMap<String, telemetry::TelemetryEntry>,

    /// The `[containment]` table, verbatim. Absent when it is the default, so a box that never
    /// wrote it stores what it stored before.
    #[serde(
        default,
        skip_serializing_if = "isolation::ContainmentSpec::is_default"
    )]
    pub(crate) containment: isolation::ContainmentSpec,
}

/// The record format this build writes and accepts: version 22 adds the `[containment]` table, whose
/// `private_proc = false` shares the container's `/proc` with every leaf. Version 21 adds `network` to each
/// `[tool.<name>]`, and stores a stdio MCP server's network in its spec's `network`, where version
/// 20 kept a separate `native_egress` flag on `ContainedMcp`. Version 20 names a secret's injection mode
/// `secret.inject`, taking `phantom` or `always`, where version 19 took `secret.phantom` with
/// `strict` or `advisory`. Version 18 names a telemetry target's records with `include`, taking
/// `deny`, `permit`, or `trace`, where version 17 took `signals`.
/// Version 17 adds the `contained_mcp` map (one `ContainedMcp` per stdio MCP server, since every
/// stdio server is now contained), so a v16 record that predates it is refused with a version
/// mismatch rather than silently losing containment. Version 16 dropped the credsd `secret.type`
/// key.
pub(crate) const RECORD_VERSION: u32 = 22;

/// A key an earlier build read, and what replaced it.
struct RemovedKey {
    key: &'static str,
    replacement: &'static str,
}

/// The removed top-level keys, in the order they are reported.
const REMOVED_TOP_LEVEL_KEYS: [RemovedKey; 3] = [
    RemovedKey {
        key: "[filesystem]",
        replacement: "`[agent.filesystem]`, naming each path the agent's own syscalls reach",
    },
    RemovedKey {
        key: "workspace",
        replacement: "`[agent] workspace`, the agent's initial working directory",
    },
    RemovedKey {
        key: "[env]",
        replacement: "`[agent] env`, the agent's literal environment",
    },
];

/// The removed `[agent]` keys.
const REMOVED_AGENT_KEYS: [RemovedKey; 5] = [
    RemovedKey {
        key: "[agent] packs",
        replacement: "nothing: a box reaches its runtime minimum and what `[agent.filesystem]` \
                      names, and its environment is `[agent] env`",
    },
    RemovedKey {
        key: "[agent] code",
        replacement: "`[agent.filesystem] read`",
    },
    RemovedKey {
        key: "[agent] default_command",
        replacement: "`[agent] command`, which a trailing `run` argv appends to",
    },
    RemovedKey {
        key: "[agent] read",
        replacement: "`[agent.filesystem] read`",
    },
    RemovedKey {
        key: "[agent] write",
        replacement: "`[agent.filesystem] write`, which no longer implies read",
    },
];

/// The removed `[telemetry.<label>]` keys.
const REMOVED_TELEMETRY_KEYS: [RemovedKey; 1] = [RemovedKey {
    key: "[telemetry.<label>] signals",
    replacement: "`[telemetry.<label>] include`, naming `deny`, `permit`, or `trace`, where \
                  `trace` covers both the agent's spans and the control plane",
}];

/// The removed `[tool.<name>]` keys.
const REMOVED_TOOL_KEYS: [RemovedKey; 3] = [
    RemovedKey {
        key: "[tool.<name>] exec",
        replacement: "`[tool.<name>] command`, the invocation prefix that selects the tool",
    },
    RemovedKey {
        key: "[tool.<name>] read",
        replacement: "`[tool.<name>.filesystem] read`",
    },
    RemovedKey {
        key: "[tool.<name>] write",
        replacement: "`[tool.<name>.filesystem] write`",
    },
];

/// The one `[tool.<name>.filesystem]` list a tool no longer states. A tool tests existence and
/// reads metadata across the operator home by default, so a per-path `metadata` grant is redundant;
/// `[agent.filesystem]` keeps `metadata`, because the agent box denies existence.
const REMOVED_TOOL_FILESYSTEM_METADATA: RemovedKey = RemovedKey {
    key: "[tool.<name>.filesystem] metadata",
    replacement: "nothing — a tool tests existence and reads metadata across the operator home by \
                  default, so it states no `metadata` list; only `[agent.filesystem]` \
                  takes `metadata`",
};

/// The removed `secret` key of an `[egress.<name>]` or `[mcp.<name>]` entry.
const REMOVED_SECRET_PHANTOM: RemovedKey = RemovedKey {
    key: "secret.phantom",
    replacement: "`secret.inject`: `\"strict\"` is now `\"phantom\"`, and `\"advisory\"` is now \
                  `\"always\"`",
};

const REMOVED_TOOL_FILESYSTEM_EXEC: RemovedKey = RemovedKey {
    key: "[tool.<name>.filesystem] exec",
    replacement: "nothing — a tool runs its whole toolchain through broad exec on macOS, \
                  so it states no `exec` list; only `[agent.filesystem]` takes `exec`",
};

const REMOVED_MCP_FILESYSTEM_METADATA: RemovedKey = RemovedKey {
    key: "[mcp.<name>.filesystem] metadata",
    replacement: "nothing — a stdio MCP server tests existence and reads metadata across the \
                  operator home by default, so it states no `metadata` list; only \
                  `[agent.filesystem]` takes `metadata`",
};

const REMOVED_MCP_FILESYSTEM_EXEC: RemovedKey = RemovedKey {
    key: "[mcp.<name>.filesystem] exec",
    replacement: "nothing — a stdio MCP server runs its whole toolchain through broad exec on \
                  macOS, so it states no `exec` list; only `[agent.filesystem]` takes `exec`",
};

/// The filesystem lists a leaf table no longer states, per `box.toml` section.
const REMOVED_LEAF_FILESYSTEM_LISTS: [(&str, [(&str, &RemovedKey); 2]); 2] = [
    (
        "tool",
        [
            ("metadata", &REMOVED_TOOL_FILESYSTEM_METADATA),
            ("exec", &REMOVED_TOOL_FILESYSTEM_EXEC),
        ],
    ),
    (
        "mcp",
        [
            ("metadata", &REMOVED_MCP_FILESYSTEM_METADATA),
            ("exec", &REMOVED_MCP_FILESYSTEM_EXEC),
        ],
    ),
];

/// Refuse a document that carries a key an earlier build read, naming the key and its replacement.
///
/// `deny_unknown_fields` would refuse them too, and this earlier check is what makes the refusal
/// name where each key went rather than an unknown field.
fn refuse_removed_keys(text: &str, path: &Path) -> Result<(), ConfigError> {
    // A document the probe cannot parse is answered by the caller's own parse, with its own error.
    let Ok(document) = toml::from_str::<toml::Value>(text) else {
        return Ok(());
    };
    let Some(table) = document.as_table() else {
        return Ok(());
    };
    let refuse = |removed: &RemovedKey| ConfigError::RemovedKey {
        path: path.to_path_buf(),
        key: removed.key,
        replacement: removed.replacement,
    };
    for removed in &REMOVED_TOP_LEVEL_KEYS {
        if table.contains_key(removed.key.trim_matches(['[', ']'])) {
            return Err(refuse(removed));
        }
    }
    if let Some(agent) = table.get("agent").and_then(toml::Value::as_table) {
        for removed in &REMOVED_AGENT_KEYS {
            let key = removed.key.trim_start_matches("[agent] ");
            if agent.contains_key(key) {
                return Err(refuse(removed));
            }
        }
    }
    if let Some(tools) = table.get("tool").and_then(toml::Value::as_table) {
        for tool in tools.values().filter_map(toml::Value::as_table) {
            for removed in &REMOVED_TOOL_KEYS {
                let key = removed.key.trim_start_matches("[tool.<name>] ");
                if tool.contains_key(key) {
                    return Err(refuse(removed));
                }
            }
        }
    }
    for (section, lists) in REMOVED_LEAF_FILESYSTEM_LISTS {
        let Some(entries) = table.get(section).and_then(toml::Value::as_table) else {
            continue;
        };
        for entry in entries.values().filter_map(toml::Value::as_table) {
            let Some(filesystem) = entry.get("filesystem").and_then(toml::Value::as_table) else {
                continue;
            };
            for (key, removed) in lists {
                if filesystem.contains_key(key) {
                    return Err(refuse(removed));
                }
            }
        }
    }
    for section in ["egress", "mcp"] {
        let Some(entries) = table.get(section).and_then(toml::Value::as_table) else {
            continue;
        };
        for entry in entries.values().filter_map(toml::Value::as_table) {
            if entry
                .get("secret")
                .and_then(toml::Value::as_table)
                .is_some_and(|secret| secret.contains_key("phantom"))
            {
                return Err(refuse(&REMOVED_SECRET_PHANTOM));
            }
        }
    }
    if let Some(targets) = table.get("telemetry").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            for removed in &REMOVED_TELEMETRY_KEYS {
                let key = removed.key.trim_start_matches("[telemetry.<label>] ");
                if target.contains_key(key) {
                    return Err(refuse(removed));
                }
            }
        }
    }
    Ok(())
}

impl Record {
    /// Parse a stored record, refusing a version this build does not know.
    pub(crate) fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        /// Just enough of the record to read its version, with every other key ignored.
        #[derive(Deserialize)]
        struct Versioned {
            version: u32,
        }

        let stamped: Versioned = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        // The removed keys are judged first, so an older record that carries one names the key
        // rather than a bare version mismatch.
        refuse_removed_keys(text, path)?;
        if stamped.version != RECORD_VERSION {
            return Err(ConfigError::RecordVersion {
                found: stamped.version,
                expected: RECORD_VERSION,
            });
        }

        let record: Self = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        if !valid_box_identity(&record.box_id) {
            return Err(ConfigError::RecordIdentity {
                found: record.box_id,
            });
        }
        BoxName::parse(&record.name)?;
        record.validate_processes()?;
        Ok(record)
    }

    /// Every process table, judged on its own shape.
    fn validate_processes(&self) -> Result<(), ConfigError> {
        if let Some(agent) = &self.agent {
            agent.validate("[agent]")?;
        }
        for (label, tool) in &self.tool {
            tool.validate(&format!("[tool.{label}]"))?;
        }
        for (name, contained) in &self.contained_mcp {
            contained.spec.validate(&format!("[mcp.{name}]"))?;
        }
        Ok(())
    }

    /// The stored `[egress.a]` entries and the remote MCP servers as validated routes, one per
    /// destination, so the gateway learns every plain-HTTP credential and every remote MCP host.
    pub(crate) fn egress_routes(&self) -> Result<Vec<EgressRoute>, BoxError> {
        routes_for_and_remote(&self.egress, &self.remote_mcp)
    }

    /// The remote MCP servers this box declares, as `(host, name)` pairs — one per destination of
    /// each `[mcp.<name>] type = "http"` entry. The gateway matches a connecting host against these
    /// to decide whether to parse the frame and raise `mcp:call`; the name is the table key.
    pub(crate) fn mcp_servers(&self) -> Vec<(String, String)> {
        self.remote_mcp
            .iter()
            .flat_map(|(name, entry)| {
                entry
                    .destinations
                    .iter()
                    .map(move |destination| (host_of(destination).to_string(), name.clone()))
            })
            .collect()
    }

    /// Credential path spellings keyed by the canonical identity of each tool's program, the
    /// identity a `shell:spawn` decision names; tools sharing one identity share one entry.
    pub(crate) fn tool_credential_paths(&self) -> BTreeMap<String, Vec<String>> {
        let Ok(operator_home) = crate::record::layout::operator_home_directory() else {
            return BTreeMap::new();
        };
        let mut paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for spec in self.tool.values() {
            let Ok(program) =
                crate::run::contain::executable::resolve(spec.program(), &spec.search_path())
            else {
                continue;
            };
            let identity = program.granted_path().to_string_lossy().into_owned();
            let spellings = paths.entry(identity).or_default();
            for (_, spelling) in spec.credential_store_entries(&operator_home) {
                if !spellings.contains(&spelling) {
                    spellings.push(spelling);
                }
            }
        }
        paths
    }

    /// The record as TOML, for `configure` to write.
    pub(crate) fn to_toml(&self) -> Result<String, BoxError> {
        toml::to_string_pretty(self).map_err(|source| ConfigError::RecordWrite { source }.into())
    }
}

fn valid_box_identity(identity: &str) -> bool {
    identity.strip_prefix("box-").is_some_and(|suffix| {
        suffix.len() == 16
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

/// The operator a policy loads for, anchored at the operator's own home.
pub(crate) fn policy_operator() -> Result<policy::Operator, BoxError> {
    let home = crate::record::layout::operator_home_directory()?;
    Ok(policy::Operator::unanchored().anchored_at(home))
}

/// Read the authored policy text, keeping its origin for diagnostics and audit.
fn read_authored_policy(
    path: Option<&Path>,
    validate_complete_schema: bool,
    operator: &policy::Operator,
) -> Result<(Option<Policy>, Option<AuthoritySource>), BoxError> {
    let Some(path) = path else {
        return Ok((None, None));
    };
    let (identity, text) = AuthoritySource::read(path, "policy")?;
    let source = Policy {
        origin: identity.path().to_path_buf(),
        text,
    };
    let validation = if validate_complete_schema {
        PolicyEngine::validate(operator, std::slice::from_ref(&source))
    } else {
        PolicyEngine::validate_staged(std::slice::from_ref(&source))
    };
    if let Err(source) = validation {
        return Err(ConfigError::PolicyInvalid {
            path: path.to_path_buf(),
            source,
        }
        .into());
    }
    Ok((Some(source), Some(identity)))
}

/// The name of one persistent box: a single safe path component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoxName(String);

/// The longest box name that leaves room for the sockets under it.
pub(crate) const MAXIMUM_BOX_NAME: usize = 32;

/// Whether one character may appear in a box name, an MCP server name, or an alias filename.
pub(crate) fn nameable(character: char) -> bool {
    matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-')
}

impl BoxName {
    /// Validate `name` as one path component under the box root.
    pub(crate) fn parse(name: &str) -> Result<Self, ConfigError> {
        let invalid = |reason: &str| ConfigError::BoxName {
            name: name.to_string(),
            reason: reason.to_string(),
        };
        if name.is_empty() {
            return Err(invalid("it is empty"));
        }
        if name == "." || name == ".." {
            return Err(invalid("it names a relative directory"));
        }
        if name.len() > MAXIMUM_BOX_NAME {
            return Err(invalid(&format!(
                "it is {} bytes; a name may be at most {MAXIMUM_BOX_NAME}, so it stays one \
                 readable label in a record and in telemetry",
                name.len()
            )));
        }
        if let Some(character) = name.chars().find(|character| !nameable(*character)) {
            return Err(invalid(&format!("it contains {character:?}")));
        }
        Ok(Self(name.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The arguments `run` appends to `[agent] command`, each one UTF-8.
pub(crate) fn trailing_arguments(argv: &[OsString]) -> Result<Vec<String>, ConfigError> {
    argv.iter()
        .map(|argument| {
            argument
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| ConfigError::NotUtf8 {
                    description: "workload argument",
                    value: argument.to_string_lossy().into_owned(),
                })
        })
        .collect()
}

// ── The wire record: the config file as the operator writes it ─────────────────

/// One config file, as written by the operator.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    /// The operator's name for this box, which is one path component.
    name: String,

    /// The caller-selected absolute directory that holds Box state.
    box_dir: PathBuf,

    /// Path to the Dogwood policy file, relative to the config file's directory unless
    /// absolute. Absent means no authored policy, and nothing is granted.
    #[serde(default)]
    policy: Option<PathBuf>,

    /// The agent this box runs.
    #[serde(default)]
    agent: Option<ProcessSpec>,

    /// The tools the hosted Shell may start, keyed by operator label.
    #[serde(default)]
    tool: BTreeMap<String, ProcessSpec>,

    /// The credential declarations: what secret goes on which request.
    #[serde(default, rename = "egress")]
    egress: BTreeMap<String, EgressEntry>,

    /// The MCP servers this box declares, local and remote.
    #[serde(default)]
    mcp: BTreeMap<String, crate::record::config::mcp::McpEntry>,

    /// Where this box's decision records and its agent's own spans go.
    #[serde(default)]
    telemetry: BTreeMap<String, telemetry::TelemetryEntry>,

    /// How the box's contained processes see the host: `[containment] private_proc`.
    #[serde(default)]
    containment: isolation::ContainmentSpec,
}

impl ConfigFile {
    fn read(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text, path)
    }

    fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        refuse_removed_keys(text, path)?;
        let file: Self = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        file.validate()?;
        Ok(file)
    }

    /// The policy path, resolved against the config file's directory.
    fn policy_path(&self, config_path: &Path) -> Option<PathBuf> {
        let policy = self.policy.as_ref()?;
        if policy.is_absolute() {
            return Some(policy.clone());
        }
        Some(
            config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(policy),
        )
    }

    /// Every declared destination as a validated [`EgressRoute`], one per destination.
    #[cfg(test)]
    fn egress_routes(&self) -> Result<Vec<EgressRoute>, BoxError> {
        routes_for(&self.egress)
    }

    /// Reject a config no run could honor, before anything is stored.
    fn validate(&self) -> Result<(), ConfigError> {
        BoxName::parse(&self.name)?;
        if let Some(agent) = &self.agent {
            agent.validate("[agent]")?;
        }
        for (label, tool) in &self.tool {
            validate_tool_label(label)?;
            tool.validate(&format!("[tool.{label}]"))?;
        }
        for (name, contained) in crate::record::config::mcp::contained_specs(&self.mcp) {
            contained.spec.validate(&format!("[mcp.{name}]"))?;
        }
        if cfg!(target_os = "macos") && !self.containment.private_proc {
            return Err(ConfigError::Contract {
                reason: "[containment] private_proc = false is Linux-only: Seatbelt cannot show \
                         the workload other processes"
                    .to_string(),
            });
        }
        validate_egress(&self.egress)
    }

    /// Every declared `ProcessSpec` beside the table that declared it.
    fn declared_specs(&self) -> impl Iterator<Item = (String, &ProcessSpec)> {
        self.agent
            .as_ref()
            .map(|agent| ("[agent]".to_string(), agent))
            .into_iter()
            .chain(
                self.tool
                    .iter()
                    .map(|(label, tool)| (format!("[tool.{label}]"), tool)),
            )
    }
}

/// Refuse a `[tool.<name>]` label that is not one plain component.
fn validate_tool_label(label: &str) -> Result<(), ConfigError> {
    if label.is_empty()
        || matches!(label, "." | "..")
        || label.chars().any(|character| !nameable(character))
    {
        return Err(ConfigError::Process {
            table: format!("[tool.{label}]"),
            reason: "the label must be one component of letters, digits, '.', '_', or '-'"
                .to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // **The egress tests still live here.** They belong in `egress.rs` beside what they test;
    // moving them needs the `load` fixture below, which every other test also uses.

    use super::egress::EgressSecret;
    use super::process::ProcessSpec;
    use clap::Parser as _;

    use crate::command::cli::{Cli, Command, PolicyCommand};

    /// A variable this process has, unreserved and validly named, so an `env://` locator naming it
    /// satisfies [`checked_provisioned_name`]'s presence check.
    fn present_variable() -> String {
        std::env::vars()
            .find(|(name, value)| {
                !value.is_empty()
                    && valid_environment_name(name)
                    && !reserved_workload_environment(name)
            })
            .map(|(name, _)| name)
            .expect("the test process has at least one unreserved non-empty variable")
    }

    /// Parse and validate a body, with a box name supplied when the body carries none.
    /// The box directory every `load` supplies, so a case states only the keys it is about.
    const LOAD_BOX_DIR: &str = "/var/lib/boxes/codex";

    fn load(text: &str) -> Result<ConfigFile, ConfigError> {
        let mut document = String::new();
        if !text.contains("name = ") {
            document.push_str("name = \"codex\"\n");
        }
        if !text.contains("box_dir = ") {
            document.push_str(&format!("box_dir = {LOAD_BOX_DIR:?}\n"));
        }
        document.push_str(text);
        let file: ConfigFile = toml::from_str(&document).expect("test config parses");
        file.validate()?;
        Ok(file)
    }

    /// One `[agent]` with the given command and nothing else.
    fn agent(command: &[&str]) -> ProcessSpec {
        ProcessSpec {
            command: command.iter().map(|word| (*word).to_string()).collect(),
            workspace: None,
            env: Default::default(),
            filesystem: Default::default(),
            network: None,
        }
    }

    /// A stored record with the given agent and egress entries, and nothing else.
    fn record(agent: Option<ProcessSpec>, egress: BTreeMap<String, EgressEntry>) -> Record {
        Record {
            version: RECORD_VERSION,
            box_id: "box-0123456789abcdef".to_string(),
            box_dir: PathBuf::from("/var/lib/boxes/codex"),
            name: "codex".to_string(),
            policy: None,
            agent,
            tool: Default::default(),
            egress,
            remote_mcp: BTreeMap::new(),
            mcp: Vec::new(),
            contained_mcp: BTreeMap::new(),
            telemetry: std::collections::BTreeMap::new(),
            containment: Default::default(),
        }
    }

    // ── The four inputs ────────────────────────────────────────────────────────

    #[test]
    fn box_names_outside_one_safe_component_are_refused() {
        // The name becomes a path component under a directory the profile grants read
        // and write on, so anything but one plain component is authority over wherever
        for name in [
            "",
            ".",
            "..",
            "../escape",
            "a/b",
            "with space",
            "tab\t",
            "n\0ul",
        ] {
            assert!(BoxName::parse(name).is_err(), "{name:?} must be refused");
        }
        for name in ["default", "codex", "my-box", "box_1", "v1.2"] {
            assert_eq!(BoxName::parse(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn a_name_longer_than_one_readable_label_is_refused() {
        let longest = "a".repeat(MAXIMUM_BOX_NAME);
        assert_eq!(BoxName::parse(&longest).unwrap().as_str(), longest);

        let error = BoxName::parse(&"a".repeat(MAXIMUM_BOX_NAME + 1))
            .expect_err("one byte over the cap must be refused");
        assert!(
            error.to_string().contains("readable label"),
            "the refusal must say why the cap exists: {error}"
        );
        // The cap no longer bounds a socket path. `box_dir` does, and
        // `layout.rs::a_box_directory_whose_socket_exceeds_the_platform_limit_is_refused` pins it.
        assert!(
            !error.to_string().contains("Unix-socket"),
            "the name sites no socket now, so the refusal must not claim it does: {error}"
        );
    }

    #[test]
    fn trailing_arguments_keep_their_order_and_refuse_non_utf8() {
        assert_eq!(
            trailing_arguments(&["exec", "--json"].map(OsString::from)).unwrap(),
            ["exec", "--json"]
        );
        assert!(trailing_arguments(&[]).unwrap().is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            let error = trailing_arguments(&[OsString::from_vec(vec![0xff, 0xfe])])
                .expect_err("a non-UTF-8 argument is refused");
            assert!(matches!(error, ConfigError::NotUtf8 { .. }));
        }
    }

    /// **The file carries nine keys**, and a tenth is a load error rather than an ignored key.
    #[test]
    fn the_config_accepts_the_nine_keys_and_refuses_a_tenth() {
        // `name` and `box_dir` are the two required keys, so every accepted spelling carries both.
        let required = "name = \"codex\"\nbox_dir = \"/var/lib/box\"\n";
        for known in [
            format!("{required}[agent]\ncommand = [\"codex\"]"),
            format!("{required}policy = \"policy.dw\""),
            format!("{required}[tool.git]\ncommand = [\"git\"]"),
            format!("{required}[containment]\nprivate_proc = false"),
        ] {
            assert!(
                toml::from_str::<ConfigFile>(&known).is_ok(),
                "{known:?} is a key set this build reads"
            );
        }
        for unknown in [
            format!("{required}workload = [\"codex\"]"),
            format!("{required}command = [\"codex\"]"),
            format!("{required}wat = 1"),
            "[agent]\ncommand = [\"codex\"]".to_string(),
            "name = \"codex\"\n".to_string(),
            "box_dir = \"/var/lib/box\"\n".to_string(),
        ] {
            assert!(
                toml::from_str::<ConfigFile>(&unknown).is_err(),
                "a config carrying {unknown:?} must fail loudly, not be ignored"
            );
        }
    }

    /// **A record written by the previous build is refused**, not loaded without `containment`.
    #[test]
    fn a_v21_record_is_refused_with_a_version_mismatch() {
        let text = toml::to_string(&record(None, BTreeMap::new()))
            .unwrap()
            .replace(&format!("version = {RECORD_VERSION}"), "version = 21");
        let error = Record::parse(&text, Path::new("/box/record.toml")).expect_err("v21 is stale");
        assert!(
            matches!(error, ConfigError::RecordVersion { found: 21, .. }),
            "{error}"
        );
        assert_eq!(RECORD_VERSION, 22, "the [containment] table is version 22");
    }

    #[test]
    fn a_record_round_trips_with_and_without_the_containment_table() {
        for private_proc in [true, false] {
            let mut stored = record(None, BTreeMap::new());
            stored.containment = isolation::ContainmentSpec { private_proc };
            let text = toml::to_string(&stored).unwrap();
            assert_eq!(
                text.contains("[containment]"),
                !private_proc,
                "the default is skipped: {text}"
            );
            assert_eq!(
                Record::parse(&text, Path::new("/box/record.toml")).unwrap(),
                stored
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_shared_proc_is_refused_on_macos() {
        let error = load("[containment]\nprivate_proc = false").expect_err("Linux-only");
        assert!(
            error.to_string().contains(
                "[containment] private_proc = false is Linux-only: Seatbelt cannot show the \
                 workload other processes"
            ),
            "{error}"
        );
    }

    #[test]
    fn a_tool_label_outside_one_component_is_refused() {
        for label in ["\"a b\"", "\"a/b\"", "\"..\""] {
            let refusal = load(&format!("[tool.{label}]\ncommand = [\"x\"]"))
                .expect_err("a label that is not one component is refused");
            assert!(refusal.to_string().contains("one component"), "{refusal}");
        }
    }

    /// **A tool and a stdio MCP server may declare a network table, and the agent may not**, so the
    /// agent's egress always goes through the gateway.
    #[test]
    fn a_tool_table_declares_network_and_the_agent_cannot() {
        for table in [
            "[tool.x]\ncommand = [\"x\"]\n[tool.x.network]\ncontain_egress = false",
            "[tool.x]\ncommand = [\"x\"]\nnetwork = { contain_egress = false }",
        ] {
            let file = load(table).expect("a tool states native egress");
            assert!(file.tool["x"].native_egress(), "{table}");
        }
        let refusal = load("[agent]\ncommand = [\"x\"]\n[agent.network]\ncontain_egress = false")
            .expect_err("an agent network table is refused");
        assert!(
            refusal
                .to_string()
                .contains("`network` is refused on `[agent]`"),
            "the refusal names the key: {refusal}"
        );
        let parsed: Result<ConfigFile, _> = toml::from_str(
            "name = \"b\"\nbox_dir = \"/b\"\n[mcp.x]\ntype = \"stdio\"\ncommand = [\"x\"]\n\
             [mcp.x.network]\ncontain_egress = false",
        );
        assert!(
            parsed.is_ok(),
            "an MCP server states native egress: {parsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_authority_source_refuses_more_than_one_filesystem_name() {
        let directory = tempfile::tempdir().expect("authority directory");
        let source_path = directory.path().join("control.any");
        let hard_link = directory.path().join("control-link");
        std::fs::write(&source_path, "first").expect("source");
        std::fs::hard_link(&source_path, &hard_link).expect("hard link");

        assert!(
            matches!(
                AuthoritySource::read(&source_path, "configuration"),
                Err(ConfigError::Contract { reason })
                    if reason.contains("more than one filesystem name")
            ),
            "an unenumerable authority alias must be refused before the source loads"
        );
        assert_eq!(std::fs::read_to_string(hard_link).unwrap(), "first");
    }

    #[cfg(unix)]
    #[test]
    fn an_authority_source_refuses_a_hard_link_added_after_load() {
        let directory = tempfile::tempdir().expect("authority directory");
        let source_path = directory.path().join("control.any");
        let hard_link = directory.path().join("control-link");
        std::fs::write(&source_path, "first").expect("source");

        let (source, text) =
            AuthoritySource::read(&source_path, "configuration").expect("source loads");
        assert_eq!(text, "first");
        std::fs::hard_link(&source_path, &hard_link).expect("hard link");

        assert!(
            matches!(
                source.verify("configuration"),
                Err(ConfigError::AuthorityChanged { .. })
            ),
            "verification must refuse an alias added after the source loads"
        );
    }

    // ── The wire record ────────────────────────────────────────────────────────

    #[test]
    fn a_minimal_config_declares_a_policy_and_one_credential() {
        let config = load(
            r#"
            policy = "box.cedar"

            [egress.a]
            destinations = ["api.stripe.com"]
            secret.ref = "env://STRIPE_SECRET_KEY"
            "#,
        )
        .expect("valid");

        assert_eq!(config.policy, Some(PathBuf::from("box.cedar")));
        assert_eq!(config.egress.len(), 1);
    }

    /// **`name` and `box_dir` are the whole minimum**, and a file holding them declares nothing
    /// else. Every other key is absent rather than defaulted.
    #[test]
    fn a_config_holding_a_name_and_a_box_directory_declares_nothing_else() {
        let config = load("").expect("valid");
        assert!(config.policy.is_none());
        assert!(config.egress.is_empty());
        assert!(config.agent.is_none());
        assert_eq!(
            config.box_dir,
            Path::new(LOAD_BOX_DIR),
            "the box directory is the one the operator named, never a default"
        );
    }

    /// **An absent `box_dir` is a load error**, because Box sites no box for a caller who names
    /// no directory. Serde produces the refusal, the same way it does for an absent `name`.
    #[test]
    fn an_absent_box_dir_is_refused_by_name() {
        let error = toml::from_str::<ConfigFile>("name = \"codex\"\n")
            .expect_err("a config with no `box_dir` must be refused");
        assert!(
            error.to_string().contains("missing field `box_dir`"),
            "the refusal must name the missing key: {error}"
        );
    }

    /// A relative `box_dir` is refused, because no directory is its root.
    #[test]
    fn a_relative_box_dir_is_refused() {
        let directory = tempfile::tempdir().expect("a config directory");
        let config = directory.path().join("box.toml");
        std::fs::write(&config, "name = \"codex\"\nbox_dir = \"state\"\n").expect("write");

        let error = match RunContract::read(&config, directory.path()) {
            Err(error) => error,
            Ok(_) => panic!("a relative `box_dir` must be refused"),
        };
        assert!(
            error.to_string().contains("`box_dir` must be absolute"),
            "{error}"
        );
        assert!(
            !directory.path().join("state").exists(),
            "a refused `box_dir` must create nothing"
        );
    }

    #[test]
    fn a_relative_policy_path_resolves_beside_the_config() {
        let config = load(r#"policy = "box.cedar""#).expect("valid");
        assert_eq!(
            config.policy_path(Path::new("/etc/boxes/strands-box.toml")),
            Some(PathBuf::from("/etc/boxes/box.cedar")),
            "a relative policy path must not depend on the operator's working directory"
        );
        let absolute = load(r#"policy = "/opt/policies/box.cedar""#).expect("valid");
        assert_eq!(
            absolute.policy_path(Path::new("/etc/boxes/strands-box.toml")),
            Some(PathBuf::from("/opt/policies/box.cedar"))
        );
    }

    /// `type` is gone with remote MCP, so it is now a hard error rather than a dead key.
    #[test]
    fn a_type_key_is_refused() {
        for spelling in ["http", "mcp", "stdio"] {
            let parsed: Result<ConfigFile, _> = toml::from_str(&format!(
                "[egress.a]\ntype = {spelling:?}\ndestinations = [\"api.test\"]\n\
                 secret.ref = \"env://T\""
            ));
            assert!(
                parsed.is_err(),
                "`type` is not a key this build reads, so {spelling:?} must be refused"
            );
        }
    }

    #[test]
    fn an_unknown_field_is_a_load_error() {
        let parsed: Result<ConfigFile, _> = toml::from_str(
            "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://T\"\ncredentail_header = \"x\"",
        );
        assert!(parsed.is_err(), "deny_unknown_fields must reject a typo");

        let top_level: Result<ConfigFile, _> =
            toml::from_str("name = \"codex\"\npolcy = \"box.cedar\"");
        assert!(top_level.is_err(), "a top-level typo must be refused too");
    }

    // ── Wire record → binding ──────────────────────────────────────────────────

    // ── The stored record ──────────────────────────────────────────────────────

    #[test]
    fn a_record_survives_the_gap_between_configure_and_start() {
        let variable = present_variable();
        let mut stored = record(
            None,
            BTreeMap::from([(
                "a".to_string(),
                EgressEntry {
                    destinations: vec!["api.stripe.com".to_string()],
                    protocol: Protocol::Http,
                    secret: Some(EgressSecret {
                        reference: format!("env://{variable}"),
                        header: Some("x-api-key".to_string()),
                        prefix: None,
                        placement: None,
                        param: None,
                        inject: None,
                        phantom_prefix: None,
                    }),
                },
            )]),
        );
        stored.policy = Some(PathBuf::from("/etc/boxes/box.dw"));

        let parsed = Record::parse(&stored.to_toml().unwrap(), Path::new("box.toml")).unwrap();

        assert_eq!(parsed, stored);
        let bindings = parsed
            .egress_routes()
            .expect("the stored authority rebuilds");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].host(), "api.stripe.com");
    }

    #[test]
    fn a_record_without_box_identity_is_refused_even_without_tool_sections() {
        for version in [8, 9] {
            let error = parsed_record(&format!("version = {version}\nname = \"codex\""))
                .expect_err("a record without Box identity cannot load");
            assert!(matches!(
                error,
                ConfigError::RecordVersion { found, expected }
                    if found == version && expected == RECORD_VERSION
            ));
        }
    }

    #[test]
    fn an_old_record_carrying_a_removed_tool_key_is_refused_by_name() {
        let text = r#"
version = 8
name = "codex"

[tool.aws]
exec = ["aws"]
read = []
write = []
env = {}
"#;

        let error =
            parsed_record(text).expect_err("version 8 spells the tool keys this build removed");
        assert!(
            matches!(
                error,
                ConfigError::RemovedKey {
                    key: "[tool.<name>] exec",
                    ..
                }
            ),
            "the removed key is judged before the version: {error}"
        );
    }

    /// **Every key an earlier build read is refused by name, with its replacement**, on a stored
    /// record before the version gate and on an authored file before the unknown-field error.
    #[test]
    fn every_removed_key_is_refused_by_name_with_its_replacement() {
        let cases: [(&str, &str, &str); 17] = [
            (
                "[filesystem]\nworkspace = \"read-write\"\n",
                "[filesystem]",
                "[agent.filesystem]",
            ),
            ("workspace = \"/work\"\n", "workspace", "[agent] workspace"),
            ("[env]\nA = \"b\"\n", "[env]", "[agent] env"),
            (
                "[agent]\npacks = [\"claude\"]\n",
                "[agent] packs",
                "[agent] env",
            ),
            (
                "[agent]\ncode = [\"/a\"]\n",
                "[agent] code",
                "[agent.filesystem] read",
            ),
            (
                "[agent]\ndefault_command = [\"claude\"]\n",
                "[agent] default_command",
                "[agent] command",
            ),
            (
                "[agent]\nread = [\"/a\"]\n",
                "[agent] read",
                "[agent.filesystem] read",
            ),
            (
                "[agent]\nwrite = [\"/a\"]\n",
                "[agent] write",
                "[agent.filesystem] write",
            ),
            (
                "[tool.aws]\nexec = [\"aws\"]\n",
                "[tool.<name>] exec",
                "[tool.<name>] command",
            ),
            (
                "[tool.aws]\nread = [\"/a\"]\n",
                "[tool.<name>] read",
                "[tool.<name>.filesystem] read",
            ),
            (
                "[tool.aws]\nwrite = [\"/a\"]\n",
                "[tool.<name>] write",
                "[tool.<name>.filesystem] write",
            ),
            (
                "[tool.aws.filesystem]\nmetadata = [\"/a\"]\n",
                "[tool.<name>.filesystem] metadata",
                "only `[agent.filesystem]` takes `metadata`",
            ),
            (
                "[tool.aws.filesystem]\nexec = [\"/a\"]\n",
                "[tool.<name>.filesystem] exec",
                "only `[agent.filesystem]` takes `exec`",
            ),
            (
                "[mcp.fetch]\ntype = \"stdio\"\ncommand = [\"fetch\"]\n\
                 [mcp.fetch.filesystem]\nmetadata = [\"/a\"]\n",
                "[mcp.<name>.filesystem] metadata",
                "only `[agent.filesystem]` takes `metadata`",
            ),
            (
                "[mcp.fetch]\ntype = \"stdio\"\ncommand = [\"fetch\"]\n\
                 [mcp.fetch.filesystem]\nexec = [\"/a\"]\n",
                "[mcp.<name>.filesystem] exec",
                "only `[agent.filesystem]` takes `exec`",
            ),
            (
                "[egress.model]\ndestinations = [\"api.example.com\"]\n\
                 secret.ref = \"env://TOKEN\"\nsecret.phantom = \"advisory\"\n",
                "secret.phantom",
                "`\"advisory\"` is now `\"always\"`",
            ),
            (
                "[mcp.github]\ntype = \"http\"\ndestinations = [\"api.githubcopilot.com\"]\n\
                 secret.ref = \"env://TOKEN\"\nsecret.phantom = \"strict\"\n",
                "secret.phantom",
                "`\"strict\"` is now `\"phantom\"`",
            ),
        ];
        let directory = tempfile::tempdir().expect("a config directory");
        for (body, key, replacement) in cases {
            // A record the build before this one wrote, so the key is judged before the version.
            let stale = format!(
                "version = {}\nbox_id = \"box-0123456789abcdef\"\nbox_dir = \"/var/lib/box\"\n\
                 name = \"codex\"\n{body}",
                RECORD_VERSION - 1
            );
            let path = directory.path().join("box.toml");
            std::fs::write(&path, format!("name = \"codex\"\n{body}")).expect("a stale file");
            for message in [
                parsed_record(&stale)
                    .expect_err("a record carrying a removed key must be refused")
                    .to_string(),
                ConfigFile::read(&path)
                    .expect_err("a config carrying a removed key must be refused")
                    .to_string(),
            ] {
                assert!(
                    !message.contains("box record is version")
                        && !message.contains("unknown field"),
                    "{key}: the key is judged before the version and the field set: {message}"
                );
                assert!(
                    message.contains(&format!("`{key}`")) && message.contains(replacement),
                    "{key}: the refusal must name the key and its replacement: {message}"
                );
            }
        }
    }

    /// A v15 credsd record stored `secret.type = "aws"` (the key was required then). After the key's
    /// removal the version gate refuses that record with a version mismatch, so the operator gets a
    /// stale-state remedy rather than a bare `unknown field` serde error.
    #[test]
    fn a_prior_credsd_record_carrying_secret_type_is_refused_by_version() {
        let stale = format!(
            "version = {}\nbox_id = \"box-0123456789abcdef\"\nbox_dir = \"/var/lib/box\"\n\
             name = \"codex\"\n[egress.model]\n\
             destinations = [\"bedrock-runtime.us-east-1.amazonaws.com\"]\n\
             secret.ref = \"credsd://prod\"\nsecret.type = \"aws\"\n",
            RECORD_VERSION - 1
        );
        let message = parsed_record(&stale)
            .expect_err("a prior credsd record must be refused")
            .to_string();
        assert!(
            !message.contains("unknown field"),
            "the version is judged before the field set: {message}"
        );
        assert!(
            message.contains(&(RECORD_VERSION - 1).to_string())
                && message.contains(&RECORD_VERSION.to_string()),
            "the refusal names both versions: {message}"
        );
    }

    /// A foreign version refuses, and the refusal names BOTH versions.
    #[test]
    fn a_record_from_another_format_is_refused() {
        for found in [RECORD_VERSION - 1, RECORD_VERSION + 1] {
            let text = format!("version = {found}\n");

            let error = parsed_record(&text).expect_err("a foreign version must be refused");

            let message = error.to_string();
            assert!(
                message.contains(&found.to_string())
                    && message.contains(&RECORD_VERSION.to_string()),
                "the refusal must name both the found version {found} and the expected \
                 {RECORD_VERSION}: {message}"
            );
            assert!(
                message.contains("empty `box_dir`") && message.contains("stale box state"),
                "the refusal must name a remedy that works for any configured directory: {message}"
            );
        }
    }

    #[test]
    fn a_record_with_an_invalid_box_identity_is_refused() {
        for found in [
            "",
            "box-0123456789abcde",
            "box-0123456789abcdeG",
            "name-0123456789abcdef",
        ] {
            let text = format!(
                "version = {RECORD_VERSION}\n\
                 box_id = {found:?}\n\
                 box_dir = \"/var/lib/box\"\n\
                 name = \"codex\"\n"
            );

            let error = parsed_record(&text).expect_err("an invalid box identity must be refused");
            let message = error.to_string();
            assert!(
                message.contains("record identity") && message.contains("stale box state"),
                "the refusal must name the bad identity and its remedy: {message}"
            );
        }
    }

    // ── The pinned operator home ───────────────────────────────────────────────

    /// The operator home these tests pin, which the box home sits under.
    fn operator_home() -> PathBuf {
        PathBuf::from("/home/strands-box-config-tests")
    }

    /// Run `body` with `HOME` pinned to [`operator_home`].
    fn with_pinned_home<T>(body: impl FnOnce() -> T) -> T {
        crate::test_support::with_operator_home(&operator_home(), body)
    }

    /// Parse a stored record with the operator home pinned.
    fn parsed_record(text: &str) -> Result<Record, ConfigError> {
        with_pinned_home(|| Record::parse(text, Path::new("box.toml")))
    }

    /// **`[agent] env` may set `IS_SANDBOX`, `HOME`, `PATH`, and `TMPDIR`, and may not set a name
    /// Core owns.**
    #[test]
    fn an_agent_env_may_set_the_operators_names_and_not_a_core_owned_one() {
        let file = load(
            "[agent]\ncommand = [\"claude\"]\nenv = { IS_SANDBOX = \"true\", HOME = \"/h\", \
             PATH = \"/usr/bin\", TMPDIR = \"/t\" }\n",
        )
        .expect("the operator's names load");
        assert_eq!(
            file.agent.expect("the table loads").env["IS_SANDBOX"],
            "true"
        );
        for name in [
            "CLAUDE_CODE_TMPDIR",
            "IS_SANDBOX",
            "HOME",
            "PATH",
            "TMPDIR",
            "TERM",
        ] {
            assert!(
                !super::env::reserved_workload_environment(name),
                "{name} is an operator's to set"
            );
        }

        let refusal = load("[agent]\ncommand = [\"claude\"]\nenv = { HTTPS_PROXY = \"x\" }\n")
            .expect_err("proxy routing is Core's");
        assert!(refusal.to_string().contains("HTTPS_PROXY"), "{refusal}");
    }

    #[test]
    fn every_otlp_exporter_spelling_is_reserved() {
        for name in [
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_PROTOCOL",
            "OTEL_EXPORTER_OTLP_HEADERS",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
            "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
            "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
            "OTEL_EXPORTER_OTLP_A_SIGNAL_NOT_INVENTED_YET",
        ] {
            assert!(
                super::env::reserved_workload_environment(name),
                "{name} must be refused: the box owns this family"
            );
        }
        // A name outside the family still works, or the prefix proves nothing.
        assert!(!super::env::reserved_workload_environment(
            "OTEL_SERVICE_NAME"
        ));
        assert!(!super::env::reserved_workload_environment(
            "OTEL_RESOURCE_ATTRIBUTES"
        ));
    }

    /// The loader hooks a phantom may never claim.
    const HOOKS: [&str; 16] = [
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "NODE_OPTIONS",
        "BASH_ENV",
        "ENV",
        "RUBYOPT",
        "PERL5LIB",
        "PERL5OPT",
        "GEM_PATH",
        "CLASSPATH",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
    ];

    /// An interpreter hook may not receive a phantom.
    #[test]
    fn an_interpreter_hook_cannot_receive_a_phantom() {
        // SAFETY: read back only through `bindings()`, and removed below.
        for hook in HOOKS {
            unsafe { std::env::set_var(hook, "/tmp/attacker") };
        }

        let outcome = std::panic::catch_unwind(|| {
            for hook in HOOKS {
                let config = load(&format!(
                    "[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://{hook}\""
                ))
                .expect("the target parses; the refusal is at binding time");
                let Err(error) = config.egress_routes() else {
                    panic!("{hook} loads code, so it must be refused");
                };
                assert!(
                    error.to_string().contains(hook),
                    "the refusal must name the variable: {error}"
                );
            }
        });

        // SAFETY: as above. Removed even when an assertion failed, so a hostile value cannot
        // leak into another test on this process.
        for hook in HOOKS {
            unsafe { std::env::remove_var(hook) };
        }
        if let Err(payload) = outcome {
            std::panic::resume_unwind(payload);
        }

        // Every entry in the production lists must appear in HOOKS, or a hook could be added
        // to the code and never covered here.
        for prefix in LOADER_HOOK_PREFIXES {
            assert!(
                HOOKS.iter().any(|hook| hook.starts_with(prefix)),
                "`{prefix}` is a refused family with no case in this test"
            );
        }
        for hook in LOADER_HOOKS {
            assert!(
                HOOKS.contains(&hook),
                "`{hook}` is refused in production with no case in this test"
            );
        }

        // And an ordinary credential name still works, or the guard proves nothing.
        unsafe { std::env::set_var("MY_API_KEY", "sk-test") };
        let ordinary =
            load("[egress.a]\ndestinations = [\"api.test\"]\nsecret.ref = \"env://MY_API_KEY\"")
                .expect("an ordinary target parses")
                .egress_routes();
        // SAFETY: as above.
        unsafe { std::env::remove_var("MY_API_KEY") };
        assert!(
            ordinary.is_ok(),
            "an ordinary credential name must still be accepted"
        );
    }

    /// The stored record is validated on READ, not merely on write.
    #[test]
    fn a_stored_record_is_revalidated_when_it_is_read() {
        let overlapping = record(
            None,
            BTreeMap::from([
                (
                    "wildcard".to_string(),
                    EgressEntry {
                        destinations: vec!["*.stripe.com".to_string()],
                        protocol: Protocol::Http,
                        secret: Some(EgressSecret {
                            reference: "env://ONE".to_string(),
                            header: None,
                            prefix: None,
                            placement: None,
                            param: None,
                            inject: None,
                            phantom_prefix: None,
                        }),
                    },
                ),
                (
                    "exact".to_string(),
                    EgressEntry {
                        destinations: vec!["api.stripe.com".to_string()],
                        protocol: Protocol::Http,
                        secret: Some(EgressSecret {
                            reference: "env://TWO".to_string(),
                            header: None,
                            prefix: None,
                            placement: None,
                            param: None,
                            inject: None,
                            phantom_prefix: None,
                        }),
                    },
                ),
            ]),
        );

        let error = match overlapping.egress_routes() {
            Ok(_) => panic!("an overlapping stored record must be refused on read"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("overlaps"), "{error}");
    }

    /// A stored record holding an all-hosts host is refused on read too.
    #[test]
    fn a_stored_all_hosts_record_is_refused_when_it_is_read() {
        let all_hosts = record(
            None,
            BTreeMap::from([(
                "a".to_string(),
                EgressEntry {
                    destinations: vec!["*:443".to_string()],
                    protocol: Protocol::Http,
                    secret: Some(EgressSecret {
                        reference: "env://ONE".to_string(),
                        header: None,
                        prefix: None,
                        placement: None,
                        param: None,
                        inject: None,
                        phantom_prefix: None,
                    }),
                },
            )]),
        );

        let error = match all_hosts.egress_routes() {
            Ok(_) => panic!("an all-hosts stored record must be refused on read"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("matches every host"),
            "the refusal must name the reason: {error}"
        );
    }

    #[test]
    fn an_unknown_record_field_is_refused() {
        let text = format!(
            "version = {RECORD_VERSION}\n\
             box_id = \"box-0123456789abcdef\"\n\
             box_dir = \"/var/lib/boxes/codex\"\n\
             name = \"codex\"\n\
             wat = \"x\""
        );

        assert!(
            parsed_record(&text).is_err(),
            "a record carrying a key this build does not know must be refused"
        );
    }

    #[test]
    fn a_stored_identity_and_every_process_survive_the_record_round_trip() {
        let mut agent = agent(&["codex", "--full-auto", "exec"]);
        agent.workspace = Some(PathBuf::from("/workspace/service"));
        agent
            .env
            .insert("HOME".to_string(), "/home/agent".to_string());
        agent.filesystem.read = vec![PathBuf::from("/agents/triage")];
        agent.filesystem.deny = vec![PathBuf::from("/agents/triage/.env")];
        let mut stored = record(Some(agent.clone()), BTreeMap::new());
        stored.egress.insert(
            "model".to_string(),
            EgressEntry {
                destinations: vec!["api.stripe.com".to_string()],
                protocol: Protocol::Http,
                secret: Some(EgressSecret {
                    reference: "env://ONE".to_string(),
                    header: None,
                    prefix: None,
                    placement: None,
                    param: None,
                    inject: None,
                    phantom_prefix: None,
                }),
            },
        );
        let mut git = self::agent(&["git"]);
        git.filesystem.write = vec![PathBuf::from("/workspace/service")];
        stored.tool.insert("git".to_string(), git.clone());

        let parsed = Record::parse(&stored.to_toml().unwrap(), Path::new("box.toml"))
            .expect("the record this build wrote must parse");

        assert_eq!(parsed.box_id, "box-0123456789abcdef");
        assert_eq!(parsed.box_dir, Path::new("/var/lib/boxes/codex"));
        assert_eq!(parsed.name, "codex");
        assert_eq!(
            parsed.agent.as_ref().expect("the agent survives"),
            &agent,
            "the command must survive element-for-element, in order, with its lists"
        );
        assert_eq!(parsed.tool["git"], git);
        assert_eq!(parsed, stored);
    }

    /// A record naming no `[agent]` parses: a box whose workload arrives on the command line every
    /// time is legitimate.
    #[test]
    fn a_record_with_no_agent_still_parses() {
        let text = format!(
            "version = {RECORD_VERSION}\n\
             box_id = \"box-0123456789abcdef\"\n\
             box_dir = \"/var/lib/boxes/codex\"\n\
             name = \"codex\""
        );

        let parsed = parsed_record(&text).expect("a record with no agent still parses");

        assert_eq!(parsed.box_id, "box-0123456789abcdef");
        assert!(
            parsed.agent.is_none(),
            "an absent `[agent]` is no stored program, not an empty one"
        );
        assert!(parsed.egress.is_empty());
        assert!(parsed.tool.is_empty());
    }

    // ── Which box a verb acts on ───────────────────────────────────────────────

    /// **`--config` is the whole selector, and there is no `--name`.** The configuration names
    /// `box_dir`, and `box_dir` is the box, so a name selector would be a second way to say which
    /// box a verb acts on — and the two could disagree.
    #[test]
    fn run_selects_a_box_by_its_configuration_alone() {
        assert!(
            Cli::try_parse_from(["strands-box", "run"]).is_err(),
            "`run` with no `--config` must refuse rather than search for one"
        );
        assert!(
            Cli::try_parse_from([
                "strands-box",
                "run",
                "--name",
                "codex",
                "--config",
                "box.toml",
            ])
            .is_err(),
            "`--name` is not a box argument"
        );

        let parsed = Cli::try_parse_from(["strands-box", "run", "--config", "box.toml"])
            .expect("run accepts one explicit config path");
        assert!(matches!(
            parsed.command,
            Command::Run { config, workload }
                if config == Path::new("box.toml") && workload.is_empty()
        ));
    }

    /// The top-level surface is `run` plus the approved policy-artifact group.
    #[test]
    fn the_command_surface_is_run_and_the_policy_group() {
        use clap::CommandFactory as _;

        let cli = Cli::command();
        let mut verbs: Vec<String> = cli
            .get_subcommands()
            .map(|command| command.get_name().to_string())
            .collect();
        verbs.sort_unstable();

        assert_eq!(
            verbs,
            ["policy", "run"],
            "`run` is the one verb that starts a box, from the complete configuration the \
             operator wrote and `--config` names; it writes no configuration of its own. `policy \
             generate-schema` writes schema artifacts from the workspace's declared MCP servers \
             and installs no authority. `ls`, `stop`, `rm`, and `reset` are withdrawn with the \
             `~/.strands-box/b/` namespace they enumerated: a caller supplies `box_dir`, so Box \
             cannot locate a box it was not handed, and the caller that created the directory \
             owns its lifecycle. `init`, `create`, `update`, `configure`, `inspect`, `exec`, \
             `ports`, `daemon`, and a box `start` are withdrawn too: a verb outside this list is \
             a surface a pentester or an operator was not handed"
        );

        assert!(
            cli.get_subcommands()
                .all(|command| command.get_name() != "daemon"),
            "there is no `daemon` group: the `run` process is the box's trusted half, so there is \
             no second lifecycle to start, stop, restart, or report on \
             (docs/design/decisions.md#one-trusted-process-per-box)"
        );

        let policy = cli
            .get_subcommands()
            .find(|command| command.get_name() == "policy")
            .expect("the approved policy group");
        let policy_commands: Vec<&str> = policy
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect();
        assert_eq!(policy_commands, ["generate-schema"]);

        let parsed = Cli::try_parse_from([
            "strands-box",
            "policy",
            "generate-schema",
            "--config",
            "box.toml",
            "--output-dir",
            "schemas",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Policy {
                command: PolicyCommand::GenerateSchema { config, output_dir }
            } if config == Path::new("box.toml") && output_dir == Path::new("schemas")
        ));
        assert!(
            Cli::try_parse_from(["strands-box", "policy", "generate-schema"]).is_err(),
            "schema generation requires named configuration and output paths"
        );
        assert!(
            Cli::try_parse_from(["strands-box", "policy", "generate-schema", "schemas"]).is_err(),
            "schema generation takes no positional output directory"
        );
        assert!(
            Cli::try_parse_from(["strands-box", "policy", "generate-mcp-schemas"]).is_err(),
            "the replaced command must not remain as a hidden alias"
        );
    }

    #[test]
    fn mcp_configuration_defers_complete_schema_validation() {
        let directory = tempfile::tempdir().expect("configuration directory");
        crate::test_support::with_operator_home(directory.path(), || {
            let workspace = directory.path().join("workspace");
            let box_directory = directory.path().join("box");
            std::fs::create_dir(&workspace).expect("workspace");
            std::fs::create_dir(&box_directory).expect("box directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&box_directory, std::fs::Permissions::from_mode(0o700))
                    .expect("private box directory");
            }
            let policy_path = directory.path().join("policy.dw");
            let config_path = directory.path().join("box.toml");
            std::fs::write(
                &policy_path,
                r#"permit(principal, action == Box::Action::"shell:exec", resource)
               when { context.input.not_in_the_canonical_schema == "value" };"#,
            )
            .expect("write policy");
            std::fs::write(
                &config_path,
                format!(
                    "name = \"codex\"\nbox_dir = {:?}\npolicy = \"policy.dw\"\n\
                 [mcp.alpha]\ntype = \"stdio\"\ncommand = [\"true\"]\n",
                    box_directory.display().to_string()
                ),
            )
            .expect("write MCP configuration");

            let mut root = crate::record::layout::BoxRoot::open_directory(&box_directory)
                .expect("box directory opens");
            root.initialize().expect("box layout initializes");
            let _lock = crate::run::lock::Lock::try_acquire(&root.lock())
                .expect("lock opens")
                .expect("box is free");
            root.settle_identity().expect("identity settles");
            RunContract::read(&config_path, &workspace)
                .expect("run contract loads")
                .into_request(&root)
                .expect("MCP configuration defers complete action-schema validation");

            std::fs::write(
                &config_path,
                format!(
                    "name = \"codex\"\nbox_dir = {:?}\npolicy = \"policy.dw\"\n",
                    box_directory.display().to_string()
                ),
            )
            .expect("write canonical configuration");
            assert!(
                RunContract::read(&config_path, &workspace)
                    .expect("run contract loads")
                    .into_request(&root)
                    .is_err(),
                "configuration without MCP servers must keep strict schema validation"
            );
        });
    }

    /// The load judges a path literal against the operator's home, not the agent's `HOME`.
    #[test]
    fn a_path_literal_is_judged_against_the_operator_home_at_record_load() {
        let directory = tempfile::tempdir().expect("configuration directory");
        crate::test_support::with_operator_home(directory.path(), || {
            let workspace = directory.path().join("workspace");
            let box_directory = directory.path().join("box");
            let agent_home = directory.path().join("agent-home");
            std::fs::create_dir(&workspace).expect("workspace");
            std::fs::create_dir(&box_directory).expect("box directory");
            std::fs::create_dir(&agent_home).expect("agent home");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&box_directory, std::fs::Permissions::from_mode(0o700))
                    .expect("private box directory");
            }
            let policy_path = directory.path().join("policy.dw");
            let config_path = directory.path().join("box.toml");
            std::fs::write(
                &config_path,
                format!(
                    "name = \"codex\"\nbox_dir = {:?}\npolicy = \"policy.dw\"\n\
                     [agent]\ncommand = [\"/usr/bin/true\"]\n[agent.env]\nHOME = {:?}\n",
                    box_directory.display().to_string(),
                    agent_home.display().to_string(),
                ),
            )
            .expect("write configuration");
            let mut root = crate::record::layout::BoxRoot::open_directory(&box_directory)
                .expect("box directory opens");
            root.initialize().expect("box layout initializes");
            let _lock = crate::run::lock::Lock::try_acquire(&root.lock())
                .expect("lock opens")
                .expect("box is free");
            root.settle_identity().expect("identity settles");
            let load = || {
                RunContract::read(&config_path, &workspace)
                    .expect("run contract loads")
                    .into_request(&root)
            };
            let forbid = |literal: &str| {
                std::fs::write(
                    &policy_path,
                    format!(
                        "forbid(principal, action == Box::Action::\"fs:read\", resource)\n\
                         when {{ context.input.path == \"{literal}\" }};\n"
                    ),
                )
                .expect("write policy");
            };

            forbid(&format!(
                "{}/workspace/secrets.env",
                directory.path().display()
            ));
            let refusal = load()
                .err()
                .expect("the absolute spelling is refused")
                .to_string();
            assert!(
                refusal.contains("write \"~/workspace/secrets.env\""),
                "{refusal}"
            );

            forbid(&format!("{}/secrets.env", agent_home.display()));
            let refusal = load()
                .err()
                .expect("the agent home is under the operator home too");
            assert!(
                refusal
                    .to_string()
                    .contains("write \"~/agent-home/secrets.env\""),
                "{refusal}"
            );

            forbid("~/workspace/secrets.env");
            load().expect("the ~ spelling loads");
        });
    }

    /// Write a box.toml whose body (the `[egress.*]`/`[mcp.*]` tables) is `body`, run it through
    /// `into_request`, and return the stored record or the configuration error.
    fn record_from_config(body: &str) -> Result<Record, crate::error::BoxError> {
        let directory = tempfile::tempdir().expect("configuration directory");
        crate::test_support::with_operator_home(directory.path(), || {
            let workspace = directory.path().join("workspace");
            let box_directory = directory.path().join("box");
            std::fs::create_dir(&workspace).expect("workspace");
            std::fs::create_dir(&box_directory).expect("box directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&box_directory, std::fs::Permissions::from_mode(0o700))
                    .expect("private box directory");
            }
            let policy_path = directory.path().join("policy.dw");
            std::fs::write(
                &policy_path,
                "permit (principal, action == Box::Action::\"net:connect\", resource);\n",
            )
            .expect("write policy");
            let config_path = directory.path().join("box.toml");
            std::fs::write(
                &config_path,
                format!(
                    "name = \"codex\"\nbox_dir = {:?}\npolicy = \"policy.dw\"\n{body}",
                    box_directory.display().to_string(),
                ),
            )
            .expect("write configuration");
            let mut root = crate::record::layout::BoxRoot::open_directory(&box_directory)
                .expect("box directory opens");
            root.initialize().expect("box layout initializes");
            let _lock = crate::run::lock::Lock::try_acquire(&root.lock())
                .expect("lock opens")
                .expect("box is free");
            root.settle_identity().expect("identity settles");
            RunContract::read(&config_path, &workspace)
                .expect("run contract loads")
                .into_request(&root)
                .map(|request| request.record)
        })
    }

    /// A name shared between `[egress.foo]` and `[mcp.foo] type = "http"` is not a collision: the two
    /// live in separate collections, so the operator's credential binding is kept, not overwritten.
    #[test]
    fn c1_egress_and_mcp_sharing_a_name_are_both_kept() {
        let record = record_from_config(
            "[egress.foo]\ndestinations = [\"api.stripe.com\"]\nsecret.ref = \"aws://prod\"\n\
             [mcp.foo]\ntype = \"http\"\ndestinations = [\"api.githubcopilot.com\"]\n",
        )
        .expect("a name shared between [egress] and [mcp] is not a collision");

        let egress = record
            .egress
            .get("foo")
            .expect("the operator [egress.foo] entry survives");
        assert_eq!(egress.destinations, ["api.stripe.com"]);
        assert_eq!(egress.protocol, Protocol::Http);
        assert_eq!(
            egress
                .secret
                .as_ref()
                .expect("the operator credential binding is not dropped")
                .reference,
            "aws://prod"
        );

        let remote = record
            .remote_mcp
            .get("foo")
            .expect("the remote MCP server [mcp.foo] is stored");
        assert_eq!(remote.destinations, ["api.githubcopilot.com"]);
        assert_eq!(remote.protocol, Protocol::Mcp);
    }

    /// `[egress.*]` and a remote `[mcp.*]` pointing at the SAME host are refused: the gateway routes a
    /// remote MCP server by host alone, so a host that names one may name nothing else.
    #[test]
    fn c1_egress_and_mcp_on_the_same_host_are_refused() {
        let error = record_from_config(
            "[egress.billing]\ndestinations = [\"api.example.com\"]\nsecret.ref = \"aws://prod\"\n\
             [mcp.search]\ntype = \"http\"\ndestinations = [\"api.example.com\"]\n",
        )
        .expect_err("a host that names a remote MCP server may name nothing else");
        assert!(
            error.to_string().contains("name nothing else"),
            "the refusal must name the host-collision rule: {error}"
        );
    }

    /// A SHARED NAME across `[egress.foo]` and `[mcp.foo]` on the SAME host must still be refused:
    /// the host-collision guard keys on `(origin, name)`, not `name`, so two distinct entries that
    /// happen to share a name do not look like one entry that named its own host twice. Distinct
    /// PATHS do not save it — `mcp_server_for` routes by host alone, so the plain-HTTP path would be
    /// misclassified as this server's `mcp:call`.
    #[test]
    fn c1_egress_and_mcp_same_name_same_host_distinct_paths_are_refused() {
        let error = record_from_config(
            "[egress.foo]\ndestinations = [\"api.example.com/v1/\"]\nsecret.ref = \"aws://prod\"\n\
             [mcp.foo]\ntype = \"http\"\ndestinations = [\"api.example.com/mcp/\"]\n",
        )
        .expect_err("a shared name on the same host is refused even with distinct paths");
        assert!(
            error.to_string().contains("name nothing else"),
            "the refusal must name the host-collision rule: {error}"
        );
    }

    /// Same as above but with distinct explicit PORTS — the host normalizes identically, so the
    /// guard must still fire (the gateway's host match is port-blind).
    #[test]
    fn c1_egress_and_mcp_same_name_same_host_distinct_ports_are_refused() {
        let error = record_from_config(
            "[egress.foo]\ndestinations = [\"api.example.com:443\"]\nsecret.ref = \"aws://prod\"\n\
             [mcp.foo]\ntype = \"http\"\ndestinations = [\"api.example.com:8443\"]\n",
        )
        .expect_err("a shared name on the same host is refused even with distinct ports");
        assert!(
            error.to_string().contains("name nothing else"),
            "the refusal must name the host-collision rule: {error}"
        );
    }

    /// Regression guard for the egress/remote-MCP field split. A remote MCP server declared ONLY in
    /// `[mcp.<name>] type = "http"` lands in `record.remote_mcp`, not `record.egress`, so EVERY
    /// consumer of the split data must read both maps: the credsd preflight (`credsd_environments`),
    /// the gateway host set (`mcp_servers`), and the routes/credentials (`egress_routes`). Each of
    /// these was — or could regress to — a `record.egress`-only reader that silently drops remote MCP,
    /// which a review of this change found twice. If any consumer goes egress-only again, this fails.
    #[test]
    fn c1_a_remote_mcp_only_source_reaches_every_consumer() {
        let host = "bedrock-runtime.us-west-2.amazonaws.com";
        let record = record_from_config(
            "[mcp.remote_bedrock]\ntype = \"http\"\n\
             destinations = [\"bedrock-runtime.us-west-2.amazonaws.com\"]\n\
             secret.ref = \"credsd://prod-inference\"\n",
        )
        .expect("a remote MCP server with a credsd credential is a valid box");

        // Storage: the server is in remote_mcp, and there is no operator [egress.*] entry.
        assert!(record.egress.is_empty(), "no [egress.*] entry was declared");
        assert!(
            record.remote_mcp.contains_key("remote_bedrock"),
            "the remote MCP server lands in record.remote_mcp"
        );

        // credsd preflight: the credsd source is visible over the union of both maps.
        assert_eq!(
            egress::credsd_environments(&record.egress, &record.remote_mcp),
            vec!["prod-inference"],
            "the preflight must see a credsd source declared only on a remote MCP server"
        );

        // Gateway host set: the remote server appears in mcp_servers() so the gateway gates its host.
        assert!(
            record
                .mcp_servers()
                .iter()
                .any(|(h, name)| h == host && name == "remote_bedrock"),
            "mcp_servers() must include the remote MCP server: {:?}",
            record.mcp_servers()
        );

        // Routes/credentials: the remote host gets an egress route so its credential attaches.
        let routes = record.egress_routes().expect("routes build");
        assert!(
            routes.iter().any(|route| route.host() == host),
            "egress_routes() must include the remote MCP host: {:?}",
            routes.iter().map(EgressRoute::host).collect::<Vec<_>>()
        );
    }
}
