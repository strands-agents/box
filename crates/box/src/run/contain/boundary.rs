//! Translating one `ProcessSpec` into the boundary a process runs behind.
//!
//! | Step | Produces |
//! |---|---|
//! | resolve `command` | the one exec literal, and its shebang interpreter chain |
//! | translate `filesystem` | one cell per entry, beneath Core's guards |
//! | add the runtime minimum | what any process on this operating system loads and runs |
//! | add the mediation plumbing | the agent's MCP aliases, the broker socket, the CA |
//! | compose `env` | phantoms beneath the spec's variables beneath Core's own names |

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Seek as _};
use std::path::{Path, PathBuf};

use containment::{ContainmentConfig, Network, Operation, Scope};
use sha2::{Digest as _, Sha256};

use crate::error::{BoxError, ConfigError, TrampolineError};
use crate::record::config::filesystem::{self, DirectGrant, DirectReach, FilesystemContext};
use crate::record::config::process::ProcessSpec;
use crate::record::config::{AuthoritySource, Record};
use crate::record::layout::BoxRoot;
use crate::run::contain::executable;
use crate::run::contain::runtime_minimum::{self, MinimumCell};
use crate::run::hosted::Attachment;

/// Where a `ProcessSpec` is translated: this BoxRun's attachment, layout, record, and loaded
/// authority sources.
pub(crate) struct Site<'a> {
    pub(crate) attachment: &'a Attachment,
    pub(crate) layout: &'a BoxRoot,
    pub(crate) stored: &'a Record,
    pub(crate) protected_sources: &'a [AuthoritySource],
}

/// What the launch role supplies: the arguments after `command`, and the working directory a spec
/// that names none starts in.
pub(crate) struct Launch<'a> {
    /// The table the spec came from, which every refusal and the disclosure name.
    pub(crate) table: &'a str,
    /// Arguments appended after the spec's `command`.
    pub(crate) trailing: &'a [String],
    /// The working directory when the spec names no `workspace`.
    pub(crate) fallback_workspace: &'a Path,
    /// What a shebang hop no `exec` entry covers gets.
    pub(crate) shebang_interpreters: ShebangInterpreters,
    /// Which of Core's two path sets this process receives.
    pub(crate) runtime_reach: RuntimeReach,
    /// What the process reads as `argv[0]` when the caller invoked the command by another spelling.
    pub(crate) argument_zero: Option<&'a Path>,
    /// Where this process's network egress goes: through the gateway (default) or direct/native.
    pub(crate) egress: EgressMode,
    /// The filesystem reach the run judged for this table, or `None` to judge the lists now.
    pub(crate) approved: Option<&'a DirectReach>,
}

/// The filesystem reach of `[agent]` and of every `[tool.<name>]`, judged once when the run starts
/// and acted on at every spawn.
#[derive(Debug)]
pub(crate) struct ApprovedReach {
    tables: BTreeMap<String, DirectReach>,
}

impl ApprovedReach {
    /// Judge every process table's lists, once, before any of them spawns.
    pub(crate) fn judge(
        stored: &Record,
        protected_sources: &[AuthoritySource],
    ) -> Result<Self, BoxError> {
        let agent = stored
            .agent
            .iter()
            .map(|spec| ("[agent]".to_string(), spec));
        let tools = stored
            .tool
            .iter()
            .map(|(label, spec)| (format!("[tool.{label}]"), spec));
        let tables = agent
            .chain(tools)
            .map(|(table, spec)| {
                judge_filesystem(spec, &table, stored, protected_sources)
                    .map(|reach| (table, reach))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(Self { tables })
    }

    /// The reach approved for one table, named as a refusal names it: `[agent]` or `[tool.<name>]`.
    pub(crate) fn table(&self, table: &str) -> Option<&DirectReach> {
        self.tables.get(table)
    }
}

/// Judge one spec's eight lists against this run's operator home, authority, and program search path.
fn judge_filesystem(
    spec: &ProcessSpec,
    table: &str,
    stored: &Record,
    protected_sources: &[AuthoritySource],
) -> Result<DirectReach, BoxError> {
    let operator_home = crate::record::layout::operator_home_directory()?;
    // Canonical, because a `~/` entry resolves against it and carries the identity the kernel
    // checks.
    let canonical_home = operator_home
        .canonicalize()
        .unwrap_or_else(|_| operator_home.clone());
    // Canonical, because every check on it is lexical and the stored spelling can carry `..`.
    let policy = stored
        .policy
        .as_deref()
        .map(crate::record::layout::resolved_to_its_deepest_existing_ancestor);
    let mut authority_directories: Vec<PathBuf> = Vec::new();
    for directory in protected_sources
        .iter()
        .filter_map(|source| source.path().parent().map(Path::to_path_buf))
    {
        if !authority_directories.contains(&directory) {
            authority_directories.push(directory);
        }
    }
    let context = FilesystemContext {
        table,
        operator_home: &canonical_home,
        policy: policy.as_deref(),
        authority_directories,
        // Only when the box declares a server at all: the search path matters because
        // `broker/mcp` execs the declared name against the operator's own `PATH`, outside
        // containment, and every declared name is bare.
        program_search_directories: if stored.mcp.is_empty() {
            Vec::new()
        } else {
            program_search_directories(&std::env::var_os("PATH").unwrap_or_default())
        },
    };
    Ok(filesystem::direct_grants(&spec.filesystem, &context)?)
}

/// Where a process's network egress goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum EgressMode {
    /// Routed through the box's egress gateway (the localhost proxy) — `Network::Localhost`. The
    /// default and the mediated posture: `net:*` policy, credential injection, and audit all apply.
    #[default]
    Gateway,
    /// Direct/native egress that bypasses the gateway — `Network::AllowAll`. The operator-declared
    /// escape (`[mcp.<name>.network] contain_egress = false`) for a workload whose client
    /// cannot honor `HTTPS_PROXY` (e.g. a single sign-on client). It gives up gateway mediation,
    /// credential injection, and per-request `net:*` policy for this process; filesystem containment
    /// still applies.
    Native,
}

impl EgressMode {
    /// The egress a spec's `network` table selects: native only for `contain_egress = false`.
    pub(crate) fn for_spec(spec: &ProcessSpec) -> Self {
        if spec.native_egress() {
            Self::Native
        } else {
            Self::Gateway
        }
    }
}

/// Which operating-system containment Core adds beneath a spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeReach {
    /// Agent containment: the agent's own operating-system runtime cells, and nothing more.
    Agent,
    /// Leaf containment: agent cells plus the operating-system cells needed by a host tool.
    Leaf,
}

impl RuntimeReach {
    /// The cells this reach states, on this host.
    fn cells(self) -> Vec<MinimumCell> {
        match self {
            Self::Agent => runtime_minimum::agent_cells(),
            Self::Leaf => runtime_minimum::leaf_cells(),
        }
    }
}

/// How the translator treats an interpreter a script's shebang names when no `exec` entry covers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShebangInterpreters {
    /// Granted, because the operator authored the command that names it.
    Granted,
    /// Refused, because the workload authored the command that names it.
    MustBeListed,
}

/// The translated boundary for one process.
pub(crate) struct Boundary {
    /// The executable, canonical and prepared.
    executable: PathBuf,

    /// The executable's canonical identity, with every symlink resolved.
    program_identity: PathBuf,

    /// The arguments, in order: the spec's fixed arguments, then the trailing ones.
    arguments: Vec<String>,

    /// The spelling the process reads as `argv[0]`, when it is not the executable's own.
    argument_zero: Option<String>,

    /// The containment config's path and the digest of the exact bytes written.
    containment_config: PathBuf,
    containment_config_file: std::fs::File,
    containment_digest: String,

    /// The process's environment, serialized for the trampoline. Kept as text only for tests; the
    /// trampoline reads [`Self::target_environment_file`].
    #[cfg(test)]
    target_environment: String,
    /// The same bytes as an opened file: the trampoline reads them through a descriptor, never argv.
    target_environment_file: std::fs::File,

    /// Whether this leaf shares the container's `/proc` (`[containment] private_proc = false`).
    shares_proc: bool,

    /// Where the process starts, and what its `PWD` says.
    working_directory: PathBuf,

    /// What the caller prints before the process starts.
    disclosure: String,

    /// Every localhost port the containment config grants, in grant order, for the Linux relay.
    #[cfg(target_os = "linux")]
    served_ports: Vec<u16>,
}

/// Every absolute directory the operator's own `PATH` names.
///
/// `broker/mcp` execs a bare-name MCP program with that `PATH`, outside containment, so these are
/// the directories a writable entry may not reach.
fn program_search_directories(search_path: &OsStr) -> Vec<PathBuf> {
    let mut directories: Vec<PathBuf> = Vec::new();
    for entry in std::env::split_paths(search_path).filter(|directory| directory.is_absolute()) {
        for spelling in search_directory_spellings(&entry) {
            if !directories.contains(&spelling) {
                directories.push(spelling);
            }
        }
    }
    directories
}

/// Every spelling of one search directory that a writable entry could enclose.
fn search_directory_spellings(path: &Path) -> Vec<PathBuf> {
    let mut spellings =
        vec![crate::record::layout::resolved_to_its_deepest_existing_ancestor(path)];
    // A dangling link fails to resolve AT the link, so the walk above answers the link's own path and
    // never reads the target, which is where the workload would plant the program.
    if let Ok(target) = std::fs::read_link(path) {
        let joined = if target.is_absolute() {
            target
        } else {
            path.parent().unwrap_or(Path::new("/")).join(target)
        };
        let resolved = crate::record::layout::resolved_to_its_deepest_existing_ancestor(&joined);
        if !spellings.contains(&resolved) {
            spellings.push(resolved);
        }
    }
    spellings
}

impl Boundary {
    /// Translate one spec into the boundary its process runs behind. The same for the agent and for a
    /// tool: what differs is what the launch role passes in.
    pub(crate) fn translate(
        spec: &ProcessSpec,
        launch: Launch<'_>,
        site: &Site<'_>,
    ) -> Result<Self, BoxError> {
        let layout = site.layout;
        let stored = site.stored;
        let attachment = site.attachment;
        let table = launch.table;

        let operator_home = crate::record::layout::operator_home_directory()?;
        let declared_home = spec.env.get("HOME").map(PathBuf::from);
        if let Some(declared) = &declared_home {
            crate::record::layout::refuse_home_in_box_state(declared, layout.root(), table)?;
        }
        let home = declared_home.unwrap_or_else(|| operator_home.clone());
        let declared_search_path: OsString = spec.search_path();
        let mediated = launch.runtime_reach == RuntimeReach::Agent;
        // A leaf resolves its shebang hops on the search path its own `PATH` holds.
        let interpreter_search_path: OsString = if mediated {
            declared_search_path.clone()
        } else {
            environment::without_alias_directory(&layout.bin_directory(), &declared_search_path)?
        };

        let private_record = layout.record();
        let private = ContainmentConfig::prepare_filesystem_path(
            private_record.parent().expect("the record has a directory"),
        )?;
        // Prepared, because the guard compares canonical identities and the grant side is canonical.
        let box_directory = ContainmentConfig::prepare_filesystem_path(layout.root())?;
        let guard = GuardedBoxState {
            private: private.resolved_path(),
            box_directory: box_directory.resolved_path(),
        };
        // Core's own grants pass the private-state guard alone. Everything the spec states, the
        // command included, is additionally judged against the whole box directory.
        let allow = |config: ContainmentConfig, path: &Path, operation, scope| {
            let prepared = ContainmentConfig::prepare_filesystem_path(path)?;
            require_private_state_absent(
                prepared.resolved_path(),
                operation,
                scope,
                guard.private,
            )?;
            config.allow_prepared(prepared, operation, scope)
        };
        let allow_operator = |config: ContainmentConfig, path: &Path, operation, scope| {
            let prepared = ContainmentConfig::prepare_filesystem_path(path)?;
            guard.judge(prepared.resolved_path(), operation, scope)?;
            config.allow_prepared(prepared, operation, scope)
        };

        // The command: element 0 resolved on the declared search path, granted at file scope, which
        // is the one exec grant every profile carries. It is the identity the profile grants and the
        // string the box execs, so no token expands there, and one that appears is refused rather
        // than left to fail as a search miss.
        if spec.program().contains(environment::OPENING) {
            return Err(ConfigError::Process {
                table: table.to_string(),
                reason: format!(
                    "`command` names the program as {:?}, and a program is never expanded; \
                     write the path",
                    spec.program()
                ),
            }
            .into());
        }
        let program = executable::resolve(spec.program(), &declared_search_path)?;
        let executable_path = program.invoked().to_path_buf();
        let program_identity = program.granted_path().to_path_buf();
        guard.judge(&program_identity, Operation::Exec, Scope::File)?;

        // The working directory: the spec's, else the launch role's. Both are judged the same way,
        // because the launch role's may be a directory the workload chose.
        let (working_directory, spelled) = match &spec.workspace {
            Some(declared) => (declared.as_path(), "`workspace`"),
            None => (launch.fallback_workspace, "the working directory"),
        };
        let working_directory =
            working_directory
                .canonicalize()
                .map_err(|source| ConfigError::Process {
                    table: table.to_string(),
                    reason: format!(
                        "cannot resolve {spelled} {}: {source}",
                        working_directory.display()
                    ),
                })?;
        if !working_directory.is_dir() {
            return Err(ConfigError::Process {
                table: table.to_string(),
                reason: format!(
                    "{spelled} {} is not a directory",
                    working_directory.display()
                ),
            }
            .into());
        }
        crate::record::workspace::refuse_operator_home(&working_directory)?;
        guard.judge(&working_directory, Operation::Metadata, Scope::Dir)?;

        // The list the Linux relay serves, built once and read back by `served_ports()`. Native
        // egress joins the host network and needs no gateway relay, so its list is empty — otherwise
        // the relay would block waiting for a listening descriptor the trampoline never sends.
        let served_ports = match launch.egress {
            EgressMode::Native => Vec::new(),
            EgressMode::Gateway => vec![attachment.proxy_port, attachment.telemetry_port],
        };
        // Native egress bypasses the gateway (AllowAll); the default routes through it (Localhost on
        // the proxy port). Filesystem containment is unchanged either way.
        let network = match launch.egress {
            // `contain_egress = false` is an operator trust grant for a named server: run it with the
            // host's network rather than the box's gateway. macOS renders `AllowAll` as
            // outbound to any IP host and the system resolver; the Linux namespace backend joins the host network namespace
            // (no private netns for this leaf), so the server reaches whatever the host can — the
            // public internet, the VPC, and the host's own services. Every other containment axis
            // (filesystem, PID, user, IPC, seccomp) is unchanged, so the grant is network-only.
            EgressMode::Native => Network::AllowAll,
            EgressMode::Gateway => Network::Localhost {
                connect: served_ports.clone(),
                listen: Vec::new(),
            },
        };
        let mut containment = ContainmentConfig::new()
            .set_network(network)?
            .set_process_info_mode(stored.containment.process_info_mode());
        // A leaf may run a bundled JS/Node runtime that touches host services at
        // startup — `getifaddrs` (net.* sysctls + a routing socket) and `getpwuid` (identity
        // resolution) — dying with no diagnostic without them. Grant those to a leaf.
        if launch.runtime_reach == RuntimeReach::Leaf {
            containment = containment.allow_runtime_services();
        }
        // A judged reach is acted on only while every granted path keeps the identity it was judged
        // with; an MCP server's table is judged here.
        let judged;
        let reach: &DirectReach = match launch.approved {
            Some(approved) => {
                filesystem::require_judged_identities(approved, table)?;
                approved
            }
            None => {
                judged = judge_filesystem(spec, table, stored, site.protected_sources)?;
                &judged
            }
        };
        let exec_trees: Vec<&Path> = reach
            .grants
            .iter()
            .filter(|grant| grant.operation == Operation::Exec && grant.scope == Scope::Root)
            .map(|grant| grant.resolved.as_path())
            .collect();
        let exec_files: Vec<&Path> = reach
            .grants
            .iter()
            .filter(|grant| grant.operation == Operation::Exec && grant.scope == Scope::File)
            .map(|grant| grant.resolved.as_path())
            .collect();
        // The command's own exec rule is implicit and carries the route the box execs; an `exec`
        // entry that names the command is that rule and adds no second cell.
        let command_listed = exec_files.contains(&program_identity.as_path());
        containment =
            containment.allow_prepared(program.into_grant(), Operation::Exec, Scope::File)?;
        let covered_by_exec = |path: &Path| {
            path == program_identity
                || exec_files.contains(&path)
                || exec_trees.iter().any(|tree| path.starts_with(tree))
        };

        // A script's interpreter chain runs too, so each hop is granted exec unless a stated grant
        // already covers it.
        let chain =
            executable::shebang_interpreter_chain(&program_identity, &interpreter_search_path);
        // A hop is granted as spelled and judged by its identity, so a stated `exec` entry naming the
        // identity covers every spelling of it.
        let chain_identities: Vec<PathBuf> = chain
            .iter()
            .map(|hop| hop.canonicalize().unwrap_or_else(|_| hop.clone()))
            .collect();
        let mut interpreters: Vec<PathBuf> = Vec::new();
        let mut interpreter_identities: Vec<&Path> = Vec::new();
        for (spelled, identity) in chain.iter().zip(&chain_identities) {
            if covered_by_exec(identity) || interpreter_identities.contains(&identity.as_path()) {
                continue;
            }
            if launch.shebang_interpreters == ShebangInterpreters::MustBeListed {
                return Err(ConfigError::Process {
                    table: table.to_string(),
                    reason: format!(
                        "{} names the interpreter {}, which no `exec` entry of {table} covers",
                        program_identity.display(),
                        spelled.display()
                    ),
                }
                .into());
            }
            containment = allow_operator(containment, spelled, Operation::Exec, Scope::File)?;
            interpreters.push(spelled.clone());
            interpreter_identities.push(identity);
        }

        // **A stated entry replaces the runtime minimum's cell at the same path.** One path holds
        // one scope, so the operator's spelling wins and Core's own is dropped.
        let stated_paths: Vec<&Path> = reach
            .grants
            .iter()
            .map(|grant| grant.resolved.as_path())
            .collect();
        let mut minimum: Vec<MinimumCell> = Vec::new();
        for cell in launch.runtime_reach.cells() {
            let resolved = cell
                .path
                .canonicalize()
                .unwrap_or_else(|_| cell.path.clone());
            if stated_paths.contains(&resolved.as_path()) || resolved == program_identity {
                continue;
            }
            containment = allow(containment, &cell.path, cell.operation, cell.scope)?;
            minimum.push(cell);
        }
        // The working directory is enterable so `chdir` and `getcwd` work, and neither readable nor
        // enumerable unless a list says so: metadata on the entry itself, and no data.
        let workspace_covered = reach.grants.iter().any(|grant| match grant.scope {
            Scope::Root => working_directory.starts_with(&grant.resolved),
            _ => working_directory == grant.resolved,
        }) || minimum.iter().any(|cell| cell.path == working_directory);
        let mut enterable_workspace = None;
        if !workspace_covered {
            containment = allow_operator(
                containment,
                &working_directory,
                Operation::Metadata,
                Scope::Dir,
            )?;
            enterable_workspace = Some(working_directory.clone());
        }

        // The mediation plumbing, for the agent alone: the five interpreter aliases, one alias per
        // declared MCP server, and the one broker socket. Every process gets the CA.
        if mediated {
            for alias in layout
                .shell_aliases()
                .into_iter()
                .chain(layout.python_aliases())
            {
                containment = allow(containment, &alias, Operation::Exec, Scope::File)?;
            }
            for alias in layout.mcp_aliases(&stored.mcp) {
                containment = allow(containment, &alias, Operation::Exec, Scope::File)?;
            }
            // A `PATH` search reads an absent name in the alias directory as absent, not refused.
            containment = allow(
                containment,
                &layout.bin_directory(),
                Operation::Metadata,
                Scope::Dir,
            )?;
            containment = allow(
                containment,
                &layout.broker_socket(),
                Operation::Connect,
                Scope::File,
            )?;
        }
        let trust_bundle = match attachment.trust_bundle.as_ref() {
            Some(bundle) => {
                // `File` scope, not `Root`: a `Root` grant plans a fresh empty `tmpfs` at the path on
                // Linux, so the workload would see a directory where its CA file should be.
                containment = allow(containment, &bundle.path, Operation::Read, Scope::File)?
                    .protect_write(&bundle.path, &bundle.opened)?;
                Some(bundle.path.clone())
            }
            None => None,
        };

        // The floor anchors its home-relative credential rows at `passwd(getuid())`, which is not
        // this value whenever the two disagree, and the trampoline applies the config with a cleared
        // environment so containment cannot read `$HOME` for itself.
        containment = containment.anchored_at(&operator_home);

        // Leaf discovery: a tool may test existence and read metadata across the
        // operator home, so a probe for optional config returns not-found rather than a fatal
        // refusal; content stays gated by the tool's `read` grants and credential stores stay
        // refused. Leaf-only — the agent box keeps its existence-denied home, so its config and
        // digest are byte-identical. macOS renders it; Linux defers, so the leaf config stays equal
        // to the agent's there too. The deny names this box's own directory, which is what a leaf
        // must not stat. A caller chooses `box_dir`, so no directory above it is a boxes namespace:
        // denying the parent would deny whatever the caller sited the box under, and for a
        // `box_dir` directly in the home that is the home itself, cancelling the grant above.
        #[cfg(target_os = "macos")]
        if launch.runtime_reach == RuntimeReach::Leaf {
            containment = containment
                .allow_discovery(&operator_home)
                .deny_discovery(guard.box_directory);
        }

        // Leaf broad exec: a tool runs its whole toolchain via `process-exec*`
        // and loads what it compiles in its writable workspace, without the box enumerating every
        // helper. Leaf-only and macOS-only — the agent box keeps enumerated exec and full W^X, so
        // its profile is byte-identical; on Linux a read-only bind confers exec already, so the flag
        // is a no-op there. The top-level program was already admitted by `shell:spawn`.
        #[cfg(target_os = "macos")]
        if launch.runtime_reach == RuntimeReach::Leaf {
            containment = containment.allow_broad_exec();
        }

        // **Every refusal the grants need, applied before the grants themselves.** macOS renders
        // these after every allow and Linux overmounts them empty, so each subtracts from the grant
        // rather than sitting beside it.
        for refusal in &reach.refusals {
            containment = containment.refuse(&refusal.path, refusal.scope)?;
        }
        for grant in &reach.grants {
            if grant.operation == Operation::Exec
                && grant.scope == Scope::File
                && grant.resolved == program_identity
            {
                continue;
            }
            containment = if grant.credential_store {
                // The guards judge the canonical identity; the grant itself keeps the authored
                // path, which the credential-store exception validates on its own terms.
                guard.judge(&grant.resolved, grant.operation, grant.scope)?;
                containment.allow_credential_store(&grant.lexical, grant.operation, grant.scope)?
            } else {
                allow_operator(containment, &grant.resolved, grant.operation, grant.scope)?
            };
        }

        containment = protect_authorities(
            containment,
            guard.private,
            site.protected_sources
                .iter()
                .map(|source| (source.path(), source.opened())),
        )?;

        // Every process gets every phantom: docs/design/decisions.md#the-box-is-the-credential-boundary.
        let phantoms: Vec<(String, String)> = attachment
            .phantoms
            .iter()
            .map(|phantom| (phantom.name.clone(), phantom.value.clone()))
            .collect();
        let composed = environment::compose(&environment::Inputs {
            phantoms: &phantoms,
            declared: &spec.env,
            home: &home,
            search_path: &declared_search_path,
            alias_directory: &layout.bin_directory(),
            aliases_first: mediated,
            working_directory: &working_directory,
            attachment,
            trust_bundle: trust_bundle.as_deref(),
        })?;
        let target_environment = serde_json::to_string(&composed)
            .map_err(|source| TrampolineError::Environment { source })?;
        // The environment reaches the trampoline as an opened file, never as argv: argv stays
        // readable in `/proc/<pid>/cmdline` for the launcher's whole life.
        let target_environment_file = layout.write_private_opened_file(
            &layout.containment_config("active-environment"),
            &target_environment,
            0o600,
        )?;

        // Every exec identity inside a writable grant is disclosed, the command and each interpreter
        // hop alike.
        let writable_grant = |identity: &Path| {
            reach.grants.iter().find_map(|grant| {
                (grant.operation == Operation::Write
                    && match grant.scope {
                        Scope::Root => identity.starts_with(&grant.resolved),
                        _ => identity == grant.resolved,
                    })
                .then(|| grant.resolved.clone())
            })
        };
        let writable: Vec<(PathBuf, PathBuf)> = std::iter::once(&program_identity)
            .chain(chain_identities.iter())
            .filter_map(|identity| writable_grant(identity).map(|grant| (identity.clone(), grant)))
            .collect();
        // Mirrors the broad-exec wiring above, so the disclosure names the carve-out exactly when the
        // leaf renders it.
        #[cfg(target_os = "macos")]
        let broad_exec = launch.runtime_reach == RuntimeReach::Leaf;
        #[cfg(not(target_os = "macos"))]
        let broad_exec = false;
        let disclosure = disclosure(&DisclosureInputs {
            table,
            grants: &reach.grants,
            minimum: &minimum,
            interpreters: &interpreters,
            enterable_workspace: enterable_workspace.as_deref(),
            home: &home,
            path: composed.get("PATH").map(String::as_str).unwrap_or_default(),
            writable: &writable,
            program: &program_identity,
            command_listed,
            broad_exec,
            native_egress: launch.egress == EgressMode::Native,
        });

        // The digest covers the exact bytes written, so the trampoline verifies what this process
        // produced rather than whatever is at the path by the time it reads.
        let config_json = containment.to_json()?;
        let containment_digest = Sha256::digest(config_json.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let containment_config = layout.containment_config("active");
        let containment_config_file =
            layout.write_private_opened_file(&containment_config, &config_json, 0o600)?;

        // Only the spec's own arguments expand. The trailing argv is what the operator typed, and a
        // prompt holding `${...}` is prompt text rather than a token.
        let mut arguments: Vec<String> = environment::expanded_arguments(spec, attachment)
            .map_err(|reason| ConfigError::Process {
                table: table.to_string(),
                reason,
            })?;
        arguments.extend(launch.trailing.iter().cloned());
        // The spelling rides beside the identity and never replaces it: the kernel execs the
        // canonical program the decision judged, and the program reads the caller's spelling.
        let argument_zero = launch
            .argument_zero
            .filter(|spelled| *spelled != executable_path.as_path())
            .map(|spelled| spelled.display().to_string());
        Ok(Self {
            working_directory,
            executable: executable_path,
            program_identity,
            arguments,
            argument_zero,
            containment_config,
            containment_config_file,
            containment_digest,
            #[cfg(test)]
            target_environment,
            target_environment_file,
            shares_proc: !stored.containment.private_proc,
            disclosure,
            #[cfg(target_os = "linux")]
            served_ports: served_ports.clone(),
        })
    }

    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(crate) fn program_identity(&self) -> &Path {
        &self.program_identity
    }

    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub(crate) fn argument_zero(&self) -> Option<&Path> {
        self.argument_zero.as_deref().map(Path::new)
    }

    pub(crate) fn containment_config(&self) -> &Path {
        &self.containment_config
    }

    pub(crate) fn containment_config_file(&self) -> &std::fs::File {
        &self.containment_config_file
    }

    #[cfg(test)]
    pub(crate) fn containment_config_text(&self) -> String {
        let mut file = &self.containment_config_file;
        file.seek(std::io::SeekFrom::Start(0))
            .expect("the config descriptor seeks");
        let mut text = String::new();
        file.read_to_string(&mut text)
            .expect("the config descriptor reads");
        file.seek(std::io::SeekFrom::Start(0))
            .expect("the config descriptor rewinds");
        text
    }

    pub(crate) fn containment_digest(&self) -> &str {
        &self.containment_digest
    }

    #[cfg(test)]
    pub(crate) fn target_environment(&self) -> &str {
        &self.target_environment
    }

    pub(crate) fn target_environment_file(&self) -> &std::fs::File {
        &self.target_environment_file
    }

    /// Whether this leaf shares the container's `/proc` (`[containment] private_proc = false`).
    pub(crate) fn shares_proc(&self) -> bool {
        self.shares_proc
    }

    /// Where the process starts, and what its `PWD` says.
    pub(crate) fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// What the caller prints on stderr before the process starts.
    pub(crate) fn disclosure(&self) -> &str {
        &self.disclosure
    }

    /// Every port the Linux relay must receive a descriptor for, in grant order.
    #[cfg(target_os = "linux")]
    pub(crate) fn served_ports(&self) -> &[u16] {
        &self.served_ports
    }
}

/// What the startup disclosure states for one spec.
struct DisclosureInputs<'a> {
    table: &'a str,
    grants: &'a [DirectGrant],
    minimum: &'a [MinimumCell],
    interpreters: &'a [PathBuf],
    enterable_workspace: Option<&'a Path>,
    home: &'a Path,
    path: &'a str,
    writable: &'a [(PathBuf, PathBuf)],
    program: &'a Path,
    command_listed: bool,
    broad_exec: bool,
    native_egress: bool,
}

/// The text a box prints for one spec: every grant no policy decision covers, Core's own additions,
/// and the effective `HOME` and `PATH`.
fn disclosure(inputs: &DisclosureInputs<'_>) -> String {
    let table = inputs.table;
    let mut lines = vec![format!(
        "strands-box: {table} runs {} with no policy decision over these paths:",
        inputs.program.display()
    )];
    if inputs.grants.is_empty() {
        lines.push("  (no filesystem entry)".to_string());
    }
    lines.extend(inputs.grants.iter().map(DirectGrant::disclosure));
    if !inputs.command_listed {
        lines.push(format!(
            "  exec        {}  (command, implicit)",
            inputs.program.display()
        ));
    }
    lines.push(format!(
        "strands-box: {table} runtime minimum, added by Core:"
    ));
    lines.extend(inputs.minimum.iter().map(MinimumCell::disclosure));
    for interpreter in inputs.interpreters {
        lines.push(format!(
            "  exec        {}  (interpreter)",
            interpreter.display()
        ));
    }
    if let Some(workspace) = inputs.enterable_workspace {
        lines.push(format!(
            "  enter       {}  (workspace, entry only)",
            workspace.display()
        ));
    }
    if inputs.broad_exec {
        lines.push(format!(
            "strands-box: {table} broad exec: may run any reachable binary, and \
             load code it writes into its writable grants above"
        ));
    }
    if inputs.native_egress {
        let arguments = if table.starts_with("[tool.") {
            ", with the arguments the agent passes,"
        } else {
            ""
        };
        lines.push(format!(
            "strands-box: {table} native egress: connects to the network directly{arguments} with \
             no egress gateway, no net:connect or http:request decision, and no credential injection"
        ));
    }
    lines.push(format!(
        "strands-box: {table} HOME={} PATH={}",
        inputs.home.display(),
        inputs.path
    ));
    for (identity, grant) in inputs.writable {
        let role = if identity == inputs.program {
            "command"
        } else {
            "interpreter"
        };
        lines.push(format!(
            "strands-box: warning: {table} {role} {} lies inside the writable grant {}, so the \
             process can replace the program it runs",
            identity.display(),
            grant.display()
        ));
    }
    lines.join("\n")
}

fn protect_authorities<'a>(
    mut config: ContainmentConfig,
    private: &Path,
    sources: impl IntoIterator<Item = (&'a Path, &'a std::fs::File)>,
) -> Result<ContainmentConfig, containment::ContainmentError> {
    let invalid = |error: serde_json::Error| {
        containment::ContainmentError::ConfigValidation(format!(
            "cannot inspect recorded containment grants: {error}"
        ))
    };
    let snapshot = serde_json::to_value(&config).map_err(invalid)?;
    let grants: Vec<serde_json::Value> =
        serde_json::from_value(snapshot["paths"].clone()).map_err(invalid)?;
    let mut writes = Vec::new();
    for grant in grants {
        let operation: Operation =
            serde_json::from_value(grant["operation"].clone()).map_err(invalid)?;
        if operation == Operation::Deny {
            continue;
        }
        let path: PathBuf = serde_json::from_value(grant["resolved"].clone()).map_err(invalid)?;
        let scope: Scope = serde_json::from_value(grant["scope"].clone()).map_err(invalid)?;
        require_private_state_absent(&path, operation, scope, private)?;
        if operation == Operation::Write {
            writes.push((path, scope));
        }
    }
    for (source, opened) in sources {
        config = config.require_file_identity(source, opened)?;
        if writes.iter().any(|(path, scope)| {
            source == path || *scope == Scope::Root && source.starts_with(path)
        }) {
            config = config.protect_write(source, opened)?;
        }
    }
    Ok(config)
}

pub(crate) fn require_private_state_absent(
    path: &Path,
    operation: Operation,
    scope: Scope,
    private: &Path,
) -> Result<(), containment::ContainmentError> {
    if path.starts_with(private)
        || operation != Operation::Metadata && scope == Scope::Root && private.starts_with(path)
    {
        return Err(containment::ContainmentError::GrantTooBroad {
            path: path.to_path_buf(),
            reason: "the grant would expose private Box state",
        });
    }
    Ok(())
}

/// The box's own paths no operator-derived grant may reach, canonicalized once by the caller.
pub(crate) struct GuardedBoxState<'a> {
    /// The box's private-state directory, canonical.
    pub(crate) private: &'a Path,
    /// The box's own directory, canonical.
    pub(crate) box_directory: &'a Path,
}

impl GuardedBoxState<'_> {
    /// Refuse an operator-derived grant that reaches into or encloses the box's own directory.
    pub(crate) fn judge(
        &self,
        path: &Path,
        operation: Operation,
        scope: Scope,
    ) -> Result<(), containment::ContainmentError> {
        require_private_state_absent(path, operation, scope, self.private)?;
        require_box_directory_absent(path, operation, scope, self.box_directory)
    }
}

/// Refuse an operator-derived grant that reaches into or encloses the box's own directory.
///
/// The box's own grants, `bin/`, the socket, `trust/`, do not route through this check, so it
/// judges only what a configuration states.
pub(crate) fn require_box_directory_absent(
    path: &Path,
    operation: Operation,
    scope: Scope,
    box_directory: &Path,
) -> Result<(), containment::ContainmentError> {
    if path.starts_with(box_directory)
        || operation != Operation::Metadata
            && scope == Scope::Root
            && box_directory.starts_with(path)
    {
        return Err(containment::ContainmentError::GrantTooBroad {
            path: path.to_path_buf(),
            reason: "the grant would expose the Box's own directory",
        });
    }
    Ok(())
}

/// Read one opened CA after refusing content that is not a public certificate bundle.
pub(crate) fn read_certificate_bundle(
    path: &Path,
    opened: &std::fs::File,
) -> Result<Vec<u8>, BoxError> {
    /// Generous for a bundle: the macOS system roots file is ~333 KiB.
    const MAXIMUM_BYTES: u64 = 4 * 1024 * 1024;
    const CERTIFICATE_MARKER: &[u8] = b"BEGIN CERTIFICATE";
    const PRIVATE_KEY_MARKER: &[u8] = b"PRIVATE KEY";

    let refuse =
        |reason: String| -> BoxError { crate::error::ConfigError::Workspace { reason }.into() };

    let metadata = opened.metadata().map_err(|source| {
        refuse(format!(
            "cannot inspect the proxy CA at {}: {source}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(refuse(format!(
            "the proxy CA at {} is not a regular file; a device or FIFO cannot be read as a \
             certificate bundle",
            path.display()
        )));
    }
    if metadata.len() > MAXIMUM_BYTES {
        return Err(refuse(format!(
            "the proxy CA at {} is {} bytes, over the {MAXIMUM_BYTES} byte maximum",
            path.display(),
            metadata.len()
        )));
    }

    // Bytes rather than a lossy `String`: the markers are ASCII, so scanning the raw bytes avoids a
    // second full copy of a file that may not be valid UTF-8.
    let mut file = opened.try_clone().map_err(|source| {
        refuse(format!(
            "cannot read the proxy CA at {}: {source}",
            path.display()
        ))
    })?;
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.seek(std::io::SeekFrom::Start(0))
        .and_then(|_| file.read_to_end(&mut contents))
        .map_err(|source| {
            refuse(format!(
                "cannot read the proxy CA at {}: {source}",
                path.display()
            ))
        })?;
    let contains = |marker: &[u8]| {
        contents
            .windows(marker.len())
            .any(|window| window == marker)
    };

    if contains(PRIVATE_KEY_MARKER) {
        return Err(refuse(format!(
            "the proxy CA at {} holds private key material; the workload reads this file in full, \
             and it carries public certificates only",
            path.display()
        )));
    }
    if !contains(CERTIFICATE_MARKER) {
        return Err(refuse(format!(
            "the proxy CA at {} is not a certificate bundle (no \"BEGIN CERTIFICATE\" block)",
            path.display()
        )));
    }
    Ok(contents)
}

/// The process's environment, composed by Core.
pub(crate) mod environment {
    use super::*;

    /// The process's `USER`. Fixed, so the operator's real username never reaches the contained
    /// process. The hosted Shell reads this same constant.
    pub(crate) const WORKLOAD_USER: &str = "strands-box";

    /// The proxy routing Core sets.
    const PROXY_NAMES: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"];

    /// Arms Node's own proxy honouring, which its runner refuses to start without.
    const NODE_PROXY_OPT_IN: &str = "NODE_USE_ENV_PROXY";

    /// The one destination a client may reach without the proxy: this box's own two loopback ports.
    const LOOPBACK_EXEMPTION: &str = "127.0.0.1,localhost";

    /// The OTLP/HTTP route the box's collector serves, and the only one it answers.
    const TRACES_ROUTE: &str = "/v1/traces";

    /// The sigil a `command` argument names a Core-owned value with.
    pub(crate) const OPENING: &str = "${";

    /// The transport the collector serves, pinned because it answers HTTP and not gRPC.
    const OTLP_PROTOCOL: &str = "http/protobuf";

    /// The trust variables, one per runtime that reads a different name.
    pub(crate) const TRUST_NAMES: [&str; 6] = [
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "CODEX_CA_CERTIFICATE",
        "AWS_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "GIT_SSL_CAINFO",
    ];

    /// The names Core sets whatever a spec says. Every one but `PATH` is refused to a spec by
    /// `reserved_workload_environment`; `PATH` is the operator's, with the alias directory prepended.
    #[cfg(test)]
    pub(crate) const CORE_OWNED: [&str; 13] = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "NODE_USE_ENV_PROXY",
        "NO_PROXY",
        "no_proxy",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "PWD",
        "USER",
        "PATH",
    ];

    /// What one composition takes.
    pub(crate) struct Inputs<'a> {
        /// Every phantom the box provisions, as `(name, value)`.
        pub(crate) phantoms: &'a [(String, String)],
        /// The spec's own `env`.
        pub(crate) declared: &'a BTreeMap<String, String>,
        /// The effective `HOME`.
        pub(crate) home: &'a Path,
        /// The declared search path, with the alias directory removed from it.
        pub(crate) search_path: &'a OsStr,
        pub(crate) alias_directory: &'a Path,
        /// Whether the alias directory comes first on `PATH`: true for the agent, false for a leaf.
        pub(crate) aliases_first: bool,
        pub(crate) working_directory: &'a Path,
        pub(crate) attachment: &'a Attachment,
        pub(crate) trust_bundle: Option<&'a Path>,
    }

    /// Compose the environment the process receives: phantoms beneath the spec's variables beneath
    /// Core's own names.
    pub(crate) fn compose(inputs: &Inputs<'_>) -> Result<BTreeMap<String, String>, BoxError> {
        let mut environment = BTreeMap::new();

        // Phantoms first, so the spec and then Core win any collision.
        environment.extend(inputs.phantoms.iter().cloned());

        // `HOME` defaults to the operator's, beneath the spec's own value.
        environment.insert("HOME".to_string(), utf8(inputs.home, "HOME")?);
        environment.extend(
            inputs
                .declared
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );

        // Core's own names, last.
        let proxy = format!("http://127.0.0.1:{}", inputs.attachment.proxy_port);
        environment.insert(NODE_PROXY_OPT_IN.to_string(), "1".to_string());
        for name in PROXY_NAMES {
            environment.insert(name.to_string(), proxy.clone());
        }
        environment.insert("NO_PROXY".to_string(), LOOPBACK_EXEMPTION.to_string());
        environment.insert("no_proxy".to_string(), LOOPBACK_EXEMPTION.to_string());
        // The agent's own instrumentation exports here, with no credential.
        environment.extend(expandable(inputs.attachment));
        environment.insert("PWD".to_string(), utf8(inputs.working_directory, "PWD")?);
        environment.insert("USER".to_string(), WORKLOAD_USER.to_string());
        environment.insert(
            "PATH".to_string(),
            composed_path(
                inputs.alias_directory,
                inputs.aliases_first,
                inputs.search_path,
            )?,
        );
        if let Some(trust_bundle) = inputs.trust_bundle {
            let value = utf8(trust_bundle, "proxy CA path")?;
            for name in TRUST_NAMES {
                environment.insert(name.to_string(), value.clone());
            }
        }
        Ok(environment)
    }

    /// The three telemetry values Core derives from this run's attachment, and the one set a
    /// `${NAME}` may name.
    pub(crate) fn expandable(attachment: &Attachment) -> BTreeMap<String, String> {
        let endpoint = format!("http://127.0.0.1:{}", attachment.telemetry_port);
        BTreeMap::from([
            (
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT".to_string(),
                format!("{endpoint}{TRACES_ROUTE}"),
            ),
            ("OTEL_EXPORTER_OTLP_ENDPOINT".to_string(), endpoint),
            (
                "OTEL_EXPORTER_OTLP_PROTOCOL".to_string(),
                OTLP_PROTOCOL.to_string(),
            ),
        ])
    }

    /// One spec's fixed arguments, expanded. The only place a spec's arguments are expanded.
    pub(crate) fn expanded_arguments(
        spec: &ProcessSpec,
        attachment: &Attachment,
    ) -> Result<Vec<String>, String> {
        let values = expandable(attachment);
        spec.fixed_arguments()
            .iter()
            .map(|argument| {
                expanded(argument, &values)
                    .map_err(|reason| format!("`command` argument {argument:?}: {reason}"))
            })
            .collect()
    }

    /// Substitute every `${NAME}` in one argument, refusing an unterminated `${` and a name
    /// [`expandable`] does not hold.
    fn expanded(argument: &str, values: &BTreeMap<String, String>) -> Result<String, String> {
        let mut resolved = String::with_capacity(argument.len());
        let mut rest = argument;
        while let Some(opening) = rest.find(OPENING) {
            resolved.push_str(&rest[..opening]);
            let tail = &rest[opening + OPENING.len()..];
            let Some(closing) = tail.find('}') else {
                return Err(format!("`{OPENING}` is never closed"));
            };
            let name = &tail[..closing];
            let Some(value) = values.get(name) else {
                return Err(format!(
                    "`{OPENING}{name}}}` names no expandable value; this build expands {}",
                    values
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            };
            resolved.push_str(value);
            rest = &tail[closing + 1..];
        }
        resolved.push_str(rest);
        Ok(resolved)
    }

    /// `search_path` without any spelling of the alias directory: defense in depth beside the
    /// absent alias and socket grants (docs/design/decisions.md#interpreters-are-brokered-aliases).
    pub(crate) fn without_alias_directory(
        alias_directory: &Path,
        search_path: &OsStr,
    ) -> Result<OsString, BoxError> {
        let alias_identity = alias_directory.canonicalize().ok();
        let names_the_alias_directory = |entry: &Path| {
            entry == alias_directory
                || alias_identity
                    .as_deref()
                    .is_some_and(|identity| entry.canonicalize().ok().as_deref() == Some(identity))
        };
        std::env::join_paths(
            std::env::split_paths(search_path).filter(|entry| !names_the_alias_directory(entry)),
        )
        .map_err(|source| TrampolineError::WorkloadPath { source }.into())
    }

    /// The alias directory first when `aliases_first`, then the declared search path without any
    /// spelling of it.
    fn composed_path(
        alias_directory: &Path,
        aliases_first: bool,
        search_path: &OsStr,
    ) -> Result<String, BoxError> {
        let remaining = without_alias_directory(alias_directory, search_path)?;
        let entries = aliases_first
            .then(|| alias_directory.to_path_buf())
            .into_iter()
            .chain(std::env::split_paths(&remaining));
        std::env::join_paths(entries)
            .map_err(|source| TrampolineError::WorkloadPath { source })?
            .into_string()
            .map_err(|value| {
                crate::error::ExecutableError::NotUtf8 {
                    description: "process PATH",
                    value: value.to_string_lossy().into_owned(),
                }
                .into()
            })
    }

    fn utf8(path: &Path, description: &'static str) -> Result<String, BoxError> {
        path.to_str().map(str::to_owned).ok_or_else(|| {
            crate::error::ExecutableError::NotUtf8 {
                description,
                value: path.to_string_lossy().into_owned(),
            }
            .into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::record::config::RECORD_VERSION;
    use crate::record::config::mcp::McpServer;
    use crate::record::config::process::{ContainedMcp, Filesystem};
    use crate::run::credential::ProvisionedVariable;

    /// One operator home holding a box root, a project, and the trees the specs below name.
    struct Fixture {
        operator: tempfile::TempDir,
        home: PathBuf,
        root: BoxRoot,
        record: Record,
        attachment: Attachment,
        /// Bound so the broker socket exists for the connect grant, as it does under a hosted box.
        _socket: std::os::unix::net::UnixListener,
    }

    impl Fixture {
        fn new() -> Self {
            let operator = tempfile::tempdir().expect("an operator home");
            let home = operator.path().canonicalize().expect("a canonical home");
            for relative in [
                "project/src",
                "vendor/sdk",
                "scratch",
                "notes",
                "tools",
                "bin",
            ] {
                std::fs::create_dir_all(home.join(relative)).expect("a directory");
            }
            std::fs::write(home.join("notes/api.md"), "").expect("a file");
            for script in ["tools/run", "bin/run"] {
                std::fs::write(home.join(script), "#!/bin/sh\n").expect("a script");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(
                        home.join(script),
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .expect("an executable script");
                }
            }
            let root = crate::record::layout::testing::box_root(operator.path(), "codex");
            let mcp = vec![
                McpServer {
                    name: "alpha".to_string(),
                    command: vec!["alpha-mcp".to_string()],
                },
                McpServer {
                    name: "beta".to_string(),
                    command: vec!["beta-mcp".to_string()],
                },
                McpServer {
                    name: "memory".to_string(),
                    command: vec!["node".to_string()],
                },
                McpServer {
                    name: "github-local".to_string(),
                    command: vec!["github-mcp-server".to_string()],
                },
            ];
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                for alias in root.all_aliases(&mcp) {
                    std::fs::write(&alias, []).expect("the alias placeholder is written");
                    std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o500))
                        .expect("the alias placeholder is executable");
                }
            }
            let record = Record {
                version: RECORD_VERSION,
                box_id: root.name().to_string(),
                box_dir: root.root().to_path_buf(),
                name: "codex".to_string(),
                policy: None,
                agent: None,
                tool: Default::default(),
                egress: Default::default(),
                remote_mcp: Default::default(),
                mcp,
                contained_mcp: Default::default(),
                telemetry: Default::default(),
                containment: Default::default(),
            };
            let attachment = Attachment {
                proxy_port: 41080,
                telemetry_port: 44318,
                trust_bundle: None,
                phantoms: vec![
                    ProvisionedVariable {
                        name: "MODEL_TOKEN".to_string(),
                        value: "phantom-model".to_string(),
                    },
                    ProvisionedVariable {
                        name: "OTHER_TOKEN".to_string(),
                        value: "phantom-other".to_string(),
                    },
                    ProvisionedVariable {
                        name: "ANTHROPIC_API_KEY".to_string(),
                        value: "phantom-anthropic".to_string(),
                    },
                    ProvisionedVariable {
                        name: "GITHUB_GIT_AUTH".to_string(),
                        value: "phantom-github-git".to_string(),
                    },
                    ProvisionedVariable {
                        name: "AWS_ACCESS_KEY_ID".to_string(),
                        value: "phantom-aws".to_string(),
                    },
                ],
            };
            let socket = std::os::unix::net::UnixListener::bind(root.broker_socket())
                .expect("the broker socket binds");
            Self {
                operator,
                home,
                root,
                record,
                attachment,
                _socket: socket,
            }
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.home.join(relative)
        }

        /// A representative spec: a shell with a fixed argument, a declared workspace, two
        /// variables, and one entry in every list Linux lowers.
        fn spec(&self) -> ProcessSpec {
            ProcessSpec {
                command: vec!["/bin/sh".to_string(), "-c".to_string()],
                workspace: Some(self.path("project")),
                env: BTreeMap::from([
                    (
                        "TMPDIR".to_string(),
                        self.path("scratch").display().to_string(),
                    ),
                    ("FOO".to_string(), "declared".to_string()),
                ]),
                filesystem: Filesystem {
                    read: vec![self.path("vendor")],
                    write: vec![self.path("scratch")],
                    read_file: vec![self.path("notes/api.md")],
                    write_file: vec![self.path("notes/api.md")],
                    metadata: vec![self.path("notes")],
                    exec: vec![self.path("tools"), self.path("bin/run")],
                    deny: vec![self.path("vendor/sdk")],
                    ..Filesystem::default()
                },
                network: None,
            }
        }

        /// The same translation with a chosen reach, so a test can vary Core's own set.
        fn translate_with_reach(
            &self,
            spec: &ProcessSpec,
            table: &str,
            reach: RuntimeReach,
        ) -> Boundary {
            let fallback = self.path("project");
            crate::test_support::with_operator_home(self.operator.path(), || {
                Boundary::translate(
                    spec,
                    Launch {
                        table,
                        trailing: &[],
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::Granted,
                        runtime_reach: reach,
                        argument_zero: None,
                        egress: EgressMode::Gateway,
                        approved: None,
                    },
                    &Site {
                        attachment: &self.attachment,
                        layout: &self.root,
                        stored: &self.record,
                        protected_sources: &[],
                    },
                )
            })
            .unwrap_or_else(|error| panic!("{table} translates: {error}"))
        }

        /// Translate with a chosen reach and egress mode, returning the `Result` so a test can assert
        /// a refusal (e.g. native egress on Linux) as well as a success.
        fn try_translate_full(
            &self,
            spec: &ProcessSpec,
            table: &str,
            reach: RuntimeReach,
            egress: EgressMode,
        ) -> Result<Boundary, BoxError> {
            let fallback = self.path("project");
            crate::test_support::with_operator_home(self.operator.path(), || {
                Boundary::translate(
                    spec,
                    Launch {
                        table,
                        trailing: &[],
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::Granted,
                        runtime_reach: reach,
                        argument_zero: None,
                        egress,
                        approved: None,
                    },
                    &Site {
                        attachment: &self.attachment,
                        layout: &self.root,
                        stored: &self.record,
                        protected_sources: &[],
                    },
                )
            })
        }

        /// Translate with a chosen reach and egress mode, so a test can exercise native egress and
        /// the leaf-only runtime-services grant without hand-building the `Launch`.
        fn translate_full(
            &self,
            spec: &ProcessSpec,
            table: &str,
            reach: RuntimeReach,
            egress: EgressMode,
        ) -> Boundary {
            self.try_translate_full(spec, table, reach, egress)
                .unwrap_or_else(|error| panic!("{table} translates: {error}"))
        }

        /// Translate `table` at the leaf reach; a test of the agent's own plumbing calls
        /// `translate_with_reach` with `RuntimeReach::Agent`.
        fn translate(&self, spec: &ProcessSpec, table: &str, trailing: &[&str]) -> Boundary {
            self.try_translate(spec, table, trailing)
                .unwrap_or_else(|error| panic!("{table} translates: {error}"))
        }

        /// The same translation, returning the `Result` so a test can assert a refusal an argument
        /// causes.
        fn try_translate(
            &self,
            spec: &ProcessSpec,
            table: &str,
            trailing: &[&str],
        ) -> Result<Boundary, BoxError> {
            let trailing: Vec<String> = trailing.iter().map(|s| (*s).to_string()).collect();
            let fallback = self.path("project");
            crate::test_support::with_operator_home(self.operator.path(), || {
                Boundary::translate(
                    spec,
                    Launch {
                        table,
                        trailing: &trailing,
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::Granted,
                        runtime_reach: RuntimeReach::Leaf,
                        argument_zero: None,
                        egress: EgressMode::Gateway,
                        approved: None,
                    },
                    &Site {
                        attachment: &self.attachment,
                        layout: &self.root,
                        stored: &self.record,
                        protected_sources: &[],
                    },
                )
            })
        }
    }

    /// A `box.toml` written into `directory` and loaded as one authority source.
    fn plant_authority(directory: &Path) -> AuthoritySource {
        std::fs::create_dir_all(directory).expect("the authority directory");
        let config = directory.join("box.toml");
        std::fs::write(&config, "name = \"planted\"\n").expect("the configuration");
        AuthoritySource::read(&config, "config")
            .expect("the planted configuration loads")
            .0
    }

    /// Every cell a boundary's containment config carries, as `(path, operation, scope)`.
    fn cells(boundary: &Boundary) -> Vec<(PathBuf, Operation, Scope)> {
        let config: serde_json::Value =
            serde_json::from_str(&boundary.containment_config_text()).expect("the config is JSON");
        config["paths"]
            .as_array()
            .expect("the config lists its paths")
            .iter()
            .map(|grant| {
                (
                    PathBuf::from(grant["resolved"].as_str().expect("a path")),
                    serde_json::from_value(grant["operation"].clone()).expect("an operation"),
                    serde_json::from_value(grant["scope"].clone()).expect("a scope"),
                )
            })
            .collect()
    }

    fn environment_of(boundary: &Boundary) -> BTreeMap<String, String> {
        serde_json::from_str(boundary.target_environment()).expect("the environment is JSON")
    }

    /// What the trampoline will read from the boundary's environment descriptor.
    fn environment_descriptor_text(boundary: &Boundary) -> String {
        let mut file = boundary.target_environment_file();
        let mut text = String::new();
        file.seek(std::io::SeekFrom::Start(0))
            .expect("the environment descriptor seeks");
        file.read_to_string(&mut text)
            .expect("the environment descriptor reads");
        text
    }

    /// **The key reaches every leaf**: the agent, a tool, and a stdio MCP server each carry
    /// `AllowAll` when the box shares its `/proc`, and `Isolated` when it does not.
    #[test]
    fn private_proc_false_reaches_the_agent_tools_and_mcp_servers() {
        for private_proc in [true, false] {
            let mut fixture = Fixture::new();
            fixture.record.containment =
                crate::record::config::isolation::ContainmentSpec { private_proc };
            let expected = if private_proc {
                containment::ProcessInfoMode::Isolated
            } else {
                containment::ProcessInfoMode::AllowAll
            };
            let spec = fixture.spec();
            for (table, reach) in [
                ("[agent]", RuntimeReach::Agent),
                ("[tool.x]", RuntimeReach::Leaf),
                ("[mcp.y]", RuntimeReach::Leaf),
            ] {
                let boundary = fixture.translate_with_reach(&spec, table, reach);
                let config =
                    containment::ContainmentConfig::from_json(&boundary.containment_config_text())
                        .expect("the config parses");
                assert_eq!(config.process_info_mode(), expected, "{table}");
                assert_eq!(boundary.shares_proc(), !private_proc, "{table}");
            }
        }
    }

    /// **The descriptor holds exactly the composed environment**, whole, for a large value too.
    #[test]
    fn the_environment_descriptor_holds_the_composed_environment() {
        let fixture = Fixture::new();
        let big = "x".repeat(200 * 1024);
        let mut spec = fixture.spec();
        spec.env.insert("BIG".to_string(), big.clone());
        let boundary = fixture.translate(&spec, "[agent]", &[]);

        let text = environment_descriptor_text(&boundary);

        assert_eq!(text, boundary.target_environment());
        assert!(text.contains(&big), "the large value arrives whole");
    }

    /// **Two leaves translated back to back keep their own environments**, though both write the
    /// same path: each holds its own opened file.
    #[test]
    fn two_boundaries_keep_their_own_environment_descriptors() {
        let fixture = Fixture::new();
        let mut first_spec = fixture.spec();
        first_spec
            .env
            .insert("WHO".to_string(), "first".to_string());
        let mut second_spec = fixture.spec();
        second_spec
            .env
            .insert("WHO".to_string(), "second".to_string());
        let first = fixture.translate(&first_spec, "[agent]", &[]);
        let second = fixture.translate(&second_spec, "[agent]", &[]);

        for (boundary, who) in [(&first, "first"), (&second, "second")] {
            let text = environment_descriptor_text(boundary);
            assert!(
                text.contains(&format!("\"WHO\":\"{who}\"")),
                "{who}: {text}"
            );
        }
    }

    /// **A spawn acts on the reach judged when the run started.** The directory holding an
    /// authority source is subtracted when a table is judged; a spawn walks no granted tree and
    /// re-judges nothing.
    #[test]
    fn a_spawn_acts_on_the_reach_judged_when_the_run_started() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec();
        spec.filesystem = Filesystem {
            write: vec![fixture.path("scratch")],
            ..Filesystem::default()
        };
        let record = Record {
            tool: BTreeMap::from([("t".to_string(), spec.clone())]),
            ..fixture.record.clone()
        };
        let approved = crate::test_support::with_operator_home(fixture.operator.path(), || {
            ApprovedReach::judge(&record, &[])
        })
        .expect("every table is judged");
        assert!(approved.table("[tool.absent]").is_none());

        let authority = fixture.path("scratch/later/authority");
        let source = plant_authority(&authority);
        let refusal = (authority.clone(), Operation::Deny, Scope::Root);
        let fallback = fixture.path("project");
        let translate = |approved: Option<&DirectReach>| {
            crate::test_support::with_operator_home(fixture.operator.path(), || {
                Boundary::translate(
                    &spec,
                    Launch {
                        table: "[tool.t]",
                        trailing: &[],
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::Granted,
                        runtime_reach: RuntimeReach::Leaf,
                        argument_zero: None,
                        egress: EgressMode::Gateway,
                        approved,
                    },
                    &Site {
                        attachment: &fixture.attachment,
                        layout: &fixture.root,
                        stored: &record,
                        protected_sources: std::slice::from_ref(&source),
                    },
                )
            })
            .expect("[tool.t] translates")
        };
        assert!(
            !cells(&translate(approved.table("[tool.t]"))).contains(&refusal),
            "a spawn acts on the reach judged at startup, which knew no source there"
        );
        assert!(
            cells(&translate(None)).contains(&refusal),
            "a table judged now subtracts the directory holding the source"
        );
    }

    /// **A spawn refuses a grant whose path changed identity after the judgement**: the directory
    /// itself replaced by a link, and an ancestor replaced by a link.
    #[cfg(unix)]
    #[test]
    fn a_spawn_refuses_a_grant_whose_identity_changed_after_judgement() {
        let fixture = Fixture::new();
        let inner = fixture.path("scratch/inner");
        std::fs::create_dir(&inner).expect("a granted directory");
        let mut spec = fixture.spec();
        spec.filesystem = Filesystem {
            write: vec![inner.clone()],
            ..Filesystem::default()
        };
        let record = Record {
            tool: BTreeMap::from([("t".to_string(), spec.clone())]),
            ..fixture.record.clone()
        };
        let approved = crate::test_support::with_operator_home(fixture.operator.path(), || {
            ApprovedReach::judge(&record, &[])
        })
        .expect("every table is judged");
        let fallback = fixture.path("project");
        let translate = || {
            crate::test_support::with_operator_home(fixture.operator.path(), || {
                Boundary::translate(
                    &spec,
                    Launch {
                        table: "[tool.t]",
                        trailing: &[],
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::Granted,
                        runtime_reach: RuntimeReach::Leaf,
                        argument_zero: None,
                        egress: EgressMode::Gateway,
                        approved: approved.table("[tool.t]"),
                    },
                    &Site {
                        attachment: &fixture.attachment,
                        layout: &fixture.root,
                        stored: &record,
                        protected_sources: &[],
                    },
                )
            })
        };
        translate().expect("an unchanged path is acted on");

        // The granted directory becomes a link to a tree the operator never named.
        std::fs::rename(&inner, fixture.path("scratch/moved")).expect("move the directory");
        std::os::unix::fs::symlink(fixture.path("notes"), &inner).expect("plant a link");
        let refusal = translate().err().expect("a link is refused").to_string();
        assert!(refusal.contains("[tool.t]"), "{refusal}");
        assert!(refusal.contains("became a symbolic link"), "{refusal}");

        // An ancestor becomes a link: the path spells the same and resolves elsewhere.
        std::fs::remove_file(&inner).expect("remove the link");
        std::fs::rename(fixture.path("scratch/moved"), &inner).expect("restore the directory");
        translate().expect("the restored path is acted on");
        let elsewhere = fixture.path("elsewhere");
        std::fs::create_dir_all(elsewhere.join("inner")).expect("a tree the link points at");
        std::fs::rename(fixture.path("scratch"), fixture.path("scratch-moved"))
            .expect("move the ancestor");
        std::os::unix::fs::symlink(&elsewhere, fixture.path("scratch")).expect("plant a link");
        let refusal = translate()
            .err()
            .expect("a linked ancestor is refused")
            .to_string();
        assert!(refusal.contains("resolves to"), "{refusal}");
        assert!(refusal.contains("elsewhere"), "{refusal}");

        // The granted directory becomes a file, then is gone.
        std::fs::remove_file(fixture.path("scratch")).expect("remove the link");
        std::fs::rename(fixture.path("scratch-moved"), fixture.path("scratch"))
            .expect("restore the ancestor");
        std::fs::remove_dir(&inner).expect("remove the directory");
        std::fs::write(&inner, "").expect("a file at the granted path");
        let refusal = translate().err().expect("a file is refused").to_string();
        assert!(
            refusal.contains("changed between a file and a directory"),
            "{refusal}"
        );
        std::fs::remove_file(&inner).expect("remove the file");
        let refusal = translate()
            .err()
            .expect("an absent path is refused")
            .to_string();
        assert!(refusal.contains("cannot be read"), "{refusal}");
    }

    /// **A spawn refuses a reach whose subtracted authority directory moved**: the directory the
    /// sources were read from is renamed, so it is no longer where the judgement subtracted it.
    #[test]
    fn a_spawn_refuses_a_reach_whose_subtracted_authority_moved() {
        let fixture = Fixture::new();
        let authority = fixture.path("scratch/inner/authority");
        let source = plant_authority(&authority);
        let mut spec = fixture.spec();
        spec.filesystem = Filesystem {
            write: vec![fixture.path("scratch")],
            ..Filesystem::default()
        };
        let record = Record {
            tool: BTreeMap::from([("t".to_string(), spec.clone())]),
            ..fixture.record.clone()
        };
        let approved = crate::test_support::with_operator_home(fixture.operator.path(), || {
            ApprovedReach::judge(&record, std::slice::from_ref(&source))
        })
        .expect("every table is judged");
        let fallback = fixture.path("project");
        let translate = || {
            crate::test_support::with_operator_home(fixture.operator.path(), || {
                Boundary::translate(
                    &spec,
                    Launch {
                        table: "[tool.t]",
                        trailing: &[],
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::Granted,
                        runtime_reach: RuntimeReach::Leaf,
                        argument_zero: None,
                        egress: EgressMode::Gateway,
                        approved: approved.table("[tool.t]"),
                    },
                    &Site {
                        attachment: &fixture.attachment,
                        layout: &fixture.root,
                        stored: &record,
                        protected_sources: std::slice::from_ref(&source),
                    },
                )
            })
        };
        let refusal = (authority.clone(), Operation::Deny, Scope::Root);
        assert!(cells(&translate().expect("the judged reach is acted on")).contains(&refusal));

        std::fs::rename(
            fixture.path("scratch/inner"),
            fixture.path("scratch/renamed"),
        )
        .expect("rename the directory above the authority");
        let refused = translate()
            .err()
            .expect("a moved authority refuses the spawn")
            .to_string();
        assert!(refused.contains("[tool.t]"), "{refused}");
        assert!(refused.contains("cannot be read"), "{refused}");

        // An empty directory recreated at the judged path is not the file the run judged.
        std::fs::create_dir_all(&authority).expect("recreate the path");
        let refused = translate()
            .err()
            .expect("a recreated path refuses the spawn")
            .to_string();
        assert!(refused.contains("was replaced"), "{refused}");
    }

    /// **A spawn refuses a reach whose `deny` path was replaced** after the judgement; on macOS a
    /// `deny` path not there when the run judged it is replayed by name.
    #[test]
    fn a_spawn_refuses_a_reach_whose_denied_path_was_replaced() {
        let fixture = Fixture::new();
        let secret = fixture.path("scratch/secret");
        std::fs::create_dir(&secret).expect("a denied directory");
        let later = fixture.path("scratch/later");
        let mut deny = vec![secret.clone()];
        if cfg!(target_os = "macos") {
            deny.push(later.clone());
        }
        let mut spec = fixture.spec();
        spec.filesystem = Filesystem {
            write: vec![fixture.path("scratch")],
            deny,
            ..Filesystem::default()
        };
        let record = Record {
            tool: BTreeMap::from([("t".to_string(), spec.clone())]),
            ..fixture.record.clone()
        };
        let approved = crate::test_support::with_operator_home(fixture.operator.path(), || {
            ApprovedReach::judge(&record, &[])
        })
        .expect("every table is judged");
        let fallback = fixture.path("project");
        let translate = || {
            crate::test_support::with_operator_home(fixture.operator.path(), || {
                Boundary::translate(
                    &spec,
                    Launch {
                        table: "[tool.t]",
                        trailing: &[],
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::Granted,
                        runtime_reach: RuntimeReach::Leaf,
                        argument_zero: None,
                        egress: EgressMode::Gateway,
                        approved: approved.table("[tool.t]"),
                    },
                    &Site {
                        attachment: &fixture.attachment,
                        layout: &fixture.root,
                        stored: &record,
                        protected_sources: &[],
                    },
                )
            })
        };
        translate().expect("the judged reach is acted on");
        std::fs::create_dir(&later).expect("the later path appears");
        translate().expect("a deny path that appears is replayed by name");

        std::fs::rename(&secret, fixture.path("scratch/moved")).expect("move the denied directory");
        std::fs::create_dir(&secret).expect("recreate the denied path");
        let refused = translate()
            .err()
            .expect("a replaced deny path refuses the spawn")
            .to_string();
        assert!(refused.contains("was replaced"), "{refused}");
    }

    #[test]
    fn a_log_directory_gets_metadata_only_when_the_process_lists_it() {
        let fixture = Fixture::new();
        let logs = fixture.path("logs");
        std::fs::create_dir(&logs).expect("a log directory");
        let mut spec = fixture.spec();
        spec.filesystem = Filesystem::default();
        let rule = format!(
            "(allow file-read-metadata (subpath \"{}\"))",
            logs.display()
        );
        for table in ["[agent]", "[tool.node]"] {
            for listed in [false, true] {
                spec.filesystem.metadata = if listed { vec![logs.clone()] } else { vec![] };
                let boundary = fixture.translate(&spec, table, &[]);
                let config = ContainmentConfig::from_json(&boundary.containment_config_text())
                    .expect("the translated config");
                let profile = containment::test_support::generate_seatbelt_profile(&config)
                    .expect("the translated profile renders");
                assert_eq!(profile.contains(&rule), listed, "{table}: {profile}");
                for operation in [
                    "file-read*",
                    "file-read-data",
                    "file-write-data",
                    "process-exec",
                ] {
                    assert!(
                        !profile.contains(&format!(
                            "(allow {operation} (subpath \"{}\"))",
                            logs.display()
                        )),
                        "{table}: {profile}"
                    );
                }
            }
        }
    }

    /// Render the seatbelt profile a boundary would apply, for asserting on its rules.
    fn rendered(boundary: &Boundary) -> String {
        let config = ContainmentConfig::from_json(&boundary.containment_config_text())
            .expect("the translated config is valid");
        containment::test_support::generate_seatbelt_profile(&config)
            .expect("the translated profile renders")
    }

    /// A spec selects native egress only through `contain_egress = false`.
    #[test]
    fn a_spec_selects_native_egress_only_through_contain_egress_false() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec();
        assert_eq!(EgressMode::for_spec(&spec), EgressMode::Gateway);
        spec.network = Some(crate::record::config::process::NetworkConfig {
            contain_egress: true,
        });
        assert_eq!(EgressMode::for_spec(&spec), EgressMode::Gateway);
        spec.network = Some(crate::record::config::process::NetworkConfig {
            contain_egress: false,
        });
        assert_eq!(EgressMode::for_spec(&spec), EgressMode::Native);
    }

    /// The startup disclosure names a leaf's native egress, and says nothing of it for a gateway leaf.
    #[test]
    fn the_disclosure_names_native_egress_only_when_it_is_selected() {
        let fixture = Fixture::new();
        let spec = fixture.spec();
        let native = fixture.translate_full(
            &spec,
            "[tool.sso-cli]",
            RuntimeReach::Leaf,
            EgressMode::Native,
        );
        assert!(
            native.disclosure().contains(
                "strands-box: [tool.sso-cli] native egress: connects to the network directly, with \
                 the arguments the agent passes,"
            ),
            "{}",
            native.disclosure()
        );
        let gateway = fixture.translate_full(
            &spec,
            "[tool.sso-cli]",
            RuntimeReach::Leaf,
            EgressMode::Gateway,
        );
        assert!(
            !gateway.disclosure().contains("native egress"),
            "{}",
            gateway.disclosure()
        );
    }

    /// **A native-egress launch translates to `Network::AllowAll` (macOS render).** `EgressMode::Native`
    /// renders outbound to any IP host and no pathless outbound allow; the default
    /// `EgressMode::Gateway` renders neither — its egress is the localhost proxy connect. This
    /// is the box-level half of the escape; the seatbelt render itself is covered in
    /// `profile_conformance`. macOS-only because it asserts the seatbelt text; the Linux side of the
    /// same `Network::AllowAll` (joining the host network namespace) is covered by
    /// `native_egress_translates_on_linux` here and the namespace backend's own tests.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_egress_translates_to_allow_all() {
        const IP_OUTBOUND: &str = "(remote ip \"*:*\")";
        let pathless = |profile: &str| {
            profile
                .lines()
                .any(|line| line.trim() == "(allow network-outbound)")
        };
        let fixture = Fixture::new();
        let spec = fixture.spec();

        let native = rendered(&fixture.translate_full(
            &spec,
            "[mcp.builder]",
            RuntimeReach::Leaf,
            EgressMode::Native,
        ));
        assert!(
            native.contains(IP_OUTBOUND) && !pathless(&native),
            "native egress must render IP-only outbound: {native}"
        );

        let gateway = rendered(&fixture.translate_full(
            &spec,
            "[mcp.builder]",
            RuntimeReach::Leaf,
            EgressMode::Gateway,
        ));
        assert!(
            !gateway.contains(IP_OUTBOUND) && !pathless(&gateway),
            "gateway egress must NOT render direct outbound: {gateway}"
        );
    }

    /// **Native egress translates on Linux (no longer refused).** `contain_egress = false` is an
    /// operator trust grant: the leaf joins the host network namespace, so `translate` accepts
    /// `EgressMode::Native` — it no longer refuses at load. Both postures translate cleanly; the
    /// host-netns render itself lives in the namespace backend's tests. Keyed on `Ok` because
    /// `Boundary` is not `Debug`.
    #[cfg(target_os = "linux")]
    #[test]
    fn native_egress_translates_on_linux() {
        let fixture = Fixture::new();
        let spec = fixture.spec();

        assert!(
            fixture
                .try_translate_full(
                    &spec,
                    "[mcp.builder]",
                    RuntimeReach::Leaf,
                    EgressMode::Native
                )
                .is_ok(),
            "native egress is an operator trust grant and must translate on Linux, not refuse"
        );
        assert!(
            fixture
                .try_translate_full(
                    &spec,
                    "[mcp.builder]",
                    RuntimeReach::Leaf,
                    EgressMode::Gateway
                )
                .is_ok(),
            "gateway egress translates on Linux"
        );
    }

    /// **The network runtime-services grants are leaf-only, driven by `RuntimeReach`.** A leaf
    /// launch renders the `net.*` sysctl read and routing socket needed for `getifaddrs`. Agent and
    /// opted-in leaf launches both render the opendirectoryd identity lookup needed for `getpwuid`.
    /// Keys on all three markers so the account grant cannot pull in the leaf network bundle.
    #[test]
    fn an_agent_gets_account_lookup_without_leaf_network_runtime_services() {
        let fixture = Fixture::new();
        let spec = fixture.spec();

        let leaf = rendered(&fixture.translate_full(
            &spec,
            "[tool.node]",
            RuntimeReach::Leaf,
            EgressMode::Gateway,
        ));
        assert!(
            leaf.contains("(sysctl-name-prefix \"net.\")"),
            "a leaf reads the net.* sysctls: {leaf}"
        );
        assert!(
            leaf.contains("opendirectoryd.libinfo"),
            "a leaf resolves identities via opendirectoryd: {leaf}"
        );

        let agent = rendered(&fixture.translate_full(
            &spec,
            "[agent]",
            RuntimeReach::Agent,
            EgressMode::Gateway,
        ));
        assert!(
            !agent.contains("(sysctl-name-prefix \"net.\")"),
            "the agent reads no net.* sysctls: {agent}"
        );
        assert!(
            agent.contains(
                "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))"
            ),
            "the agent gets the named account lookup: {agent}"
        );
        assert!(!agent.contains("(allow system-socket (socket-domain AF_ROUTE))"));
    }

    /// **One spec, two launch roles, one boundary.** The containment config, the environment, the
    /// program, the arguments, and the working directory are equal; only the table name in the
    /// disclosure differs.
    #[test]
    fn one_spec_translates_the_same_as_agent_and_as_tool() {
        let fixture = Fixture::new();
        let spec = fixture.spec();

        let as_agent = fixture.translate(&spec, "[agent]", &["echo agent"]);
        let agent_config = as_agent.containment_config_text();
        let agent_environment = as_agent.target_environment().to_string();
        let agent_disclosure = as_agent.disclosure().to_string();
        let as_tool = fixture.translate(&spec, "[tool.sh]", &["echo agent"]);

        assert_eq!(agent_config, as_tool.containment_config_text());
        assert_eq!(agent_environment, as_tool.target_environment());
        assert_eq!(as_agent.executable(), as_tool.executable());
        assert_eq!(as_agent.arguments(), as_tool.arguments());
        assert_eq!(as_agent.working_directory(), as_tool.working_directory());
        assert_eq!(
            agent_disclosure.replace("[agent]", "[tool.sh]"),
            as_tool.disclosure(),
            "the disclosure names the table and nothing else that depends on the role"
        );
    }

    /// **Discovery is wired for a leaf and not for the agent.** The same spec, translated at
    /// each reach, renders the operator home existence-and-metadata *open* for a leaf and
    /// existence-*denied* for the agent, so discovery keys on `RuntimeReach` and the agent box is
    /// byte-identical to before discovery.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_leaf_discovers_the_operator_home_and_the_main_box_does_not() {
        let fixture = Fixture::new();
        let spec = fixture.spec();
        let home = fixture
            .operator
            .path()
            .canonicalize()
            .expect("the operator home resolves");
        let meta_allow = format!(
            "(allow file-read-metadata (subpath \"{}\"))",
            home.display()
        );
        let exist_deny = format!(
            "(deny file-test-existence (subpath \"{}\"))",
            home.display()
        );
        let profile = |reach| {
            let boundary = fixture.translate_with_reach(&spec, "[tool.git]", reach);
            let config = ContainmentConfig::from_json(&boundary.containment_config_text())
                .expect("the translated config");
            containment::test_support::generate_seatbelt_profile(&config)
                .expect("the profile renders")
        };

        let leaf = profile(RuntimeReach::Leaf);
        assert!(
            leaf.contains(&meta_allow),
            "a leaf discovers the home: {leaf}"
        );
        assert!(
            !leaf.contains(&exist_deny),
            "a leaf suppresses the home existence-deny: {leaf}"
        );

        // The box-state exclusion targets THIS BOX'S OWN DIRECTORY. A caller selects `box_dir`, so
        // the parent is whatever they sited the box under and is not a boxes namespace: denying it
        // would deny an unrelated directory, and for a `box_dir` directly in the home it would deny
        // the home and cancel the discovery allow above. Both spellings are asserted, because the
        // parent-denying derivation this replaced still renders a passing subpath for the root.
        let box_root = fixture.root.root();
        let parent = box_root.parent().expect("the box directory's parent");
        let box_root_deny = format!(
            "(deny file-read-metadata (subpath \"{}\"))",
            box_root.display()
        );
        let parent_deny = format!(
            "(deny file-read-metadata (subpath \"{}\"))",
            parent.display()
        );
        assert!(
            leaf.contains(&box_root_deny),
            "the leaf excludes this box's own directory from discovery: {leaf}"
        );
        assert!(
            !leaf.contains(&parent_deny),
            "the exclusion is this box's directory, never the directory the caller sited it \
             under: {leaf}"
        );

        let agent = profile(RuntimeReach::Agent);
        assert!(
            agent.contains(&exist_deny),
            "the agent box keeps its home existence-deny: {agent}"
        );
        assert!(
            !agent.contains(&meta_allow),
            "the agent box gets no broad home metadata: {agent}"
        );
    }

    /// **The agent's alias directory answers an absent name as absent, and a leaf gets no cell
    /// there.** The cell is metadata on the directory's own entry, so it reads no alias and lists
    /// none.
    #[test]
    fn the_agent_tests_existence_in_its_alias_directory_and_a_leaf_does_not() {
        let fixture = Fixture::new();
        let spec = fixture.spec();
        let bin = fixture.root.bin_directory();

        let agent = cells(&fixture.translate_with_reach(&spec, "[agent]", RuntimeReach::Agent));
        let at_bin: Vec<_> = agent.iter().filter(|(path, _, _)| *path == bin).collect();
        assert_eq!(
            at_bin,
            [&(bin.clone(), Operation::Metadata, Scope::Dir)],
            "the agent holds one metadata cell on the alias directory's entry: {agent:?}"
        );

        let leaf = cells(&fixture.translate_with_reach(&spec, "[tool.git]", RuntimeReach::Leaf));
        assert!(
            !leaf.iter().any(|(path, _, _)| *path == bin),
            "a leaf holds no cell on the alias directory: {leaf:?}"
        );
    }

    /// **The alias directory's existence allow renders beneath the home deny and reaches no other
    /// box directory.**
    #[cfg(target_os = "macos")]
    #[test]
    fn the_alias_directory_existence_allow_is_the_only_box_state_it_opens() {
        let fixture = Fixture::new();
        let boundary =
            fixture.translate_with_reach(&fixture.spec(), "[agent]", RuntimeReach::Agent);
        let config = ContainmentConfig::from_json(&boundary.containment_config_text())
            .expect("the translated config");
        let profile = containment::test_support::generate_seatbelt_profile(&config)
            .expect("the profile renders");
        let home = fixture
            .operator
            .path()
            .canonicalize()
            .expect("the operator home resolves");
        let root = fixture.root.root().canonicalize().expect("the box root");
        let rule = |operation: &str, filter: &str, path: &Path| {
            format!("(allow {operation} ({filter} \"{}\"))", path.display())
        };

        let home_deny = format!(
            "(deny file-test-existence (subpath \"{}\"))",
            home.display()
        );
        let bin_allow = rule("file-test-existence", "subpath", &root.join("bin"));
        let deny_at = profile.find(&home_deny).expect("the home existence-deny");
        let allow_at = profile
            .find(&bin_allow)
            .expect("the alias directory existence allow");
        assert!(
            deny_at < allow_at,
            "the allow renders after the home deny, so it wins: {profile}"
        );
        for other in ["private", "run", "trust"] {
            assert!(
                !profile.contains(&rule("file-test-existence", "subpath", &root.join(other))),
                "{other} gets no existence subtree: {profile}"
            );
        }
        assert!(
            !profile.contains(&rule("file-test-existence", "subpath", &root)),
            "the box root gets no existence subtree: {profile}"
        );
        for operation in ["file-read*", "file-read-data"] {
            assert!(
                !profile.contains(&rule(operation, "subpath", &root.join("bin"))),
                "the alias directory stays unread: {profile}"
            );
        }
    }

    /// **Broad exec is wired for a leaf and not for the agent.** The same spec, translated at
    /// each reach, renders `(allow process-exec*)` for a leaf and never for the agent, so broad exec
    /// keys on `RuntimeReach` and the agent box keeps enumerated exec.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_leaf_gets_broad_exec_and_the_main_box_does_not() {
        let fixture = Fixture::new();
        let spec = fixture.spec();
        let profile = |reach| {
            let boundary = fixture.translate_with_reach(&spec, "[tool.git]", reach);
            let config = ContainmentConfig::from_json(&boundary.containment_config_text())
                .expect("the translated config");
            containment::test_support::generate_seatbelt_profile(&config)
                .expect("the profile renders")
        };

        let leaf = profile(RuntimeReach::Leaf);
        assert!(
            leaf.contains("(allow process-exec*)"),
            "a leaf renders broad exec: {leaf}"
        );

        let agent = profile(RuntimeReach::Agent);
        assert!(
            !agent.contains("(allow process-exec*)"),
            "the agent box renders no broad exec: {agent}"
        );
    }

    /// **The caller's spelling becomes `argv[0]` and the executable stays the identity**, so a venv
    /// link runs the canonical interpreter while the interpreter reads the link as its own path.
    #[test]
    fn the_launch_spelling_becomes_argument_zero_and_the_executable_stays_canonical() {
        let fixture = Fixture::new();
        let spec = fixture.spec();
        let spelled = fixture.path("project/.venv/bin/python");
        let fallback = fixture.path("project");
        let boundary = crate::test_support::with_operator_home(fixture.operator.path(), || {
            Boundary::translate(
                &spec,
                Launch {
                    table: "[tool.python]",
                    trailing: &[],
                    fallback_workspace: &fallback,
                    shebang_interpreters: ShebangInterpreters::Granted,
                    runtime_reach: RuntimeReach::Leaf,
                    argument_zero: Some(&spelled),
                    egress: EgressMode::Gateway,
                    approved: None,
                },
                &Site {
                    attachment: &fixture.attachment,
                    layout: &fixture.root,
                    stored: &fixture.record,
                    protected_sources: &[],
                },
            )
        })
        .expect("the tool translates");
        let plain = fixture.translate(&spec, "[tool.python]", &[]);
        assert_eq!(boundary.argument_zero(), Some(spelled.as_path()));
        assert_eq!(boundary.executable(), plain.executable());
        assert_eq!(
            plain.argument_zero(),
            None,
            "the route itself is not repeated as a spelling"
        );
    }

    /// **A trailing argv appends to `command`**, so a fixed leading argument keeps its place.
    #[test]
    fn a_trailing_argv_appends_to_the_commands_fixed_arguments() {
        let fixture = Fixture::new();
        let spec = fixture.spec();

        let boundary = fixture.translate(&spec, "[agent]", &["printf x", "--", "tail"]);

        assert_eq!(
            boundary.executable(),
            Path::new("/bin/sh")
                .canonicalize()
                .expect("sh resolves")
                .parent()
                .expect("a directory")
                .join("sh")
        );
        assert_eq!(boundary.arguments(), ["-c", "printf x", "--", "tail"]);
        assert_eq!(boundary.working_directory(), fixture.path("project"));
    }

    /// **A `${NAME}` in `command` resolves to this run's value**, and the text around it is
    /// unchanged.
    #[test]
    fn a_core_owned_token_expands_to_this_runs_value() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec();
        spec.command.push(
            "otel.trace_exporter={otlp-http={endpoint=\"${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}\"}}"
                .to_string(),
        );
        spec.command
            .push("${OTEL_EXPORTER_OTLP_ENDPOINT}/${OTEL_EXPORTER_OTLP_PROTOCOL}".to_string());

        let boundary = fixture.translate(&spec, "[agent]", &[]);

        assert_eq!(
            boundary.arguments(),
            [
                "-c",
                "otel.trace_exporter={otlp-http={endpoint=\"http://127.0.0.1:44318/v1/traces\"}}",
                "http://127.0.0.1:44318/http/protobuf",
            ],
            "every token resolves, and the text around it is untouched"
        );
        let environment = environment_of(&boundary);
        assert_eq!(
            environment["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"], "http://127.0.0.1:44318/v1/traces",
            "the signal-specific name is the full URL an exporter uses as-is"
        );
        assert_eq!(
            environment["OTEL_EXPORTER_OTLP_ENDPOINT"], "http://127.0.0.1:44318",
            "the base name stays the base, which a conforming SDK appends the route to"
        );
    }

    /// **An unknown name inside `${...}`, and an unterminated `${`, are each refused**, naming the
    /// argument.
    #[test]
    fn an_unexpandable_token_refuses_the_run() {
        let fixture = Fixture::new();
        for (argument, needle) in [
            (
                "endpoint=${OTEL_TRACES_ENDPOINT}",
                "names no expandable value",
            ),
            (
                "endpoint=${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "is never closed",
            ),
        ] {
            let mut spec = fixture.spec();
            spec.command.push(argument.to_string());

            let error = fixture
                .try_translate(&spec, "[agent]", &[])
                .err()
                .unwrap_or_else(|| panic!("{argument} must be refused"));
            let message = error.to_string();
            assert!(
                message.contains(argument) && message.contains(needle),
                "the refusal names the offending argument and why: {message}"
            );
        }
    }

    /// **A credential phantom is refused rather than expanded, and the expandable set holds exactly
    /// three telemetry names.**
    #[test]
    fn a_credential_phantom_is_refused_rather_than_expanded() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec();
        spec.command
            .push("--header=${ANTHROPIC_API_KEY}".to_string());

        let error = fixture
            .try_translate(&spec, "[agent]", &[])
            .err()
            .expect("a phantom name is not expandable");
        let message = error.to_string();
        assert!(
            message.contains("names no expandable value"),
            "the refusal is the unexpandable one: {message}"
        );
        assert!(
            !message.contains("phantom-anthropic"),
            "the refusal never carries the value: {message}"
        );

        let expandable = environment::expandable(&fixture.attachment);
        assert_eq!(
            expandable.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "OTEL_EXPORTER_OTLP_PROTOCOL",
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            ],
            "the expandable set is exactly three telemetry names"
        );
        // Every other composed name is unreachable from a token, the phantom and the headers
        // spellings included. `OTEL_EXPORTER_OTLP_HEADERS` is where OTLP puts an `Authorization`
        // value, so a prefix test would have admitted it.
        let composed = environment_of(&fixture.translate(&fixture.spec(), "[agent]", &[]));
        for name in composed.keys().map(String::as_str).chain([
            "OTEL_EXPORTER_OTLP_HEADERS",
            "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
            "ANTHROPIC_API_KEY",
        ]) {
            assert!(
                expandable.contains_key(name)
                    == matches!(
                        name,
                        "OTEL_EXPORTER_OTLP_ENDPOINT"
                            | "OTEL_EXPORTER_OTLP_PROTOCOL"
                            | "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
                    ),
                "{name} must not be expandable"
            );
        }
    }

    /// **A `${...}` in element 0 of `command` is refused.**
    #[test]
    fn a_token_in_the_program_is_refused() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec();
        spec.command[0] = "${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}".to_string();

        let error = fixture
            .try_translate(&spec, "[agent]", &[])
            .err()
            .expect("a program is never expanded");
        assert!(
            error.to_string().contains("a program is never expanded"),
            "the refusal says why: {error}"
        );
    }

    /// **Expansion applies to `command` and not to the trailing argv**, which runs unchanged.
    #[test]
    fn a_trailing_argument_is_never_expanded() {
        let fixture = Fixture::new();
        let boundary = fixture.translate(
            &fixture.spec(),
            "[agent]",
            &["print ${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT} and ${WHATEVER}"],
        );

        assert_eq!(
            boundary.arguments(),
            [
                "-c",
                "print ${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT} and ${WHATEVER}"
            ]
        );
    }

    /// **Every list translates to its cell**, beside the command's own exec grant and the
    /// workspace's enter-only grant.
    #[test]
    fn the_eight_lists_translate_to_their_cells() {
        let fixture = Fixture::new();
        let boundary =
            fixture.translate_with_reach(&fixture.spec(), "[agent]", RuntimeReach::Agent);
        let translated = cells(&boundary);
        let has = |relative: &str, operation: Operation, scope: Scope| {
            translated.contains(&(fixture.path(relative), operation, scope))
        };

        assert!(
            has("vendor", Operation::Read, Scope::Root),
            "{translated:?}"
        );
        assert!(
            has("scratch", Operation::Write, Scope::Root),
            "{translated:?}"
        );
        assert!(
            has("notes/api.md", Operation::Read, Scope::File),
            "{translated:?}"
        );
        assert!(
            has("notes/api.md", Operation::Write, Scope::File),
            "{translated:?}"
        );
        assert!(
            has("notes", Operation::Metadata, Scope::Root),
            "{translated:?}"
        );
        assert!(has("tools", Operation::Exec, Scope::Root), "{translated:?}");
        assert!(
            has("bin/run", Operation::Exec, Scope::File),
            "{translated:?}"
        );
        assert!(
            has("vendor/sdk", Operation::Deny, Scope::Root),
            "{translated:?}"
        );
        assert!(
            has("project", Operation::Metadata, Scope::Dir),
            "the workspace is enterable, and neither readable nor enumerable: {translated:?}"
        );
        assert!(
            !translated
                .iter()
                .any(|(path, operation, _)| *path == fixture.path("project")
                    && *operation == Operation::Read),
            "no read cell reaches the workspace: {translated:?}"
        );
        let command = boundary
            .executable()
            .canonicalize()
            .expect("the command resolves");
        assert!(
            translated.contains(&(command, Operation::Exec, Scope::File)),
            "the command's identity is granted exec at file scope: {translated:?}"
        );
        assert!(
            !translated
                .iter()
                .any(|(path, _, _)| path.starts_with(fixture.root.root().join("private"))),
            "no cell reaches private state: {translated:?}"
        );
        for alias in fixture.root.shell_aliases() {
            assert!(
                translated.contains(&(alias.clone(), Operation::Exec, Scope::File)),
                "every shell alias is executable: {translated:?}"
            );
        }
        // The agent gets an alias for every declared MCP server.
        for alias in fixture.root.mcp_aliases(&fixture.record.mcp) {
            assert!(
                translated.contains(&(alias.clone(), Operation::Exec, Scope::File)),
                "every MCP alias is executable by the agent: {translated:?}"
            );
        }
    }

    /// **A tool gets every phantom and no MCP alias**: the box is the credential boundary, and only
    /// the agent starts an MCP server.
    #[test]
    fn a_tool_gets_every_phantom_and_no_mcp_alias() {
        let fixture = Fixture::new();
        let boundary = fixture.translate(&fixture.spec(), "[tool.sh]", &[]);
        let translated = cells(&boundary);
        for alias in fixture.root.mcp_aliases(&fixture.record.mcp) {
            assert!(
                !translated.iter().any(|(path, _, _)| *path == alias),
                "a tool gets no MCP alias: {translated:?}"
            );
        }
        let environment = environment_of(&boundary);
        for phantom in &fixture.attachment.phantoms {
            assert_eq!(
                environment.get(&phantom.name),
                Some(&phantom.value),
                "a tool gets every phantom"
            );
        }
    }

    /// **A program outside every exec grant is still refused.** The loader's directories are read
    /// roots of the minimum, and no cell reaches a program directory or grants exec beyond the
    /// command, the stated `exec` entries, and the aliases.
    #[test]
    fn a_program_outside_every_exec_grant_is_still_refused() {
        let fixture = Fixture::new();
        let boundary = fixture.translate(&fixture.spec(), "[agent]", &[]);
        let translated = cells(&boundary);

        for program_directory in ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec"] {
            let identity = Path::new(program_directory)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(program_directory));
            assert!(
                !translated.iter().any(|(path, _, scope)| {
                    *path == identity || *scope == Scope::Root && identity.starts_with(path)
                }),
                "no cell reaches {program_directory}: {translated:?}"
            );
        }
        let command = boundary
            .executable()
            .canonicalize()
            .expect("the command resolves");
        let mut permitted: Vec<PathBuf> =
            vec![command, fixture.path("tools"), fixture.path("bin/run")];
        permitted.extend(fixture.root.shell_aliases());
        permitted.extend(fixture.root.python_aliases());
        permitted.extend(fixture.root.mcp_aliases(&fixture.record.mcp));
        let unexpected: Vec<&PathBuf> = translated
            .iter()
            .filter(|(_, operation, _)| *operation == Operation::Exec)
            .map(|(path, _, _)| path)
            .filter(|path| !permitted.contains(path))
            .collect();
        assert!(
            unexpected.is_empty(),
            "exec is the command, the `exec` entries, and the aliases: {unexpected:?}"
        );
        if cfg!(target_os = "linux") {
            assert!(
                boundary
                    .disclosure()
                    .contains("(loader directory: code maps and runs here)"),
                "the Linux disclosure states the loader residual: {}",
                boundary.disclosure()
            );
        }
    }

    /// **The environment is phantoms beneath the spec's variables beneath Core's names**, `HOME`
    /// is the operator's when undeclared, `PATH` starts with the alias directory, and nothing is
    /// inherited from the host.
    #[test]
    fn the_environment_is_composed_and_inherits_nothing() {
        let fixture = Fixture::new();
        let boundary =
            fixture.translate_with_reach(&fixture.spec(), "[agent]", RuntimeReach::Agent);
        let environment = environment_of(&boundary);

        assert_eq!(
            environment.get("HOME").map(String::as_str),
            fixture.operator.path().to_str(),
            "HOME is the operator's when env.HOME is unset"
        );
        assert_eq!(environment.get("FOO").map(String::as_str), Some("declared"));
        assert_eq!(
            environment.get("MODEL_TOKEN").map(String::as_str),
            Some("phantom-model"),
            "every phantom is present"
        );
        assert_eq!(
            environment.get("OTHER_TOKEN").map(String::as_str),
            Some("phantom-other"),
            "every phantom is present, whatever route provisioned it"
        );
        assert!(
            environment["PATH"]
                .starts_with(&format!("{}:", fixture.root.bin_directory().display())),
            "PATH starts with the alias directory: {}",
            environment["PATH"]
        );
        assert_eq!(
            environment["PWD"],
            fixture.path("project").display().to_string()
        );
        assert_eq!(environment["USER"], environment::WORKLOAD_USER);
        assert_eq!(environment["HTTPS_PROXY"], "http://127.0.0.1:41080");
        let allowed: Vec<&str> = ["HOME", "FOO", "TMPDIR"]
            .into_iter()
            .chain(
                fixture
                    .attachment
                    .phantoms
                    .iter()
                    .map(|phantom| phantom.name.as_str()),
            )
            .chain(environment::CORE_OWNED)
            .collect();
        for name in environment.keys() {
            assert!(
                allowed.contains(&name.as_str()),
                "{name} reached the process from nowhere the spec or Core states"
            );
        }
        for name in environment::CORE_OWNED {
            assert!(environment.contains_key(name), "Core sets {name}");
            assert!(
                name == "PATH" || crate::record::config::env::reserved_workload_environment(name),
                "{name} is Core's, so a spec may not claim it"
            );
        }
    }

    /// **A leaf holds no variable from the operator's environment**: only its spec's `env`, every
    /// phantom, and Core's names, in both egress modes.
    #[test]
    fn a_leaf_holds_no_operator_variable_only_its_spec_phantom_and_core_names() {
        let fixture = Fixture::new();
        for egress in [EgressMode::Gateway, EgressMode::Native] {
            let leaf =
                fixture.translate_full(&fixture.spec(), "[tool.sh]", RuntimeReach::Leaf, egress);
            let environment = environment_of(&leaf);

            assert_eq!(
                environment.get("HOME").map(String::as_str),
                fixture.operator.path().to_str(),
                "a leaf's HOME is the operator's when env.HOME is unset ({egress:?})"
            );
            assert_eq!(environment.get("FOO").map(String::as_str), Some("declared"));
            for phantom in &fixture.attachment.phantoms {
                assert_eq!(
                    environment.get(&phantom.name),
                    Some(&phantom.value),
                    "every phantom reaches a leaf ({egress:?})"
                );
            }
            let allowed: Vec<&str> = ["HOME", "FOO", "TMPDIR"]
                .into_iter()
                .chain(
                    fixture
                        .attachment
                        .phantoms
                        .iter()
                        .map(|phantom| phantom.name.as_str()),
                )
                .chain(environment::CORE_OWNED)
                .collect();
            for name in environment.keys() {
                assert!(
                    allowed.contains(&name.as_str()),
                    "{name} reached the leaf from nowhere the spec or Core states ({egress:?})"
                );
            }
            for name in environment::CORE_OWNED {
                assert!(
                    environment.contains_key(name),
                    "Core sets {name} on a leaf ({egress:?})"
                );
            }
        }
    }

    /// **A declared `HOME` and `PATH` are honoured**, and Core's names still win a collision.
    #[test]
    fn a_declared_home_and_path_win_beneath_cores_names() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec();
        let home = fixture.path("scratch");
        spec.env
            .insert("HOME".to_string(), home.display().to_string());
        spec.env
            .insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        // A phantom that collides with a declared name loses to the spec.
        spec.env
            .insert("MODEL_TOKEN".to_string(), "declared-wins".to_string());

        let boundary = fixture.translate_with_reach(&spec, "[agent]", RuntimeReach::Agent);
        let environment = environment_of(&boundary);

        assert_eq!(environment["HOME"], home.display().to_string());
        assert_eq!(
            environment["PATH"],
            format!("{}:/usr/bin:/bin", fixture.root.bin_directory().display())
        );
        assert_eq!(environment["MODEL_TOKEN"], "declared-wins");
        assert!(
            boundary
                .disclosure()
                .contains(&format!("HOME={}", home.display())),
            "the disclosure names the effective HOME: {}",
            boundary.disclosure()
        );
    }

    /// **The disclosure names every grant, Core's minimum, and the effective `HOME` and `PATH`.**
    #[test]
    fn the_disclosure_states_what_the_process_reaches() {
        let fixture = Fixture::new();
        let boundary =
            fixture.translate_with_reach(&fixture.spec(), "[agent]", RuntimeReach::Agent);
        let disclosure = boundary.disclosure();

        for needle in [
            "strands-box: [agent] runs",
            &format!("read        {}", fixture.path("vendor").display()),
            &format!("write       {}", fixture.path("scratch").display()),
            &format!("exec        {}", fixture.path("tools").display()),
            &format!(
                "exec        {}  (command, implicit)",
                Path::new("/bin/sh").canonicalize().expect("sh").display()
            ),
            "strands-box: [agent] runtime minimum, added by Core:",
            "/dev/null",
            &format!(
                "enter       {}  (workspace, entry only)",
                fixture.path("project").display()
            ),
            &format!(
                "HOME={} PATH={}:",
                fixture.operator.path().display(),
                fixture.root.bin_directory().display()
            ),
        ] {
            assert!(
                disclosure.contains(needle),
                "missing {needle:?} in:\n{disclosure}"
            );
        }
        assert!(
            !disclosure.contains("warning"),
            "a command outside every writable grant earns no warning: {disclosure}"
        );
    }

    /// **A command inside its own writable grant is disclosed as a warning**, and still runs.
    #[test]
    fn a_writable_command_is_disclosed_as_a_warning() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec();
        spec.command = vec![fixture.path("tools/run").display().to_string()];
        spec.filesystem.write.push(fixture.path("tools"));
        spec.filesystem.exec = vec![fixture.path("bin/run")];

        let boundary = fixture.translate(&spec, "[agent]", &[]);

        assert!(
            boundary.disclosure().contains("warning: [agent] command")
                && boundary
                    .disclosure()
                    .contains("can replace the program it runs"),
            "{}",
            boundary.disclosure()
        );
    }

    /// **An interpreter hop inside a writable grant is disclosed as a warning**, like the command.
    #[test]
    fn a_writable_interpreter_is_disclosed_as_a_warning() {
        let fixture = Fixture::new();
        let interpreter = fixture.path("scratch/interp");
        std::fs::copy("/bin/sh", &interpreter).expect("an interpreter copy");
        std::fs::write(
            fixture.path("bin/run"),
            format!("#!{}\n", interpreter.display()),
        )
        .expect("a script naming it");
        let mut spec = fixture.spec();
        spec.command = vec![fixture.path("bin/run").display().to_string()];
        spec.filesystem.exec = vec![fixture.path("bin/run")];

        let boundary = fixture.translate(&spec, "[agent]", &[]);
        let disclosure = boundary.disclosure();

        assert!(
            disclosure.contains("warning: [agent] interpreter")
                && disclosure.contains(&interpreter.display().to_string()),
            "{disclosure}"
        );
    }

    /// **A writable interpreter a stated `exec` entry covers is still disclosed**, because the
    /// exposure is the same whichever list granted the hop.
    #[test]
    fn a_writable_interpreter_under_a_stated_exec_grant_is_still_disclosed() {
        let fixture = Fixture::new();
        let interpreter = fixture.path("scratch/interp");
        std::fs::copy("/bin/sh", &interpreter).expect("an interpreter copy");
        std::fs::write(
            fixture.path("bin/run"),
            format!("#!{}\n", interpreter.display()),
        )
        .expect("a script naming it");
        let mut spec = fixture.spec();
        spec.command = vec![fixture.path("bin/run").display().to_string()];
        spec.filesystem.exec = vec![fixture.path("bin/run"), interpreter.clone()];

        let boundary = fixture.translate(&spec, "[agent]", &[]);
        let disclosure = boundary.disclosure();

        assert!(
            disclosure.contains("warning: [agent] interpreter")
                && disclosure.contains(&interpreter.display().to_string()),
            "{disclosure}"
        );
    }

    /// **The command's exec rule is disclosed as implicit unless an `exec` entry names it.**
    #[test]
    fn the_commands_exec_rule_is_disclosed_as_implicit_unless_listed() {
        let fixture = Fixture::new();
        let sh = Path::new("/bin/sh").canonicalize().expect("sh exists");
        let needle = format!("exec        {}  (command, implicit)", sh.display());

        let implicit = fixture.translate(&fixture.spec(), "[agent]", &[]);
        assert!(
            implicit.disclosure().contains(&needle),
            "{}",
            implicit.disclosure()
        );

        let mut spec = fixture.spec();
        spec.filesystem.exec.push(sh);
        let listed = fixture.translate(&spec, "[agent]", &[]);
        assert!(
            !listed.disclosure().contains(&needle),
            "{}",
            listed.disclosure()
        );
    }

    /// **A linked command keeps its route when an `exec` entry names its target**: the profile
    /// carries the spelling the box execs.
    #[cfg(unix)]
    #[test]
    fn a_linked_command_keeps_its_route_when_an_exec_entry_names_its_target() {
        let fixture = Fixture::new();
        let link = fixture.path("bin/link");
        std::os::unix::fs::symlink(fixture.path("bin/run"), &link).expect("a link to the command");
        let mut spec = fixture.spec();
        spec.command = vec![link.display().to_string()];
        spec.filesystem.exec = vec![fixture.path("bin/run")];

        let boundary = fixture.translate(&spec, "[agent]", &[]);

        assert_eq!(boundary.executable(), link.as_path());
        let config = std::fs::read_to_string(boundary.containment_config()).expect("config");
        assert!(
            config.contains("bin/link"),
            "the route must be in the profile: {config}"
        );
        let translated = cells(&boundary);
        assert_eq!(
            translated
                .iter()
                .filter(|(path, operation, scope)| {
                    *path == fixture.path("bin/run")
                        && *operation == Operation::Exec
                        && *scope == Scope::File
                })
                .count(),
            1,
            "{translated:?}"
        );
    }

    /// **A workload-authored command may not bring an interpreter no `exec` entry covers**: the
    /// caller-boundary launch refuses the shebang hop by name, and an entry covering it lets it run.
    #[cfg(unix)]
    #[test]
    fn a_fallback_program_may_not_bring_an_unlisted_interpreter() {
        use std::os::unix::fs::PermissionsExt as _;
        let fixture = Fixture::new();
        let built = fixture.path("scratch/built.sh");
        std::fs::write(&built, "#!/bin/sh\nprintf ran\n").expect("a built script");
        std::fs::set_permissions(&built, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        let mut spec = fixture.spec();
        spec.command = vec![built.display().to_string()];
        spec.filesystem.exec = vec![fixture.path("scratch")];
        let fallback = fixture.path("project");
        let translate = |spec: &ProcessSpec| {
            crate::test_support::with_operator_home(fixture.operator.path(), || {
                Boundary::translate(
                    spec,
                    Launch {
                        table: "[agent]",
                        trailing: &[],
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::MustBeListed,
                        runtime_reach: RuntimeReach::Leaf,
                        argument_zero: None,
                        egress: EgressMode::Gateway,
                        approved: None,
                    },
                    &Site {
                        attachment: &fixture.attachment,
                        layout: &fixture.root,
                        stored: &fixture.record,
                        protected_sources: &[],
                    },
                )
            })
        };

        let refused = translate(&spec)
            .err()
            .expect("an unlisted interpreter is refused");
        assert!(
            refused.to_string().contains("names the interpreter"),
            "{refused}"
        );

        spec.filesystem
            .exec
            .push(Path::new("/bin/sh").canonicalize().expect("sh"));
        // macOS `/bin/sh` is a selector that execs the `/var/select/sh` variant, which the
        // interpreter chain grants too, so the `exec` list must cover it. Linux has no selector.
        #[cfg(target_os = "macos")]
        if let Ok(variant) = Path::new("/var/select/sh").canonicalize() {
            spec.filesystem.exec.push(variant);
        }
        translate(&spec).expect("a listed interpreter lets the script run");
    }

    /// **A command named in its own `exec` list is granted once**, and the disclosure then shows the
    /// operator's entry rather than the implicit rule.
    #[test]
    fn a_command_named_in_its_own_exec_list_is_granted_once() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec();
        spec.command = vec![fixture.path("bin/run").display().to_string()];
        spec.filesystem.exec = vec![fixture.path("bin/run")];

        let boundary = fixture.translate(&spec, "[agent]", &[]);

        let translated = cells(&boundary);
        assert_eq!(
            translated
                .iter()
                .filter(|(path, operation, scope)| {
                    *path == fixture.path("bin/run")
                        && *operation == Operation::Exec
                        && *scope == Scope::File
                })
                .count(),
            1,
            "{translated:?}"
        );
        assert!(
            !boundary.disclosure().contains("(command, implicit)"),
            "{}",
            boundary.disclosure()
        );
    }

    /// **An interpreter a stated `exec` entry names is granted once**, whichever spelling the shebang
    /// uses for it.
    #[test]
    fn an_interpreter_an_exec_entry_covers_is_not_granted_twice() {
        let fixture = Fixture::new();
        let sh = Path::new("/bin/sh").canonicalize().expect("sh exists");
        let mut spec = fixture.spec();
        spec.command = vec![fixture.path("bin/run").display().to_string()];
        spec.filesystem.exec = vec![fixture.path("bin/run"), sh.clone()];

        let boundary = fixture.translate(&spec, "[agent]", &[]);

        let translated = cells(&boundary);
        assert_eq!(
            translated
                .iter()
                .filter(|(path, operation, scope)| {
                    *path == sh && *operation == Operation::Exec && *scope == Scope::File
                })
                .count(),
            1,
            "{translated:?}"
        );
    }

    /// The contract's full Claude Code example, with `/Users/example` and `/opt` planted under one
    /// temporary root and every system path left real.
    struct ContractExample {
        fixture: Fixture,
        root: PathBuf,
        /// The host's `/etc/localtime`, or a planted file where a build host has none.
        localtime: PathBuf,
        localtime_is_real: bool,
    }

    impl ContractExample {
        fn new() -> Self {
            let fixture = Fixture::new();
            let root = fixture.path("contract");
            for directory in [
                "Users/example/work/catalog-api/src",
                "Users/example/work/catalog-api/.git/hooks",
                "Users/example/work/catalog-api/secrets",
                "Users/example/box-demo/agent-home",
                "Users/example/box-demo/agent-tmp",
                "Users/example/box-demo/git-home",
                "Users/example/box-demo/git-tmp",
                "Users/example/box-demo/hook-home",
                "Users/example/box-demo/hook-tmp",
                "Users/example/box-demo/hook-output",
                "Users/example/box-demo/aws-home",
                "Users/example/box-demo/aws-tmp",
                "opt/claude/bin",
                "opt/box-tools/bin",
                "opt/box-runtime/python/bin",
                "opt/box-hooks",
                "opt/aws-cli/v2/current/bin",
            ] {
                std::fs::create_dir_all(root.join(directory)).expect("a directory");
            }
            for file in [
                "Users/example/work/catalog-api/.env",
                "Users/example/.gitconfig",
                "Users/example/box-demo/hook-output/events.log",
                "opt/box-hooks/record-edit.py",
            ] {
                std::fs::write(root.join(file), "").expect("a file");
            }
            for program in [
                "opt/claude/bin/claude",
                "opt/box-tools/bin/git",
                "opt/box-runtime/python/bin/python3",
                "opt/aws-cli/v2/current/bin/aws",
            ] {
                std::fs::write(root.join(program), "#!/bin/sh\n").expect("a program");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(
                        root.join(program),
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .expect("an executable program");
                }
            }
            let (localtime, localtime_is_real) = match Path::new("/etc/localtime").canonicalize() {
                Ok(real) => (real, true),
                Err(_) => {
                    std::fs::create_dir_all(root.join("etc")).expect("an etc directory");
                    std::fs::write(root.join("etc/localtime"), "").expect("a planted localtime");
                    (root.join("etc/localtime"), false)
                }
            };
            Self {
                fixture,
                root,
                localtime,
                localtime_is_real,
            }
        }

        /// The example's spelling of an absolute path, planted under the temporary root.
        fn at(&self, example_path: &str) -> String {
            format!("{}{example_path}", self.root.display())
        }

        /// One table of the example, with its `/Users/example` and `/opt` paths planted, `/bin/sh`
        /// spelled as the identity the host resolves it to, and the two entries the host refuses by
        /// name removed: `list` on Linux, and `metadata` on `/etc`, which the floor refuses
        /// everywhere because the privilege configuration under it is never reachable through a
        /// root grant (`the_contract_examples_etc_metadata_entry_is_refused_by_the_floor`).
        fn spec(&self, table: &str) -> ProcessSpec {
            let sh = Path::new("/bin/sh")
                .canonicalize()
                .expect("the host has a shell")
                .display()
                .to_string();
            let localtime = self.localtime.display().to_string();
            let text = table
                .replace("/Users/example", &self.at("/Users/example"))
                .replace("/opt/", &self.at("/opt/"))
                .replace("\"/bin/sh\"", &format!("{sh:?}"))
                .replace("\"/etc/localtime\"", &format!("{localtime:?}"));
            let mut spec: ProcessSpec = toml::from_str(&text).expect("the example parses");
            if cfg!(target_os = "linux") {
                spec.filesystem.list.clear();
            }
            spec.filesystem
                .metadata
                .retain(|path| path != Path::new("/etc"));
            spec
        }
    }

    /// **The contract example's `metadata = ["/etc"]` is refused as too broad by the system-tree
    /// floor**, because a `metadata` entry is a root grant and that row permits the `/etc` entry
    /// alone, which is what a path lookup needs. This test canonicalizes the path, so on macOS it
    /// reaches the floor; an operator's own `/etc` spelling meets the symbolic-link refusal on an
    /// `[agent.filesystem]` entry first, and `/private/etc` is the spelling the floor judges.
    #[test]
    fn the_contract_examples_etc_metadata_entry_is_refused_by_the_floor() {
        let example = ContractExample::new();
        let mut spec = example.spec(CONTRACT_AGENT);
        let etc = Path::new("/etc").canonicalize().expect("etc exists");
        spec.filesystem.metadata.push(etc.clone());
        let fallback = example.fixture.path("project");

        let error =
            crate::test_support::with_operator_home(example.fixture.operator.path(), || {
                Boundary::translate(
                    &spec,
                    Launch {
                        table: "[agent]",
                        trailing: &[],
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::Granted,
                        runtime_reach: RuntimeReach::Leaf,
                        argument_zero: None,
                        egress: EgressMode::Gateway,
                        approved: None,
                    },
                    &Site {
                        attachment: &example.fixture.attachment,
                        layout: &example.fixture.root,
                        stored: &example.fixture.record,
                        protected_sources: &[],
                    },
                )
            })
            .err()
            .expect("a metadata root grant on /etc is refused");

        let message = error.to_string();
        assert!(
            message.contains(&format!("\"{}\" is refused", etc.display()))
                && message.contains("too broad"),
            "{message}"
        );
    }

    /// **A working directory the launch role supplies is judged like a declared one**: the box's
    /// own directory and the operator's home are refused whichever branch names them.
    #[test]
    fn a_fallback_working_directory_is_judged_like_a_declared_one() {
        let fixture = Fixture::new();
        let mut spec = fixture.spec();
        spec.workspace = None;
        for (fallback, needle) in [
            (fixture.root.root().to_path_buf(), "Box's own directory"),
            (fixture.root.root().join("bin"), "Box's own directory"),
            (fixture.operator.path().to_path_buf(), "operator's home"),
        ] {
            let error = crate::test_support::with_operator_home(fixture.operator.path(), || {
                Boundary::translate(
                    &spec,
                    Launch {
                        table: "[tool.sh]",
                        trailing: &[],
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::Granted,
                        runtime_reach: RuntimeReach::Leaf,
                        argument_zero: None,
                        egress: EgressMode::Gateway,
                        approved: None,
                    },
                    &Site {
                        attachment: &fixture.attachment,
                        layout: &fixture.root,
                        stored: &fixture.record,
                        protected_sources: &[],
                    },
                )
            })
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "{} must be refused as a working directory",
                    fallback.display()
                )
            });
            assert!(error.to_string().contains(needle), "{error}");
        }
    }

    /// **The translator refuses a declared home in trusted Box state**, for the agent and for a
    /// tool, so a spec reaching it by any route meets the same refusal the configuration does.
    #[test]
    fn a_declared_home_in_trusted_box_state_is_refused_by_the_translator() {
        let fixture = Fixture::new();
        let fallback = fixture.path("project");
        for (table, home) in [
            ("[agent]", fixture.root.root().join("home")),
            ("[tool.sh]", fixture.root.root().join("private/h")),
        ] {
            let mut spec = fixture.spec();
            spec.env
                .insert("HOME".to_string(), home.display().to_string());

            let error = crate::test_support::with_operator_home(fixture.operator.path(), || {
                Boundary::translate(
                    &spec,
                    Launch {
                        table,
                        trailing: &[],
                        fallback_workspace: &fallback,
                        shebang_interpreters: ShebangInterpreters::Granted,
                        runtime_reach: RuntimeReach::Leaf,
                        argument_zero: None,
                        egress: EgressMode::Gateway,
                        approved: None,
                    },
                    &Site {
                        attachment: &fixture.attachment,
                        layout: &fixture.root,
                        stored: &fixture.record,
                        protected_sources: &[],
                    },
                )
            })
            .err()
            .unwrap_or_else(|| panic!("{} must be refused as {table}'s home", home.display()));

            let message = error.to_string();
            assert!(
                message.contains(table) && message.contains("trusted Box state"),
                "{message}"
            );
        }
    }

    /// **A metadata cell on an ancestor of private state grants none of its contents**, while a
    /// read cell there is refused: the exemption the guards carry for `Metadata` is exact.
    #[test]
    fn a_metadata_only_ancestor_does_not_grant_private_contents() {
        let box_directory = Path::new("/boxes/codex");
        let private = box_directory.join("private");
        for scope in [Scope::Dir, Scope::Root] {
            require_private_state_absent(Path::new("/boxes"), Operation::Metadata, scope, &private)
                .expect("metadata on an ancestor exposes no private content");
        }
        require_private_state_absent(&private, Operation::Metadata, Scope::Dir, &private)
            .expect_err("metadata on private state itself is refused");
        require_private_state_absent(Path::new("/boxes"), Operation::Read, Scope::Root, &private)
            .expect_err("a read root above private state is refused");
        require_box_directory_absent(
            Path::new("/boxes"),
            Operation::Metadata,
            Scope::Root,
            box_directory,
        )
        .expect("metadata above the box directory exposes nothing");
        require_box_directory_absent(
            Path::new("/boxes"),
            Operation::Read,
            Scope::Root,
            box_directory,
        )
        .expect_err("a read root above the box directory is refused");
    }

    /// **A policy path spelled through a parent component still resolves to the file it names**,
    /// so the write guard judges the same identity the box loads.
    #[test]
    fn a_policy_spelled_through_a_parent_component_is_still_resolved() {
        let fixture = Fixture::new();
        let policy = fixture.path("project/.strands-box/policy.dw");
        std::fs::create_dir_all(policy.parent().unwrap()).expect("the authority directory");
        std::fs::write(&policy, "").expect("a policy");
        let spelled = fixture.path("project/src/../.strands-box/policy.dw");
        assert_eq!(
            crate::record::layout::resolved_to_its_deepest_existing_ancestor(&spelled),
            policy
        );
        let absent = fixture.path("project/src/../.strands-box/later/policy.dw");
        assert_eq!(
            crate::record::layout::resolved_to_its_deepest_existing_ancestor(&absent),
            policy.parent().unwrap().join("later/policy.dw")
        );
    }

    const CONTRACT_AGENT: &str = r#"
command = ["/opt/claude/bin/claude"]
workspace = "/Users/example/work/catalog-api"
env = { HOME = "/Users/example/box-demo/agent-home", TMPDIR = "/Users/example/box-demo/agent-tmp", PATH = "/opt/box-tools/bin:/usr/bin:/bin" }

[filesystem]
list = ["/Users/example/work"]
read = ["/Users/example/work/catalog-api", "/Users/example/box-demo/agent-home", "/Users/example/box-demo/agent-tmp"]
write = ["/Users/example/work/catalog-api/src", "/Users/example/box-demo/agent-home", "/Users/example/box-demo/agent-tmp"]
read_file = ["/etc/localtime"]
metadata = ["/etc", "/Users/example/work"]
exec = ["/bin/sh"]
deny = ["/Users/example/work/catalog-api/.env", "/Users/example/work/catalog-api/secrets"]
"#;

    const CONTRACT_GIT: &str = r#"
command = ["/opt/box-tools/bin/git"]
workspace = "/Users/example/work/catalog-api"
env = { HOME = "/Users/example/box-demo/git-home", TMPDIR = "/Users/example/box-demo/git-tmp", PATH = "/opt/box-tools/bin:/usr/bin:/bin", GIT_CONFIG_GLOBAL = "/Users/example/.gitconfig", GIT_TERMINAL_PROMPT = "0" }

[filesystem]
read = ["/Users/example/work/catalog-api", "/Users/example/box-demo/git-home", "/Users/example/box-demo/git-tmp"]
write = ["/Users/example/work/catalog-api", "/Users/example/box-demo/git-home", "/Users/example/box-demo/git-tmp"]
read_file = ["/Users/example/.gitconfig", "/etc/localtime"]
metadata = ["/etc"]
exec = ["/bin/sh", "/Users/example/work/catalog-api/.git/hooks"]
deny = ["/Users/example/work/catalog-api/.env", "/Users/example/work/catalog-api/secrets"]
"#;

    const CONTRACT_RECORD_EDIT: &str = r#"
command = ["/opt/box-runtime/python/bin/python3", "/opt/box-hooks/record-edit.py"]
workspace = "/Users/example/box-demo/hook-output"
env = { HOME = "/Users/example/box-demo/hook-home", TMPDIR = "/Users/example/box-demo/hook-tmp", PATH = "/opt/box-runtime/python/bin:/usr/bin:/bin", BOX_LOG_PATH = "/Users/example/box-demo/hook-output/events.log", PYTHONDONTWRITEBYTECODE = "1" }

[filesystem]
read = ["/Users/example/box-demo/hook-home", "/Users/example/box-demo/hook-tmp"]
write = ["/Users/example/box-demo/hook-home", "/Users/example/box-demo/hook-tmp"]
read_file = ["/opt/box-hooks/record-edit.py"]
write_file = ["/Users/example/box-demo/hook-output/events.log"]
"#;

    const CONTRACT_AWS: &str = r#"
command = ["/opt/aws-cli/v2/current/bin/aws"]
workspace = "/Users/example/work/catalog-api"
env = { HOME = "/Users/example/box-demo/aws-home", TMPDIR = "/Users/example/box-demo/aws-tmp", AWS_REGION = "us-east-2", AWS_PAGER = "" }

[filesystem]
read = ["/opt/aws-cli/v2/current", "/Users/example/box-demo/aws-home", "/Users/example/box-demo/aws-tmp"]
write = ["/Users/example/box-demo/aws-tmp"]
"#;

    /// **The contract's full Claude Code example translates, table by table, to the cells the
    /// contract states**, every process gets every phantom, and only the agent gets MCP aliases.
    #[test]
    fn the_contracts_claude_code_example_translates_to_its_cells() {
        let example = ContractExample::new();
        let fixture = &example.fixture;
        let at = |path: &str| PathBuf::from(example.at(path));
        let identity = |path: &str| Path::new(path).canonicalize().expect("a system path");

        // [agent]
        let agent = fixture.translate_with_reach(
            &example.spec(CONTRACT_AGENT),
            "[agent]",
            RuntimeReach::Agent,
        );
        let translated = cells(&agent);
        let has = |path: PathBuf, operation: Operation, scope: Scope| {
            translated.contains(&(path, operation, scope))
        };
        for tree in [
            "/Users/example/work/catalog-api",
            "/Users/example/box-demo/agent-home",
            "/Users/example/box-demo/agent-tmp",
        ] {
            assert!(
                has(at(tree), Operation::Read, Scope::Root),
                "read {tree}: {translated:?}"
            );
        }
        for tree in [
            "/Users/example/work/catalog-api/src",
            "/Users/example/box-demo/agent-home",
            "/Users/example/box-demo/agent-tmp",
        ] {
            assert!(
                has(at(tree), Operation::Write, Scope::Root),
                "write {tree}: {translated:?}"
            );
        }
        assert!(
            has(example.localtime.clone(), Operation::Read, Scope::File),
            "the stated entry and the minimum's cell are one: {translated:?}"
        );
        if example.localtime_is_real {
            assert_eq!(
                translated
                    .iter()
                    .filter(|(path, _, _)| *path == example.localtime)
                    .count(),
                1,
                "the stated entry replaces the minimum's cell: {translated:?}"
            );
        } else {
            println!(
                "skipping: this host has no /etc/localtime, so the minimum has no cell to replace"
            );
        }
        assert!(has(identity("/etc"), Operation::Metadata, Scope::Dir));
        assert!(has(
            at("/Users/example/work"),
            Operation::Metadata,
            Scope::Root
        ));
        if cfg!(not(target_os = "linux")) {
            assert!(has(at("/Users/example/work"), Operation::List, Scope::Root));
        }
        assert!(has(identity("/bin/sh"), Operation::Exec, Scope::File));
        assert!(has(
            at("/Users/example/work/catalog-api/.env"),
            Operation::Deny,
            Scope::File
        ));
        assert!(has(
            at("/Users/example/work/catalog-api/secrets"),
            Operation::Deny,
            Scope::Root
        ));
        assert!(
            !has(
                at("/Users/example/work/catalog-api"),
                Operation::Metadata,
                Scope::Dir
            ),
            "a workspace a read entry covers needs no enter-only grant: {translated:?}"
        );
        for alias in fixture.root.mcp_aliases(&fixture.record.mcp) {
            assert!(has(alias, Operation::Exec, Scope::File));
        }
        let environment = environment_of(&agent);
        assert_eq!(
            environment["HOME"],
            example.at("/Users/example/box-demo/agent-home")
        );
        assert_eq!(
            environment["PATH"],
            format!(
                "{}:{}:/usr/bin:/bin",
                fixture.root.bin_directory().display(),
                example.at("/opt/box-tools/bin")
            )
        );
        assert_eq!(environment["ANTHROPIC_API_KEY"], "phantom-anthropic");
        assert_eq!(environment["GITHUB_GIT_AUTH"], "phantom-github-git");
        assert_eq!(environment["AWS_ACCESS_KEY_ID"], "phantom-aws");
        assert_eq!(
            agent.working_directory(),
            at("/Users/example/work/catalog-api")
        );

        // [tool.git]
        let git = fixture.translate(&example.spec(CONTRACT_GIT), "[tool.git]", &["status"]);
        let translated = cells(&git);
        let has = |path: PathBuf, operation: Operation, scope: Scope| {
            translated.contains(&(path, operation, scope))
        };
        assert!(has(
            at("/Users/example/work/catalog-api"),
            Operation::Write,
            Scope::Root
        ));
        assert!(has(
            at("/Users/example/.gitconfig"),
            Operation::Read,
            Scope::File
        ));
        assert!(has(
            at("/Users/example/work/catalog-api/.git/hooks"),
            Operation::Exec,
            Scope::Root
        ));
        assert!(has(
            at("/Users/example/work/catalog-api/.env"),
            Operation::Deny,
            Scope::File
        ));
        assert_eq!(git.arguments(), ["status"]);
        let environment = environment_of(&git);
        assert_eq!(
            environment["HOME"],
            example.at("/Users/example/box-demo/git-home")
        );
        assert_eq!(environment["GIT_TERMINAL_PROMPT"], "0");
        assert_eq!(environment["GITHUB_GIT_AUTH"], "phantom-github-git");
        assert_eq!(environment["ANTHROPIC_API_KEY"], "phantom-anthropic");

        // [tool.record-edit]
        let hook = fixture.translate(
            &example.spec(CONTRACT_RECORD_EDIT),
            "[tool.record-edit]",
            &[],
        );
        let translated = cells(&hook);
        let has = |path: PathBuf, operation: Operation, scope: Scope| {
            translated.contains(&(path, operation, scope))
        };
        assert!(has(
            at("/opt/box-hooks/record-edit.py"),
            Operation::Read,
            Scope::File
        ));
        assert!(has(
            at("/Users/example/box-demo/hook-output/events.log"),
            Operation::Write,
            Scope::File
        ));
        assert!(
            has(
                at("/Users/example/box-demo/hook-output"),
                Operation::Metadata,
                Scope::Dir
            ),
            "a workspace no list covers is enterable only: {translated:?}"
        );
        assert_eq!(
            hook.arguments(),
            [example.at("/opt/box-hooks/record-edit.py")]
        );
        assert_eq!(environment_of(&hook)["PYTHONDONTWRITEBYTECODE"], "1");

        // [tool.aws]
        let aws = fixture.translate(
            &example.spec(CONTRACT_AWS),
            "[tool.aws]",
            &["sts", "get-caller-identity"],
        );
        let translated = cells(&aws);
        assert!(translated.contains(&(
            at("/opt/aws-cli/v2/current"),
            Operation::Read,
            Scope::Root
        )));
        assert!(translated.contains(&(
            at("/Users/example/box-demo/aws-tmp"),
            Operation::Write,
            Scope::Root
        )));
        let environment = environment_of(&aws);
        assert_eq!(environment["AWS_ACCESS_KEY_ID"], "phantom-aws");
        assert_eq!(environment["AWS_PAGER"], "");
        assert_eq!(
            environment["PATH"],
            std::env::var("PATH").expect("the operator has a PATH"),
            "a tool's undeclared PATH is the operator's, with no alias directory"
        );
    }

    /// **A leaf resolves its shebang hops past the alias directory.** A leaf whose declared `PATH`
    /// names the alias directory runs a `#!/usr/bin/env bash` script on the surrounding OS's `bash`.
    #[test]
    fn a_leafs_shebang_resolves_past_the_alias_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let fixture = Fixture::new();
        let bin = fixture.root.bin_directory();
        let script = fixture.path("scripts/run.sh");
        std::fs::create_dir_all(script.parent().expect("a parent")).expect("a script directory");
        std::fs::write(&script, "#!/usr/bin/env bash\nexit 0\n").expect("a script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("an executable script");
        let mut spec = fixture.spec();
        spec.command = vec![script.display().to_string()];
        spec.env.insert(
            "PATH".to_string(),
            format!("{}:/usr/bin:/bin", bin.display()),
        );

        let leaf = fixture
            .try_translate_full(&spec, "[tool.run]", RuntimeReach::Leaf, EgressMode::Gateway)
            .unwrap_or_else(|error| panic!("the leaf translates: {error}"));
        let leaf_cells = cells(&leaf);
        assert!(
            !leaf_cells.iter().any(|(path, _, _)| path.starts_with(&bin)),
            "the shebang resolves to no alias: {leaf_cells:?}"
        );
        assert!(
            leaf_cells
                .iter()
                .any(|(path, operation, _)| *operation == Operation::Exec
                    && path.file_name().is_some_and(|name| name == "bash")),
            "the surrounding OS's bash is the shebang hop: {leaf_cells:?}"
        );
    }

    /// **Apart from its output, nothing comes back from a leaf.** A leaf holds no alias on its
    /// `PATH`, no exec on any alias, and no connect on the broker socket, so it cannot reach the
    /// Strands Shell again. The agent keeps all three.
    #[test]
    fn a_leaf_holds_no_route_back_to_the_broker() {
        let fixture = Fixture::new();
        let socket = fixture.root.broker_socket();
        let bin = fixture.root.bin_directory();
        // A declared PATH that names the alias directory, in any spelling, still gives a leaf none
        // of it.
        let link = fixture.path("bin-link");
        std::os::unix::fs::symlink(&bin, &link).expect("a link to the alias directory");
        let mut spec = fixture.spec();
        spec.env.insert(
            "PATH".to_string(),
            format!(
                "/usr/bin:{bin}:{bin}/:{bin}/../bin:{link}:/bin",
                bin = bin.display(),
                link = link.display()
            ),
        );

        for egress in [EgressMode::Gateway, EgressMode::Native] {
            let leaf = fixture.translate_full(&spec, "[tool.sh]", RuntimeReach::Leaf, egress);
            let leaf_cells = cells(&leaf);
            assert_eq!(environment_of(&leaf)["PATH"], "/usr/bin:/bin");
            assert!(
                !leaf_cells.iter().any(|(path, _, _)| path.starts_with(&bin)),
                "a leaf reaches no alias: {leaf_cells:?}"
            );
            assert!(
                !leaf_cells.iter().any(|(path, _, _)| *path == socket),
                "a leaf cannot connect to the broker: {leaf_cells:?}"
            );
            assert!(
                !leaf_cells
                    .iter()
                    .any(|(path, _, _)| path.starts_with(fixture.root.run_directory())),
                "a leaf reaches nothing under the run directory: {leaf_cells:?}"
            );
            // A native-egress leaf may connect to any socket it can see, so the box directory must
            // stay hidden from its discovery.
            if cfg!(target_os = "macos") {
                let config: serde_json::Value =
                    serde_json::from_str(&leaf.containment_config_text())
                        .expect("the config is JSON");
                let root = fixture
                    .root
                    .root()
                    .canonicalize()
                    .expect("the box root resolves");
                assert!(
                    config["discovery_denies"]
                        .as_array()
                        .expect("a leaf lists its discovery denies")
                        .iter()
                        .any(|denied| denied.as_str() == root.to_str()),
                    "a leaf's discovery excludes the box directory: {config}"
                );
            }
        }

        let agent =
            fixture.translate_full(&spec, "[agent]", RuntimeReach::Agent, EgressMode::Gateway);
        let agent_cells = cells(&agent);
        assert_eq!(
            environment_of(&agent)["PATH"],
            format!("{}:/usr/bin:/bin", bin.display())
        );
        for alias in fixture
            .root
            .shell_aliases()
            .into_iter()
            .chain(fixture.root.python_aliases())
        {
            assert!(
                agent_cells.contains(&(alias.clone(), Operation::Exec, Scope::File)),
                "the agent execs {}: {agent_cells:?}",
                alias.display()
            );
        }
        assert!(
            agent_cells.contains(&(socket.clone(), Operation::Connect, Scope::File)),
            "the agent connects to the broker: {agent_cells:?}"
        );
    }

    /// **The agent's one connect grant is its own broker, and a leaf holds none.**
    #[test]
    fn no_box_holds_a_connect_grant_beyond_its_own_broker() {
        let fixture = Fixture::new();
        let spec = fixture.spec();
        let connects = |boundary: &Boundary| {
            cells(boundary)
                .into_iter()
                .filter(|(_, operation, _)| *operation == Operation::Connect)
                .map(|(path, _, _)| path)
                .collect::<Vec<_>>()
        };

        let agent =
            fixture.translate_full(&spec, "[agent]", RuntimeReach::Agent, EgressMode::Gateway);
        assert_eq!(
            connects(&agent),
            [fixture.root.broker_socket()],
            "the agent connects to its own broker alone"
        );
        for egress in [EgressMode::Gateway, EgressMode::Native] {
            let leaf = fixture.translate_full(&spec, "[tool.sh]", RuntimeReach::Leaf, egress);
            assert_eq!(
                connects(&leaf),
                Vec::<PathBuf>::new(),
                "a {egress:?} leaf connects to no socket"
            );
        }
    }

    /// **`Agent` withholds leaf-only cells, and `Leaf` carries them.**
    ///
    /// The agent's launch role selects the first, so a harness no longer reads the frameworks or the
    /// loader's library directories. Both reaches keep what any process needs to run at all, which
    /// is what makes this a narrowing rather than a break.
    #[test]
    fn agent_containment_withholds_leaf_cells() {
        let fixture = Fixture::new();
        let spec = fixture.spec();
        let narrow = cells(&fixture.translate_with_reach(&spec, "[agent]", RuntimeReach::Agent));
        let wide = cells(&fixture.translate_with_reach(&spec, "[tool.sh]", RuntimeReach::Leaf));

        // On identity, because the config stores a canonical path and `/etc` is a link on macOS.
        let holds = |set: &[(PathBuf, Operation, Scope)], path: &str| {
            let wanted = Path::new(path)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(path));
            set.iter()
                .any(|(cell, _, _)| cell.canonicalize().unwrap_or_else(|_| cell.clone()) == wanted)
        };

        // **Named per platform, because membership differs and existence does not say which set a
        // path is in.** `/usr/share/terminfo` exists on Linux and is macOS-only in the leaf
        // file, so a list gated on existence alone asserted the wrong thing there and failed the
        // Linux build.
        #[cfg(target_os = "macos")]
        let leaf_only = ["/usr/lib", "/etc/ssl", "/usr/share/terminfo"];
        #[cfg(not(target_os = "macos"))]
        let leaf_only = ["/usr/lib", "/etc/ssl", "/lib"];
        for leaf_only in leaf_only {
            if !Path::new(leaf_only).exists() {
                println!("skipping: this host has no {leaf_only}");
                continue;
            }
            assert!(
                holds(&wide, leaf_only),
                "leaf containment must carry {leaf_only}"
            );
            assert!(
                !holds(&narrow, leaf_only),
                "agent containment must withhold {leaf_only}: {narrow:?}"
            );
        }

        // The control: a narrowing that withheld these would stop every box from running.
        // `/System/Library` is in that set because Node opens
        // `/System/Library/OpenSSL/openssl.cnf` before it runs a line — measured, and withholding it
        // aborted Node 18 at startup.
        for both in ["/dev/null", "/usr/share/zoneinfo", "/System/Library"] {
            if !Path::new(both).exists() {
                continue;
            }
            assert!(holds(&narrow, both), "agent containment must keep {both}");
            assert!(holds(&wide, both), "leaf containment must keep {both}");
        }
        // The mediation plumbing is the agent's alone and grows with the declared MCP servers, so the
        // comparison is over the runtime cells.
        let runtime = |set: &[(PathBuf, Operation, Scope)]| {
            set.iter()
                .filter(|(cell, _, _)| {
                    !cell.starts_with(fixture.root.bin_directory())
                        && *cell != fixture.root.broker_socket()
                })
                .count()
        };
        assert!(
            runtime(&narrow) < runtime(&wide),
            "agent containment must be the smaller set: {} against {}",
            runtime(&narrow),
            runtime(&wide)
        );
    }

    /// **The agent's launch selects `Agent` and every other launch selects `Leaf`.**
    ///
    /// Read from the source, because the choice is one field at each call site. It reads each
    /// `Launch { … }` literal as a block and pairs its `table` with its `runtime_reach`, so swapping
    /// the two reaches fails it — a test that only counted the two spellings did not.
    #[test]
    fn the_agent_launch_selects_agent_containment() {
        /// Every `(table, reach)` pair a source file's production half states.
        fn pairs(source: &str) -> Vec<(String, String)> {
            // The production half only: a `#[cfg(test)]` module builds fixtures with either reach.
            let production = match source.find("\n#[cfg(test)]\nmod tests {") {
                Some(at) => &source[..at],
                None => source,
            };
            let mut found = Vec::new();
            for block in production.split("Launch {").skip(1) {
                let literal = block.split("},").next().unwrap_or(block);
                let field = |name: &str| {
                    literal
                        .split(&format!("{name}:"))
                        .nth(1)
                        .map(|rest| rest.split(',').next().unwrap_or("").trim().to_string())
                };
                if let (Some(table), Some(reach)) = (field("table"), field("runtime_reach")) {
                    found.push((table, reach));
                }
            }
            found
        }

        let run = pairs(include_str!("../../command/run.rs"));
        assert!(!run.is_empty(), "run.rs states no Launch");
        for (table, reach) in &run {
            let expected = if table.contains("[agent]") {
                "RuntimeReach::Agent"
            } else {
                "RuntimeReach::Leaf"
            };
            assert_eq!(
                reach, expected,
                "the launch for {table} must select {expected}"
            );
        }
        assert!(
            run.iter().any(|(table, _)| table.contains("[agent]")),
            "run.rs must state the agent's launch: {run:?}"
        );
        assert!(
            run.iter().any(|(table, _)| !table.contains("[agent]")),
            "run.rs must state a tool's launch: {run:?}"
        );

        // A host binary the Shell spawned is a tool, whatever table it came from.
        for (table, reach) in pairs(include_str!("../hosted.rs")) {
            assert_eq!(
                reach, "RuntimeReach::Leaf",
                "a spawned program's launch ({table}) must select leaf containment"
            );
        }
    }

    /// A tool's credential-store grant reaches its own boundary, and no other table's.
    #[test]
    fn a_credential_store_grant_reaches_only_its_own_table() {
        let mut fixture = Fixture::new();
        let store = fixture.path(".aws");
        std::fs::create_dir_all(&store).expect("a credential store");
        std::fs::write(store.join("credentials"), "[default]\n").expect("a credential");
        let mut granted = fixture.spec();
        granted.filesystem.read.push(store.clone());
        fixture.record.tool.insert("a".to_string(), granted.clone());
        fixture.record.tool.insert("b".to_string(), fixture.spec());

        let config = |boundary: &Boundary| -> serde_json::Value {
            serde_json::from_str(&boundary.containment_config_text()).expect("the config is JSON")
        };
        let a = fixture.translate_full(
            &granted,
            "[tool.a]",
            RuntimeReach::Leaf,
            EgressMode::Gateway,
        );
        assert!(
            cells(&a)
                .iter()
                .any(|(path, _, _)| path.starts_with(&store)),
            "the table that names the store reaches it: {:?}",
            cells(&a)
        );
        assert_eq!(
            config(&a)["credential_store_grants"]
                .as_array()
                .map(Vec::len),
            Some(1),
            "the table that names the store carries its one exception"
        );

        let b = fixture.translate_full(
            &fixture.spec(),
            "[tool.b]",
            RuntimeReach::Leaf,
            EgressMode::Gateway,
        );
        let agent = fixture.translate_with_reach(&fixture.spec(), "[agent]", RuntimeReach::Agent);
        for (table, boundary) in [("[tool.b]", &b), ("[agent]", &agent)] {
            let translated = cells(boundary);
            assert!(
                !translated
                    .iter()
                    .any(|(path, _, _)| path.starts_with(&store)),
                "{table} reaches no path under the store: {translated:?}"
            );
            assert!(
                config(boundary)["credential_store_grants"]
                    .as_array()
                    .is_none_or(Vec::is_empty),
                "{table} carries no credential-store exception"
            );
        }
    }

    /// The agent's boundary ignores tool and MCP grants, and adds one alias per added MCP server.
    #[test]
    fn the_agent_boundary_is_identical_with_and_without_tool_and_mcp_grants() {
        let mut fixture = Fixture::new();
        let spec = fixture.spec();
        let before = fixture
            .translate_with_reach(&spec, "[agent]", RuntimeReach::Agent)
            .containment_config_text();

        let mut tool = fixture.spec();
        tool.filesystem.read.push(fixture.path("project"));
        tool.filesystem.write.push(fixture.path("tools"));
        fixture.record.tool.insert("sh".to_string(), tool.clone());
        fixture.record.contained_mcp.insert(
            "alpha".to_string(),
            ContainedMcp {
                spec: ProcessSpec {
                    network: Some(crate::record::config::process::NetworkConfig {
                        contain_egress: false,
                    }),
                    ..tool
                },
            },
        );
        let granted = fixture
            .translate_with_reach(&spec, "[agent]", RuntimeReach::Agent)
            .containment_config_text();
        assert_eq!(
            granted, before,
            "a tool or MCP grant does not change the agent's boundary"
        );

        let server = McpServer {
            name: "gamma".to_string(),
            command: vec!["gamma-mcp".to_string()],
        };
        let alias = fixture
            .root
            .mcp_aliases(std::slice::from_ref(&server))
            .remove(0);
        std::fs::write(&alias, []).expect("the alias placeholder is written");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o500))
                .expect("the alias placeholder is executable");
        }
        let alias = alias.canonicalize().expect("the alias resolves");
        let before_cells =
            cells(&fixture.translate_with_reach(&spec, "[agent]", RuntimeReach::Agent));
        fixture.record.mcp.push(server);
        let mut after_cells =
            cells(&fixture.translate_with_reach(&spec, "[agent]", RuntimeReach::Agent));
        let added = after_cells
            .iter()
            .position(|cell| *cell == (alias.clone(), Operation::Exec, Scope::File))
            .unwrap_or_else(|| panic!("the added server's alias is granted: {after_cells:?}"));
        after_cells.remove(added);
        assert_eq!(
            after_cells, before_cells,
            "an added MCP server adds its alias and nothing else"
        );
    }
}
