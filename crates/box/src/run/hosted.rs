//! One box's trusted half, owned by the `run` process that started it.
//!
//! [`HostedBox`] holds everything that decides for one box: its `PolicyEngine` and temporal
//! history, its egress gateway and that gateway's ephemeral certificate authority, its broker
//! socket with both interpreters behind it, and only that box's resolved secrets. It is opened
//! before the workload is spawned and dropped when the workload exits.
//!
//! **There is no daemon.** The process that parents the workload is the process that decides for
//! it, so authority lives where the parent already is. Two properties follow:
//!
//! - **One compromise reaches one box.** A shared process would hold N boxes' plaintext secrets
//!   and N signing keys in one address space, reachable by a memory-safety failure in the least
//!   trustworthy code there.
//! - **One failure reaches one box.** A bind failure refuses this run and no other.
//!
//! **One `run` owns a box at a time** (docs/design/decisions.md#one-run-owns-one-box-directory).
//! The box lock is held for the whole run, so a second `run` refuses by name rather than starting
//! a second `PolicyEngine`. Two engines mean two temporal histories, and a rule spanning `fs:*` and
//! `net:*` would then load cleanly and enforce nothing.
//!
//! Drop order carries teardown: discovery joins, the broker unbinds, the gateway joins, the record
//! is withdrawn, and the lock releases last.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use egress_gateway::{
    CapabilitySet, CredentialCapability, MitmConfig, MitmHandle, MitmInterceptor,
};
use policy::{
    EgressPolicyInterceptor, GovernedBox, McpServerKind, PolicyEngine, Principal, ToolCatalogs,
};

use crate::error::{BoxError, ConfigError, DaemonError};
use crate::record::config::process::ProcessSpec;
use crate::record::config::{AuthoritySource, Record};
use crate::record::layout::BoxRoot;
use crate::run::broker::BrokerHost;
use crate::run::broker::complete::{DiscoveryCoordinator, DiscoveryDoor};
use crate::run::broker::mcp::DiscoveryRegistryHost;
use crate::run::broker::shell::EgressRouting;
use crate::run::contain::boundary::{
    ApprovedReach, Boundary, EgressMode, Launch, RuntimeReach, ShebangInterpreters, Site,
};
use crate::run::credential;
use crate::run::lock::{BoxLive, Lock};
use crate::run::telemetry;

/// What the workload's boundary needs from the box hosting it.
#[derive(Debug, Clone)]
pub(crate) struct Attachment {
    /// The proxy's loopback port, which becomes the workload's only route out.
    pub(crate) proxy_port: u16,

    /// This box's telemetry port, which the agent's own instrumentation exports to.
    pub(crate) telemetry_port: u16,

    /// The public CA certificate the workload must trust, when the proxy has one.
    pub(crate) trust_bundle: Option<TrustBundle>,

    /// Every variable a route provisions, placed in every process the box starts.
    pub(crate) phantoms: Vec<credential::ProvisionedVariable>,
}

/// One opened public trust bundle and the bytes read from that identity.
#[derive(Debug, Clone)]
pub(crate) struct TrustBundle {
    pub(crate) path: std::path::PathBuf,
    pub(crate) opened: Arc<std::fs::File>,
    pub(crate) pem: Arc<Vec<u8>>,
}

/// The process the hosted Shell runs for one host-binary invocation: the `[tool.<name>]` whose
/// `command` prefix matched, or the caller itself for a program under one of its own `exec` entries.
pub(crate) struct SelectedTool {
    pub(crate) table: String,
    pub(crate) spec: ProcessSpec,
    /// The invocation's arguments after the spec's fixed ones.
    pub(crate) trailing: Vec<String>,
    /// Granted for a table's own command; a workload-built program must have its interpreters listed.
    pub(crate) shebang_interpreters: ShebangInterpreters,
}

/// Select the tool whose `command` prefix matches `program`, the identity the `shell:spawn`
/// decision named, and `args`, among every declared tool. The longest matching prefix wins.
/// A program no table names runs in the caller's own boundary when it lies under one of the
/// caller's `exec` entries.
///
/// The prefix is compared expanded, because the translator runs the expanded arguments.
pub(crate) fn select_tool(
    record: &Record,
    attachment: &Attachment,
    program: &Path,
    args: &[String],
) -> Result<SelectedTool, BoxError> {
    let refuse = |reason: String| {
        BoxError::from(ConfigError::ToolSelection {
            program: program.display().to_string(),
            reason,
        })
    };
    let caller = record
        .agent
        .as_ref()
        .ok_or_else(|| refuse("the configuration has no `[agent]` table".to_string()))?;
    let no_match = || {
        refuse(
            "no `[tool.<name>] command` matches this program and its leading arguments".to_string(),
        )
    };
    // The identity is compared as the decision named it: resolving it again here would judge a file
    // planted after the decision.
    let invoked = program;
    // The matched prefix length travels with the winner, so `trailing` never re-derives it from an
    // unexpanded count.
    let mut selected: Option<(&str, &ProcessSpec, usize)> = None;
    let mut unexpandable: Vec<String> = Vec::new();
    let mut named_by_a_table = false;
    for (label, spec) in &record.tool {
        let Ok(resolved) =
            crate::run::contain::executable::resolve(spec.program(), &spec.search_path())
        else {
            continue;
        };
        if resolved.granted_path() != invoked {
            continue;
        }
        named_by_a_table = true;
        // A token this build cannot expand is the operator's error, so the refusal names it rather
        // than reporting a non-match. It is held until the loop ends, so a malformed table cannot
        // hide a sibling that matches.
        let fixed = match crate::run::contain::boundary::environment::expanded_arguments(
            spec, attachment,
        ) {
            Ok(fixed) => fixed,
            Err(reason) => {
                unexpandable.push(format!("`[tool.{label}]` {reason}"));
                continue;
            }
        };
        if args.len() < fixed.len() || args[..fixed.len()] != fixed[..] {
            continue;
        }
        if selected.is_none_or(|(_, current, _)| spec.command.len() > current.command.len()) {
            selected = Some((label, spec, fixed.len()));
        }
    }
    match selected {
        Some((label, spec, fixed)) => Ok(SelectedTool {
            table: format!("[tool.{label}]"),
            spec: spec.clone(),
            trailing: args[fixed..].to_vec(),
            shebang_interpreters: ShebangInterpreters::Granted,
        }),
        None if !unexpandable.is_empty() => Err(refuse(unexpandable[0].clone())),
        // A program some table names is that table's, whatever its arguments; it never runs as
        // the caller's own build output.
        None if named_by_a_table => Err(no_match()),
        None if caller_exec_covers(caller, invoked) => Ok(SelectedTool {
            table: "[agent]".to_string(),
            spec: ProcessSpec {
                command: vec![invoked.display().to_string()],
                network: None,
                ..caller.clone()
            },
            trailing: args.to_vec(),
            shebang_interpreters: ShebangInterpreters::MustBeListed,
        }),
        None => Err(no_match()),
    }
}

/// Whether `program` lies under one of `caller`'s own `exec` entries and under none of its `deny`
/// entries, each judged by its identity.
fn caller_exec_covers(caller: &ProcessSpec, program: &Path) -> bool {
    let operator_home = crate::record::layout::operator_home_directory().ok();
    let expanded = |entry: &Path| -> Option<PathBuf> {
        let spelled = entry.to_string_lossy();
        // `~` and `~/…` are both home-relative, so neither reaches `canonicalize` as a literal.
        let relative = spelled
            .strip_prefix("~/")
            .or_else(|| spelled.strip_prefix('~').filter(|rest| rest.is_empty()));
        match (relative, &operator_home) {
            (Some(relative), Some(home)) => Some(home.join(relative)),
            (Some(_), None) => None,
            _ => Some(entry.to_path_buf()),
        }
    };
    let covers = |identity: &Path| {
        if identity.is_dir() {
            program.starts_with(identity)
        } else {
            identity == program
        }
    };
    let granted = caller.filesystem.exec.iter().any(|entry| {
        expanded(entry)
            .and_then(|path| path.canonicalize().ok())
            .is_some_and(|identity| covers(&identity))
    });
    if !granted {
        return false;
    }
    // An `exec` entry this run cannot resolve grants nothing, and a `deny` entry it cannot resolve
    // refuses, so each unresolved entry fails closed. An entry that names no file is the one
    // resolution failure that covers nothing.
    for entry in &caller.filesystem.deny {
        let Some(path) = expanded(entry) else {
            return false;
        };
        match path.canonicalize() {
            Ok(identity) if covers(&identity) => return false,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return false,
        }
    }
    true
}

/// Build the hook that runs a host binary in its own boundary
/// (docs/design/decisions.md#the-box-runs-a-host-binary-through-the-spawn-host-seam).
///
/// The box installs this on the hosted Shell in place of the vendored crate's built-in spawn. Each
/// call selects the tool the invocation matches, translates that tool's `ProcessSpec` through the
/// same translator the agent used, runs it through the trampoline, and hands the captured output
/// back.
fn tool_spawner(
    attachment: Attachment,
    layout: BoxRoot,
    record: Record,
    approved: Arc<ApprovedReach>,
    workspace: PathBuf,
    protected_sources: Vec<AuthoritySource>,
    recorder: Arc<telemetry::DecisionRecorder>,
) -> strands_shell::os::HostSpawner {
    Arc::new(move |spawn: strands_shell::os::HostSpawn| {
        let recorder = Arc::clone(&recorder);
        let attachment = attachment.clone();
        let layout = layout.clone();
        let record = record.clone();
        let approved = Arc::clone(&approved);
        let workspace = workspace.clone();
        let protected_sources = protected_sources.clone();
        Box::pin(async move {
            let selected = select_tool(&record, &attachment, &spawn.program, &spawn.args)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let cwd = caller_directory(&spawn.cwd, &selected.spec, &workspace);
            let table = selected.table.clone();
            // The reach this run judged for the table; every declared table was judged, so a miss
            // is refused.
            let reach = approved.table(&table).ok_or_else(|| {
                std::io::Error::other(format!("{table} has no reach judged for this run"))
            })?;
            let site = Site {
                attachment: &attachment,
                layout: &layout,
                stored: &record,
                protected_sources: &protected_sources,
            };
            let boundary = Boundary::translate(
                &selected.spec,
                Launch {
                    table: &table,
                    trailing: &selected.trailing,
                    fallback_workspace: &cwd,
                    shebang_interpreters: selected.shebang_interpreters,
                    // A spawned host binary is the toolchain case: it loads frameworks and
                    // libraries the agent's own program never touches.
                    runtime_reach: RuntimeReach::Leaf,
                    argument_zero: Some(&spawn.invoked),
                    egress: EgressMode::for_spec(&selected.spec),
                    approved: Some(reach),
                },
                &site,
            )
            .map_err(|error| std::io::Error::other(error.to_string()))?;
            // Recorded before the run, so a call the agent cancels or outlasts still leaves it.
            if selected.spec.native_egress() {
                let label = table
                    .strip_prefix("[tool.")
                    .and_then(|rest| rest.strip_suffix(']'))
                    .unwrap_or(&table);
                recorder.record(telemetry::EffectiveDecision::enforcement_permit(
                    "egress:native",
                    label.to_string(),
                    "native-egress",
                ));
            }
            let captured = crate::run::contain::supervise::LeafBox::run(boundary, &layout)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            Ok(strands_shell::os::HostSpawnOutcome {
                status: captured.status,
                stdout: captured.stdout,
                stderr: captured.stderr,
            })
        })
    })
}

/// Builds and spawns the contained leaf for a stdio MCP server. Every stdio server is contained;
/// its `[mcp.<name>]` grants describe the leaf's reach.
///
/// It owns clones of the same launch inputs the tool-spawn hook closes over — the parent box's
/// `Attachment`, `BoxRoot`, `Record`, and protected sources — so the broker thread can contain a
/// server through the same [`Boundary::translate`] the agent and tools use, without the raw values
/// crossing the thread boundary. A contained MCP leaf reuses the parent's gateway and policy exactly
/// as a tool leaf does; it owns no second [`HostedBox`].
pub(crate) struct McpLeafLauncher {
    attachment: Attachment,
    layout: BoxRoot,
    record: Record,
    protected_sources: Vec<AuthoritySource>,
    /// The agent's workspace — the contained MCP leaf's working directory. NOT the box's
    /// `private/mcp` (the non-unix/no-launcher fallback start's cwd): that is private Box state and
    /// a leaf grant on it is refused ("would expose private Box state").
    workspace: PathBuf,
}

impl McpLeafLauncher {
    fn new(
        attachment: Attachment,
        layout: BoxRoot,
        record: Record,
        protected_sources: Vec<AuthoritySource>,
        workspace: PathBuf,
    ) -> Self {
        Self {
            attachment,
            layout,
            record,
            protected_sources,
            workspace,
        }
    }

    /// Whether `server` has a contained leaf this launcher must start — true for every stdio
    /// server. A server absent here is remote (http), which has no leaf.
    pub(crate) fn contains(&self, server: &str) -> bool {
        self.record.contained_mcp.contains_key(server)
    }

    /// Whether `server` was granted native egress (`contain_egress = false`) — its leaf bypasses the
    /// gateway, so its outbound traffic is not mediated, credential-injected, or journaled. The
    /// broker records that downgrade explicitly when it starts such a server.
    pub(crate) fn is_native_egress(&self, server: &str) -> bool {
        self.record
            .contained_mcp
            .get(server)
            .is_some_and(|contained| contained.spec.native_egress())
    }

    /// The credential-store spellings `server`'s filesystem lists grant its leaf.
    pub(crate) fn credential_reads(&self, server: &str, operator_home: &Path) -> Vec<String> {
        self.record
            .contained_mcp
            .get(server)
            .map(|contained| {
                contained
                    .spec
                    .credential_store_entries(operator_home)
                    .into_iter()
                    .map(|(_, spelling)| spelling)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Translate `server`'s `[mcp.<name>]` `ProcessSpec` into the boundary its leaf will run in.
    pub(crate) fn prepare(&self, server: &str) -> Result<Boundary, BoxError> {
        let contained = self.record.contained_mcp.get(server).ok_or_else(|| {
            BoxError::from(ConfigError::Contract {
                reason: format!("no contained MCP server named {server:?}"),
            })
        })?;
        let table = format!("[mcp.{server}]");
        let site = Site {
            attachment: &self.attachment,
            layout: &self.layout,
            stored: &self.record,
            protected_sources: &self.protected_sources,
        };
        let egress = EgressMode::for_spec(&contained.spec);
        Boundary::translate(
            &contained.spec,
            Launch {
                table: &table,
                trailing: &[],
                fallback_workspace: &self.workspace,
                shebang_interpreters: ShebangInterpreters::Granted,
                argument_zero: None,
                runtime_reach: RuntimeReach::Leaf,
                egress,
                approved: None,
            },
            &site,
        )
    }

    /// Spawn the contained streaming leaf `boundary` describes.
    pub(crate) async fn spawn(
        &self,
        boundary: Boundary,
    ) -> Result<crate::run::contain::supervise::StreamingLeaf, BoxError> {
        crate::run::contain::supervise::LeafBox::spawn_streaming(boundary, &self.layout).await
    }
}

/// The directory a tool starts in when its spec names none: the caller's, when it resolves inside
/// the agent's workspace or a tree the tool's own lists name; else the agent's workspace.
fn caller_directory(requested: &Path, tool: &ProcessSpec, agent_workspace: &Path) -> PathBuf {
    let Ok(resolved) = requested.canonicalize() else {
        return agent_workspace.to_path_buf();
    };
    let operator_home = crate::record::layout::operator_home_directory().ok();
    let lists = &tool.filesystem;
    let mut roots = lists
        .read
        .iter()
        .chain(&lists.write)
        .chain(&lists.list)
        .chain(&lists.metadata)
        .filter_map(|entry| {
            let spelled = entry.to_string_lossy();
            let expanded = match (spelled.strip_prefix("~/"), &operator_home) {
                (Some(relative), Some(home)) => home.join(relative),
                _ if spelled == "~" => operator_home.clone()?,
                _ => entry.clone(),
            };
            expanded.canonicalize().ok()
        })
        .chain(std::iter::once(agent_workspace.to_path_buf()));
    if roots.any(|root| resolved.starts_with(&root)) {
        resolved
    } else {
        agent_workspace.to_path_buf()
    }
}

/// The published live record, withdrawn when this value drops.
struct PublishedRecord(BoxRoot);

impl Drop for PublishedRecord {
    fn drop(&mut self) {
        BoxLive::withdraw(&self.0);
    }
}

/// One box's trusted half: its authority, its gateway, and its broker.
pub(crate) struct HostedBox {
    /// Run-scoped lazy MCP discovery and its finalization worker.
    discovery: Option<DiscoveryRegistryHost>,

    /// The broker serving this box's aliases.
    broker: Option<BrokerHost>,

    /// A fatal cross-door completion verdict from the discovery coordinator,
    /// raced against the broker and the registry in [`stopped`](Self::stopped).
    coordinator_fatal: tokio::sync::mpsc::UnboundedReceiver<BoxError>,

    /// The egress gateway. Dropped after the broker, which joins its accept thread.
    _proxy: MitmHandle,

    /// This box's collector. Dropped after the gateway, and the drain that precedes teardown is
    /// what exports; a verdict taken after it reaches no target.
    _collector: Arc<telemetry::Collector>,

    /// What this run's boundary reads. Plain data, so its position carries nothing.
    attachment: Attachment,

    /// Every process table's filesystem reach, judged once when this run started.
    approved: Arc<ApprovedReach>,

    /// The inactive kernel policy adapter shares this run's existing authority.
    #[cfg(feature = "kernel-policy-integration")]
    _kernel_policy: policy::KernelPolicyAdapter,

    /// The live record, withdrawn before the lock frees, so no reader finds a record whose lock is
    /// already available.
    _record: PublishedRecord,

    /// The box lock. Dropped LAST, so no second run starts before teardown ends.
    _owned: Lock,
}

impl HostedBox {
    pub(crate) fn prepare_policy(
        root: &BoxRoot,
        operator: &policy::Operator,
        sources: Vec<policy::Policy>,
    ) -> Result<Arc<PolicyEngine>, BoxError> {
        let database_path = root.dogwood_database();
        let database = root.open_dogwood_database()?;
        Ok(Arc::new(
            PolicyEngine::open_staged_file(operator, sources, database, database_path)?
                .observed_by(Arc::new(telemetry::PolicyDecisionObserver)),
        ))
    }

    /// Open this box's trusted half, or refuse. `workspace` and `home` are the agent's effective
    /// working directory and `HOME`, which the interpreters share.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        root: &BoxRoot,
        record: &Record,
        policy: Arc<PolicyEngine>,
        collector: Arc<telemetry::Collector>,
        protected_sources: &[AuthoritySource],
        owned: Lock,
        workspace: &Path,
        home: &Path,
    ) -> Result<Self, BoxError> {
        // Whatever a previous owner left is stale, because the lock above just proved nothing of
        // this box is running.
        BoxLive::withdraw(root);
        root.remove_file(&root.broker_socket())?;
        // Re-created rather than assumed, each singly, so its mode is explicit and a symlink at
        // either name is refused rather than followed.
        let trust = root.trust_directory();
        for directory in [root.run_directory(), trust.clone()] {
            root.create_child_directory(&directory)?;
        }
        // **Both directories are CLEARED, not merely re-created.** Every cached containment config
        // names a proxy port that is about to change, and every certificate in `trust/` was minted
        root.clear_directory(&root.containment_directory())?;
        root.clear_directory(&trust)?;
        let trust_certificate = Arc::new(root.open_trust_certificate()?);

        let telemetry_port = collector.port();
        let recorder = telemetry::DecisionRecorder::over(Arc::clone(&collector));
        let projection = credential::workspace(&record.egress_routes()?)?;
        let mut capabilities = CapabilitySet::builder();
        for (destination, store) in projection.capabilities {
            capabilities =
                capabilities.add_credential(CredentialCapability::new(destination, store));
        }

        // The two-door discovery completion coordinator. It hears from the
        // stdio broker always, and from the egress gateway when the record declares a remote MCP
        // server; the door that drains last runs the one `finish_mcp_discovery` verdict. A fatal
        // verdict reaches this box's supervision through `stopped`.
        let remote_mcp_servers: Vec<(String, String)> = record.mcp_servers();
        let (coordinator_fatal_sender, coordinator_fatal) = tokio::sync::mpsc::unbounded_channel();
        let mut doors = BTreeSet::from([DiscoveryDoor::Stdio]);
        if !remote_mcp_servers.is_empty() {
            doors.insert(DiscoveryDoor::Egress);
        }
        let coordinator = DiscoveryCoordinator::new(
            doors,
            Arc::clone(&policy),
            coordinator_fatal_sender,
            Some(Arc::clone(&collector)),
        );

        // One catalog set for both kinds of MCP server, so each stages through the same rules.
        let catalogs = Arc::new(ToolCatalogs::new(
            Arc::clone(&policy),
            record
                .mcp
                .iter()
                .map(|server| (server.name.clone(), McpServerKind::Stdio))
                .chain(
                    remote_mcp_servers
                        .iter()
                        .map(|(_, name)| (name.clone(), McpServerKind::Http)),
                ),
        ));
        let egress_policy = EgressPolicyInterceptor::into_handle_with_discovery(
            Arc::clone(&policy),
            Principal::agent(),
            GovernedBox::assigned(root.name()),
            remote_mcp_servers.clone(),
            Arc::clone(&catalogs),
            {
                // The egress door reports itself finished once every remote server is terminal.
                let coordinator = Arc::clone(&coordinator);
                Arc::new(move || coordinator.report_finished(DiscoveryDoor::Egress))
            },
        );
        let proxy = MitmInterceptor::start_with_emitter_and_opened_ca(
            MitmConfig {
                intercept_ca_dir: Some(trust.clone()),
                credential_env: projection.phantom_environment,
                // The servers the gateway frames are the servers the policy door tracks.
                mcp_servers: remote_mcp_servers,
                ..MitmConfig::default()
            },
            capabilities.build(),
            // The box every request is judged as, taken from the root this process opened.
            telemetry::EgressDecisionInterceptor::over(egress_policy),
            Box::new(telemetry::EgressDecisionRecorder::over(Arc::clone(
                &recorder,
            ))),
            &trust_certificate,
        )
        .map_err(BoxError::from)?;
        let proxy_port = proxy
            .port()
            .ok_or_else(|| BoxError::from(DaemonError::NoProxyPort))?;
        require_no_private_key(root, &trust)?;
        let trust_bundle = proxy
            .intercept_ca_path()
            .map(|path| -> Result<TrustBundle, BoxError> {
                Ok(TrustBundle {
                    path: path.to_path_buf(),
                    opened: Arc::clone(&trust_certificate),
                    pem: Arc::new(crate::run::contain::boundary::read_certificate_bundle(
                        path,
                        &trust_certificate,
                    )?),
                })
            })
            .transpose()?;

        // Route the hosted Shell's outbound HTTP through this box's own gateway, so a Shell
        // `curl` meets the same `net:connect`/`http:request` policy the workload's traffic does.
        // The gateway binds TCP loopback, so the target is a `127.0.0.1:{port}`
        // proxy the Shell's reqwest client reaches natively; the CA is the gateway's intercept
        // certificate. With no interception CA there is nothing to trust, so the Shell's network
        // stays off — a fail-closed refusal, never a direct dial around the gateway.
        let egress = trust_bundle.as_ref().map(|bundle| EgressRouting {
            proxy_target: format!("http://127.0.0.1:{proxy_port}"),
            ca_pem: Arc::clone(&bundle.pem),
        });

        // The broker after the proxy, and both before the record is published: a reader that saw
        // the record before the broker bound would learn a port for a socket that does not exist,
        let discovery = DiscoveryRegistryHost::start_with_coordinator(
            &record.mcp,
            catalogs,
            Arc::clone(&coordinator),
        )
        .map_err(|source| crate::error::McpDiscoveryError::Thread { source })?;
        // Built before the broker starts, because the broker's host-binary seam runs a leaf box
        // from these exact inputs — the same attachment the agent workload uses.
        let attachment = Attachment {
            proxy_port,
            telemetry_port,
            trust_bundle,
            phantoms: projection.workload_environment,
        };
        // Every process table's lists, judged once, before any of them spawns.
        let approved = Arc::new(ApprovedReach::judge(record, protected_sources)?);
        // The host-binary seam: a command the Shell does not implement runs in the
        // boundary of the tool the invocation selects, not as an uncontained child.
        let host_spawner = Some(tool_spawner(
            attachment.clone(),
            root.clone(),
            record.clone(),
            Arc::clone(&approved),
            workspace.to_path_buf(),
            protected_sources.to_vec(),
            Arc::clone(&recorder),
        ));
        // Every stdio MCP server is started contained, as a streaming leaf, through the same inputs.
        // Built only when the box declares at least one stdio server, so a box with none carries no
        // launcher.
        let mcp_leaf_launcher = (!record.contained_mcp.is_empty()).then(|| {
            Arc::new(McpLeafLauncher::new(
                attachment.clone(),
                root.clone(),
                record.clone(),
                protected_sources.to_vec(),
                workspace.to_path_buf(),
            ))
        });
        let broker = BrokerHost::start(
            root,
            record,
            workspace,
            home,
            Arc::clone(&policy),
            discovery.registry(),
            egress,
            recorder,
            host_spawner,
            mcp_leaf_launcher,
            protected_sources,
        )?;
        BoxLive::publish(root, proxy_port)?;
        let published = PublishedRecord(root.clone());
        Ok(Self {
            discovery: Some(discovery),
            broker: Some(broker),
            coordinator_fatal,
            _proxy: proxy,
            _collector: collector,
            attachment,
            approved,
            #[cfg(feature = "kernel-policy-integration")]
            _kernel_policy: policy::KernelPolicyAdapter::new(
                policy,
                GovernedBox::assigned(root.name()),
            ),
            _record: published,
            _owned: owned,
        })
    }

    /// Open the authority for this box, over its own stored text and nothing else.
    #[cfg(test)]
    fn open_authority(root: &BoxRoot) -> Result<Arc<PolicyEngine>, BoxError> {
        let mut sources = Vec::new();
        if let Some(text) = root.read_policy()? {
            sources.push(policy::Policy {
                origin: root.policy(),
                text,
            });
        }
        Self::prepare_policy(root, &policy::Operator::unanchored(), sources)
    }

    /// What this run's boundary reads.
    pub(crate) fn attachment(&self) -> &Attachment {
        &self.attachment
    }

    /// The filesystem reach this run judged for every process table.
    pub(crate) fn approved(&self) -> &ApprovedReach {
        &self.approved
    }

    /// Wait until this box's broker stops, and answer why.
    pub(crate) async fn stopped(&mut self) -> BoxError {
        let discovery = self
            .discovery
            .as_mut()
            .expect("the discovery registry exists while the box is hosted");
        let broker = self
            .broker
            .as_mut()
            .expect("the broker exists while the box is hosted");
        tokio::select! {
            failure = discovery.stopped() => failure,
            failure = broker.stopped() => failure,
            failure = self.coordinator_fatal.recv() =>
                failure.unwrap_or_else(|| crate::error::McpDiscoveryError::NoOutcome.into()),
        }
    }
}

impl Drop for HostedBox {
    fn drop(&mut self) {
        if let Some(discovery) = &self.discovery {
            discovery.close();
        }
        drop(self.broker.take());
        drop(self.discovery.take());
    }
}

/// The PEM label that marks key material, whatever the file is called.
const PRIVATE_KEY_LABEL: &[u8] = b"PRIVATE KEY";

/// Refuse to serve when the workload-readable trust directory holds key material.
fn require_no_private_key(root: &BoxRoot, trust: &Path) -> Result<(), BoxError> {
    let entries = root.directory_entry_names(trust)?;
    for entry in entries {
        let path = trust.join(entry);
        // **An unreadable entry is refused, not skipped.** This directory is a read grant for the
        // workload, so a file whose bytes the box cannot inspect is a file it cannot clear.
        let bytes = root.read_bytes(&path)?;
        // Searched as bytes. `from_utf8_lossy` allocates a full replacement copy of anything that
        // is not valid UTF-8, and a DER file costs up to three times its size that way.
        if bytes
            .windows(PRIVATE_KEY_LABEL.len())
            .any(|w| w == PRIVATE_KEY_LABEL)
        {
            return Err(DaemonError::Refused {
                reason: format!(
                    "{} holds a private key, and that directory is granted read to the \
                     workload; the ephemeral certificate authority's key must stay in memory",
                    path.display()
                ),
            }
            .into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_uninspectable_trust_directory_is_refused() {
        let home = tempfile::tempdir().expect("operator home");
        let root = crate::record::layout::testing::box_root(home.path(), "trust-inspection");
        let trust = root.trust_directory();
        require_no_private_key(&root, &trust).expect("empty trust directory is inspectable");
        std::fs::remove_dir(&trust).expect("remove trust directory");
        require_no_private_key(&root, &trust).expect_err("missing trust directory is refused");
    }

    /// A record declaring every server named, so each gets an alias.
    fn record_with_mcp(root: &BoxRoot, mcp: Vec<crate::record::config::mcp::McpServer>) -> Record {
        Record {
            version: crate::record::config::RECORD_VERSION,
            box_id: root.name().to_string(),
            box_dir: root.root().to_path_buf(),
            name: "codex".to_string(),
            policy: None,
            agent: Some(ProcessSpec {
                command: vec!["/bin/sh".to_string()],
                workspace: None,
                env: Default::default(),
                filesystem: Default::default(),
                network: None,
            }),
            tool: Default::default(),
            egress: Default::default(),
            remote_mcp: Default::default(),
            mcp,
            contained_mcp: Default::default(),
            telemetry: Default::default(),
        }
    }

    /// The operator home a test root sits under, which is also the agent's workspace here.
    fn workspace_of(root: &BoxRoot) -> PathBuf {
        root.operator_home()
            .expect("the test root has an operator home")
            .to_path_buf()
    }

    fn record(root: &BoxRoot) -> Record {
        record_with_mcp(
            root,
            vec![crate::record::config::mcp::McpServer {
                name: "alpha".to_string(),
                command: vec!["alpha-mcp".to_string()],
            }],
        )
    }

    /// A collector with one file target, for a test that needs an authority rather than a record.
    fn collector(directory: &Path) -> Arc<telemetry::Collector> {
        Arc::new(
            ::telemetry::open(::telemetry::TelemetryConfig::for_box("codex").with_target(
                ::telemetry::Target::new(
                    ::telemetry::TargetKind::File,
                    directory.join("records.jsonl").to_string_lossy(),
                ),
            ))
            .expect("the collector opens"),
        )
    }

    #[cfg(feature = "kernel-policy-integration")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kernel_adapter_submits_to_the_hosted_authority() {
        let operator = tempfile::tempdir().unwrap();
        let root = crate::record::layout::testing::box_root(operator.path(), "kernel-test");
        let home = operator.path().canonicalize().unwrap();
        let policy = HostedBox::prepare_policy(
            &root,
            &policy::Operator::unanchored(),
            vec![policy::Policy {
                origin: root.policy(),
                text: r#"
permit(principal, action == Box::Action::"fs:write", resource);
forbid(principal, action == Box::Action::"fs:write", resource)
when { context.input.path == "~/probe" }
when temporal {
    formerly within 3600s (Box::Action::"fs:write"::request{ input.path: "~/marker" })
};"#
                .to_string(),
            }],
        )
        .unwrap();
        let owned = Lock::try_acquire(&root.lock()).unwrap().unwrap();
        let record = record_with_mcp(&root, vec![]);
        let hosted = crate::test_support::with_operator_home(operator.path(), || {
            HostedBox::open(
                &root,
                &record,
                Arc::clone(&policy),
                collector(operator.path()),
                &[],
                owned,
                &home,
                &home,
            )
            .unwrap()
        });
        let resolver = policy::PathResolver::over([home.clone()])
            .unwrap()
            .reporting_under(&home);
        let probe = resolver.approve_host(&home.join("probe")).unwrap();
        let governed = GovernedBox::assigned(root.name());
        let request = policy::Request::Fs {
            path: &probe,
            operation: policy::FsOperation::WriteContent,
        };
        assert!(
            policy
                .decide(&governed, &Principal::agent(), &request)
                .is_allow()
        );
        let marker = resolver.approve_host(&home.join("marker")).unwrap();
        assert!(
            hosted
                ._kernel_policy
                .decide(&marker, policy::FsOperation::WriteContent)
                .is_allow()
        );
        assert!(
            !policy
                .decide(&governed, &Principal::agent(), &request)
                .is_allow()
        );
    }

    fn open_hosted(operator: &tempfile::TempDir, root: &BoxRoot, record: &Record) -> HostedBox {
        open_hosted_recording(operator, root, record).0
    }

    /// The same box, with the collector handle kept, so a test can drain it and read the file.
    fn open_hosted_recording(
        operator: &tempfile::TempDir,
        root: &BoxRoot,
        record: &Record,
    ) -> (HostedBox, Arc<telemetry::Collector>) {
        let collector = collector(operator.path());
        let policy = HostedBox::prepare_policy(
            root,
            &policy::Operator::unanchored(),
            vec![policy::Policy {
                origin: root.policy(),
                text: r#"permit (principal, action == Box::Action::"mcp:call", resource);
permit (principal, action == Box::Action::"shell:spawn", resource);
permit (principal, action == alpha::Action::"read", resource);"#
                    .to_string(),
            }],
        )
        .expect("the staged authority opens");
        let owned = Lock::try_acquire(&root.lock())
            .expect("the lock opens")
            .expect("the lock is free");
        let workspace = workspace_of(root);
        let hosted = HostedBox::open(
            root,
            record,
            policy,
            Arc::clone(&collector),
            &[],
            owned,
            &workspace,
            &workspace,
        )
        .expect("the box is hosted");
        (hosted, collector)
    }

    /// **Opening the box judges every process table's reach once**, so a tool spawn acts on what
    /// this run approved and a grant that cannot be judged refuses the box before the agent starts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn opening_the_box_judges_every_process_tables_reach_once() {
        let operator = tempfile::tempdir().expect("operator home");
        let root = crate::record::layout::testing::box_root(operator.path(), "codex");
        let home = operator.path().canonicalize().expect("a canonical home");
        let vendor = home.join("vendor");
        std::fs::create_dir(&vendor).expect("a readable tree");
        let tool = |read: PathBuf| ProcessSpec {
            command: vec!["/bin/sh".to_string()],
            workspace: None,
            env: Default::default(),
            filesystem: crate::record::config::process::Filesystem {
                read: vec![read],
                ..Default::default()
            },
            network: None,
        };
        let mut record = record(&root);
        record.tool.insert("t".to_string(), tool(vendor.clone()));
        let hosted = crate::test_support::with_operator_home(operator.path(), || {
            open_hosted(&operator, &root, &record)
        });
        let approved = hosted.approved();
        assert!(approved.table("[agent]").is_some());
        let judged = approved.table("[tool.t]").expect("the tool is judged");
        assert_eq!(
            judged
                .grants
                .iter()
                .map(|grant| grant.resolved.clone())
                .collect::<Vec<_>>(),
            vec![vendor.clone()]
        );
        assert!(approved.table("[tool.absent]").is_none());
        drop(hosted);

        record
            .tool
            .insert("u".to_string(), tool(home.join("absent")));
        let collector = collector(operator.path());
        let policy = HostedBox::prepare_policy(&root, &policy::Operator::unanchored(), Vec::new())
            .expect("an empty authority opens");
        let owned = Lock::try_acquire(&root.lock())
            .expect("the lock opens")
            .expect("the lock is free");
        let workspace = workspace_of(&root);
        let refusal = crate::test_support::with_operator_home(operator.path(), || {
            HostedBox::open(
                &root,
                &record,
                policy,
                collector,
                &[],
                owned,
                &workspace,
                &workspace,
            )
        })
        .err()
        .expect("a tool grant that cannot be judged refuses the box")
        .to_string();
        assert!(refusal.contains("[tool.u]"), "{refusal}");
        assert!(refusal.contains("is not there"), "{refusal}");
    }

    #[cfg(unix)]
    fn place_aliases(root: &BoxRoot, record: &Record) {
        use std::os::unix::fs::PermissionsExt as _;

        for alias in root.all_aliases(&record.mcp) {
            std::fs::write(&alias, []).expect("the alias placeholder is written");
            std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o500))
                .expect("the alias placeholder is executable");
        }
    }

    #[cfg(unix)]
    async fn wait_for_file(path: &Path) -> bool {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !path.is_file() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
    }

    #[cfg(unix)]
    use crate::test_support::{HELD_GROUP, SIGNALS, process_exists, processes_exit, wait_for_pids};

    #[cfg(unix)]
    async fn send_mcp_frame(
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        body: crate::run::broker::protocol::Body,
    ) {
        crate::run::broker::protocol::write_frame(
            writer,
            &crate::run::broker::protocol::Frame {
                version: crate::run::broker::protocol::PROTOCOL_VERSION,
                program: 1,
                body,
            },
        )
        .await
        .expect("the MCP transport frame is written");
    }

    #[cfg(unix)]
    async fn send_mcp_json(
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        value: serde_json::Value,
    ) {
        let mut bytes = serde_json::to_vec(&value).expect("the MCP frame serializes");
        bytes.push(b'\n');
        send_mcp_frame(
            writer,
            crate::run::broker::protocol::Body::Input {
                data: crate::run::broker::protocol::encode_payload(&bytes),
            },
        )
        .await;
    }

    #[cfg(unix)]
    async fn initialized_mcp_client(
        root: &BoxRoot,
        program: &str,
    ) -> (
        tokio::net::unix::OwnedReadHalf,
        tokio::net::unix::OwnedWriteHalf,
    ) {
        let stream = tokio::net::UnixStream::connect(root.broker_socket())
            .await
            .expect("the MCP client connects");
        let (mut reader, mut writer) = stream.into_split();
        send_mcp_frame(
            &mut writer,
            crate::run::broker::protocol::Body::Open {
                mode: crate::run::broker::protocol::Interpreter::Mcp {
                    server: program.to_string(),
                },
            },
        )
        .await;
        send_mcp_json(
            &mut writer,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }),
        )
        .await;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::run::broker::protocol::read_frame::<crate::run::broker::protocol::Frame, _>(
                &mut reader,
            ),
        )
        .await
        .expect("the initialize response arrives")
        .expect("the initialize response reads")
        .expect("the initialize response is present");
        assert!(
            matches!(
                response.body,
                crate::run::broker::protocol::Body::Output { .. }
            ),
            "the initialized MCP server must answer through the broker"
        );
        send_mcp_json(
            &mut writer,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }),
        )
        .await;
        (reader, writer)
    }

    #[cfg(unix)]
    async fn connection_closes(reader: &mut tokio::net::unix::OwnedReadHalf) -> bool {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Ok(Some(_)) = crate::run::broker::protocol::read_frame::<
                crate::run::broker::protocol::Frame,
                _,
            >(reader)
            .await
            {}
        })
        .await
        .is_ok()
    }

    #[tokio::test]
    async fn authority_uses_the_box_private_dogwood_database() {
        let operator = tempfile::tempdir().expect("operator home");
        let root = crate::record::layout::testing::box_root(operator.path(), "codex");

        let _authority = HostedBox::open_authority(&root).expect("authority opens");

        assert!(
            root.dogwood_database().is_file(),
            "the authority must create its database below the box private directory"
        );
    }

    /// A raw policy verdict is not the box's canonical decision record.
    #[tokio::test]
    async fn a_raw_policy_refusal_reaches_no_box_telemetry_file() {
        use policy::{ApprovedPath, FsOperation, GovernedBox, PathResolver, Request};

        let operator = tempfile::tempdir().expect("operator home");
        let root = crate::record::layout::testing::box_root(operator.path(), "codex");
        let records = operator.path().join("records.jsonl");

        let collector = Arc::new(
            ::telemetry::open(::telemetry::TelemetryConfig::for_box("codex").with_target(
                ::telemetry::Target::new(::telemetry::TargetKind::File, records.to_string_lossy()),
            ))
            .expect("the collector opens"),
        );
        let authority = HostedBox::open_authority(&root).expect("authority opens");

        let canonical = operator.path().canonicalize().expect("a canonical root");
        let approved: ApprovedPath = PathResolver::over([canonical.clone()])
            .expect("a resolver")
            .approve_host(&canonical.join("secret.txt"))
            .expect("inside the root");
        let decision = authority.decide(
            &GovernedBox::assigned(root.name()),
            &Principal::agent(),
            &Request::Fs {
                path: &approved,
                operation: FsOperation::ReadContent,
            },
        );
        assert!(!decision.is_allow(), "an absent policy denies by default");

        collector.drained().await;

        assert!(
            !records.exists()
                || std::fs::read_to_string(&records)
                    .expect("the telemetry file is readable")
                    .is_empty(),
            "PolicyEngine::decide reports only a raw verdict; a policy enforcement point must \
             submit the final result"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn teardown_wakes_waiters_reaps_processes_and_joins_finalization_before_withdrawal() {
        let operator = tempfile::tempdir().expect("operator home");
        let root = crate::record::layout::testing::box_root(operator.path(), "codex");
        let pids_path = operator.path().join("mcp-pids");
        let lists_path = operator.path().join("mcp-lists");
        let script = r#"trap '' TERM
/bin/sh -c 'trap "" TERM; sleep 3600' &
printf '%s %s\n' "$$" "$!" >> "$1"
while IFS= read -r frame; do
    case "$frame" in
        *'"method":"initialize"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"alpha","version":"1"}}}'
            ;;
        *'"method":"tools/list"'*)
            printf x >> "$2"
            ;;
    esac
done
wait"#;
        let record = record_with_mcp(
            &root,
            vec![
                crate::record::config::mcp::McpServer {
                    name: "alpha".to_string(),
                    command: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        script.to_string(),
                        "alpha-mcp".to_string(),
                        pids_path.to_string_lossy().into_owned(),
                        lists_path.to_string_lossy().into_owned(),
                    ],
                },
                crate::record::config::mcp::McpServer {
                    name: "beta".to_string(),
                    command: vec!["/bin/false".to_string()],
                },
            ],
        );
        let hosted = open_hosted(&operator, &root, &record);
        let registry = hosted
            .discovery
            .as_ref()
            .expect("the discovery host exists")
            .registry();
        let (mut leader_reader, mut leader_writer) = initialized_mcp_client(&root, "/bin/sh").await;
        let (mut follower_reader, mut follower_writer) =
            initialized_mcp_client(&root, "/bin/sh").await;
        let pids = wait_for_pids(&pids_path, 4)
            .await
            .expect("both MCP process groups start");
        let mut unique_pids = pids.clone();
        unique_pids.sort_unstable();
        unique_pids.dedup();
        assert_eq!(
            unique_pids.len(),
            4,
            "two MCP process groups must each report a leader and a descendant"
        );
        send_mcp_json(
            &mut leader_writer,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
        )
        .await;
        assert!(
            wait_for_file(&lists_path).await,
            "the leader must start catalog capture"
        );
        send_mcp_json(
            &mut follower_writer,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let lists_before_teardown = std::fs::read(&lists_path).unwrap_or_default().len();

        let (entered, arrival) = std::sync::mpsc::channel();
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let hook_gate = Arc::clone(&gate);
        registry.set_staging_hook(Arc::new(move |_| {
            let _ = entered.send(());
            let (lock, wake) = &*hook_gate;
            let mut open = lock.lock().expect("staging gate");
            while !*open {
                open = wake.wait(open).expect("generation gate wait");
            }
        }));
        let finalizer_started = registry.testing_stage_catalog("beta", "read").is_ok();
        let finalizer_entered = arrival
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_ok();

        let (dropped, drop_finished) = std::sync::mpsc::channel();
        let drop_thread = std::thread::spawn(move || {
            drop(hosted);
            let _ = dropped.send(());
        });
        let (leader_closed, follower_closed, processes_reaped) = tokio::join!(
            connection_closes(&mut leader_reader),
            connection_closes(&mut follower_reader),
            processes_exit(&pids),
        );
        let drop_waited = drop_finished.try_recv().is_err();
        let live_while_waiting = BoxLive::read(&root).is_some();
        let lock_held_while_waiting = Lock::is_held(&root.lock()).unwrap_or(false);

        let (lock, wake) = &*gate;
        *lock.lock().expect("generation gate") = true;
        wake.notify_all();
        let drop_completed = drop_finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok();
        drop_thread.join().expect("host drop thread");

        assert!(finalizer_started, "the blocked finalizer must start");
        assert!(finalizer_entered, "the finalizer must reach the test gate");
        assert!(drop_waited, "host drop must wait for the finalizer");
        assert_eq!(
            lists_before_teardown, 2,
            "each connection's root list must reach its own server"
        );
        assert!(
            leader_closed && follower_closed,
            "teardown must wake the leader and follower exchanges"
        );
        assert!(
            processes_reaped,
            "teardown must reap both MCP process groups"
        );
        assert!(
            live_while_waiting,
            "live state must remain published after MCP cleanup and while finalization is blocked"
        );
        assert!(
            lock_held_while_waiting,
            "the box lock must remain held after MCP cleanup and while finalization is blocked"
        );
        assert!(drop_completed, "host drop must finish after the finalizer");
        assert!(
            BoxLive::read(&root).is_none(),
            "host drop must withdraw live state"
        );
        assert!(
            !Lock::is_held(&root.lock()).expect("the released lock state reads"),
            "host drop must release the lock last"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fatal_durable_staging_stops_the_supervised_workload_and_withdraws_live_state() {
        let _supervising = SIGNALS.lock().await;
        let operator = tempfile::tempdir().expect("operator home");
        let root = crate::record::layout::testing::box_root(operator.path(), "codex");
        let mut record = record(&root);
        place_aliases(&root, &record);
        let scratch = operator.path().join("scratch");
        std::fs::create_dir(&scratch).expect("a writable scratch tree");
        let scratch = scratch.canonicalize().expect("a canonical scratch tree");
        let workload_pid_path = scratch.join("workload.pid");
        // The agent is a shell script the test controls, run through `[agent] command`.
        let agent = record.agent.as_mut().expect("the record has an agent");
        agent.command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            r#"printf '%s' "$$" > "$1"
trap '' TERM
while :; do :; done"#
                .to_string(),
            "hosted-v47-workload".to_string(),
            workload_pid_path.to_string_lossy().into_owned(),
        ];
        agent.filesystem.write = vec![scratch.clone()];
        let hosted = open_hosted(&operator, &root, &record);
        let registry = hosted
            .discovery
            .as_ref()
            .expect("the discovery host exists")
            .registry();
        let boundary = crate::test_support::with_operator_home(operator.path(), || {
            // The scratch tree stands in for the invocation directory: the operator's home itself is
            // refused as a working directory.
            Boundary::translate(
                record.agent.as_ref().expect("the agent"),
                Launch {
                    table: "[agent]",
                    trailing: &[],
                    fallback_workspace: &scratch,
                    shebang_interpreters: ShebangInterpreters::Granted,
                    runtime_reach: RuntimeReach::Leaf,
                    argument_zero: None,
                    egress: EgressMode::Gateway,
                    approved: None,
                },
                &Site {
                    attachment: hosted.attachment(),
                    layout: &root,
                    stored: &record,
                    protected_sources: &[],
                },
            )
        })
        .expect("the workload boundary translates");
        let contained =
            crate::run::contain::supervise::Contained::testing_spawn_uncontained(boundary, hosted)
                .await
                .expect("the supervised workload starts");
        let workload_pid = wait_for_pids(&workload_pid_path, 1)
            .await
            .expect("the supervised workload writes its process id")[0];
        assert!(
            process_exists(workload_pid),
            "the supervised workload must be live before staging fails"
        );

        registry.testing_fail_next_staging_durably();
        registry
            .testing_stage_catalog("alpha", "read")
            .expect("the finalizer starts");

        let failure = tokio::time::timeout(std::time::Duration::from_secs(10), contained.wait())
            .await
            .expect("the fatal staging failure stops the supervised workload")
            .expect_err("the run must report the durable staging failure");
        assert!(
            failure
                .to_string()
                .contains("policy staging history failure"),
            "{failure}"
        );
        assert!(
            processes_exit(&[workload_pid]).await,
            "the fatal staging failure must reap the supervised workload"
        );
        assert!(
            BoxLive::read(&root).is_none(),
            "fatal teardown must withdraw live state"
        );
        assert!(
            !Lock::is_held(&root.lock()).expect("the released lock state reads"),
            "fatal teardown must release the lock after live-state withdrawal"
        );
    }

    /// A supervised workload run from `script` through `[agent] command`, with `"$1"` naming a
    /// writable file for its pids.
    #[cfg(unix)]
    struct SupervisedWorkload {
        _supervising: tokio::sync::MutexGuard<'static, ()>,
        _operator: tempfile::TempDir,
        contained: crate::run::contain::supervise::Contained,
        pids: Vec<libc::pid_t>,
    }

    #[cfg(unix)]
    async fn supervised_workload(script: &str, pid_count: usize) -> SupervisedWorkload {
        let supervising = SIGNALS.lock().await;
        let operator = tempfile::tempdir().expect("operator home");
        let root = crate::record::layout::testing::box_root(operator.path(), "codex");
        let mut record = record(&root);
        place_aliases(&root, &record);
        let scratch = operator.path().join("scratch");
        std::fs::create_dir(&scratch).expect("a writable scratch tree");
        let scratch = scratch.canonicalize().expect("a canonical scratch tree");
        let pid_path = scratch.join("workload.pids");
        let agent = record.agent.as_mut().expect("the record has an agent");
        agent.command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            script.to_string(),
            "supervised-workload".to_string(),
            pid_path.to_string_lossy().into_owned(),
        ];
        agent.filesystem.write = vec![scratch.clone()];
        let hosted = open_hosted(&operator, &root, &record);
        let boundary = crate::test_support::with_operator_home(operator.path(), || {
            Boundary::translate(
                record.agent.as_ref().expect("the agent"),
                Launch {
                    table: "[agent]",
                    trailing: &[],
                    fallback_workspace: &scratch,
                    shebang_interpreters: ShebangInterpreters::Granted,
                    runtime_reach: RuntimeReach::Leaf,
                    argument_zero: None,
                    egress: EgressMode::Gateway,
                    approved: None,
                },
                &Site {
                    attachment: hosted.attachment(),
                    layout: &root,
                    stored: &record,
                    protected_sources: &[],
                },
            )
        })
        .expect("the workload boundary translates");
        let contained =
            crate::run::contain::supervise::Contained::testing_spawn_uncontained(boundary, hosted)
                .await
                .expect("the supervised workload starts");
        let pids = wait_for_pids(&pid_path, pid_count)
            .await
            .expect("the supervised workload writes its process ids");
        assert!(
            pids.iter().copied().all(process_exists),
            "the workload's processes must be live before the check: {pids:?}"
        );
        SupervisedWorkload {
            _supervising: supervising,
            _operator: operator,
            contained,
            pids,
        }
    }

    /// **A setup failure after spawn ends the whole workload process group.** Every post-spawn
    /// error in `run` leaves through a `?` that drops the `Contained`, and the drop is what ends the
    /// group: the leader and its descendant are both gone once the box has returned.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_setup_failure_after_spawn_ends_the_whole_workload_process_group() {
        let workload = supervised_workload(HELD_GROUP, 2).await;
        let pids = workload.pids.clone();

        drop(workload);

        assert!(
            processes_exit(&pids).await,
            "the leader and its descendant must be gone: {pids:?}"
        );
    }

    /// **A normal exit still ends the descendants the leader left behind.** The leader exits zero
    /// with a `SIGTERM`-ignoring child still running; `wait` reports the leader's own status and the
    /// child is gone when it returns.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_normal_exit_ends_the_descendants_the_leader_left_behind() {
        let workload = supervised_workload(
            r#"trap '' TERM; sleep 3600 & printf '%s %s' "$$" "$!" > "$1"; exit 0"#,
            2,
        )
        .await;
        let pids = workload.pids.clone();

        let code = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            workload.contained.wait(),
        )
        .await
        .expect("the run ends once the leader has exited")
        .expect("the run reports the leader's status");

        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", std::process::ExitCode::SUCCESS)
        );
        assert!(
            processes_exit(&pids).await,
            "the descendant must be gone once the run has returned: {pids:?}"
        );
    }

    /// Raise `signal` at this process once the workload exists and before `wait` is called, and
    /// report the run's outcome with the group's pids. A listener is registered first, so the
    /// process never sees the default action. Each signal can be raised once per process: the box
    /// restores the default disposition after it handles `SIGTERM` or `SIGHUP`.
    #[cfg(unix)]
    async fn box_signalled_after_spawn(
        signal: libc::c_int,
        kind: tokio::signal::unix::SignalKind,
        script: &str,
    ) -> (Result<std::process::ExitCode, BoxError>, Vec<libc::pid_t>) {
        let mut observer = tokio::signal::unix::signal(kind).expect("the test observes the signal");
        let workload = supervised_workload(script, 2).await;
        let pids = workload.pids.clone();

        // SAFETY: signalling this process by its own pid.
        assert_eq!(unsafe { libc::kill(libc::getpid(), signal) }, 0);
        observer.recv().await.expect("the signal is delivered");

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            workload.contained.wait(),
        )
        .await
        .expect("the run ends after the signal");
        (outcome, pids)
    }

    /// **`SIGTERM` to the box ends the workload before the box exits, from the moment the workload
    /// exists.** The signal lands after spawn and before `wait` is called; without a handler armed
    /// at spawn the box would die on the default action and leave the group behind, and a handler
    /// armed only by `wait` would never see this delivery.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_terminate_signal_to_the_box_ends_the_workload_before_the_box_exits() {
        let (outcome, pids) = box_signalled_after_spawn(
            libc::SIGTERM,
            tokio::signal::unix::SignalKind::terminate(),
            HELD_GROUP,
        )
        .await;

        assert!(
            outcome.is_ok(),
            "the run reports the workload's status: {outcome:?}"
        );
        assert!(
            processes_exit(&pids).await,
            "the leader and its descendant must be gone: {pids:?}"
        );
    }

    /// **`SIGHUP` to the box ends the workload the same way.** The run reports the workload's own
    /// death, which `stop` causes with `SIGTERM` and then `SIGKILL`, not the signal the box received.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hangup_signal_to_the_box_ends_the_workload_before_the_box_exits() {
        let (outcome, pids) = box_signalled_after_spawn(
            libc::SIGHUP,
            tokio::signal::unix::SignalKind::hangup(),
            HELD_GROUP,
        )
        .await;

        let code = outcome.expect("the run reports the workload's status");
        assert_eq!(
            format!("{code:?}"),
            format!(
                "{:?}",
                std::process::ExitCode::from(128 + libc::SIGKILL as u8)
            ),
            "a group that ignores SIGTERM dies of SIGKILL"
        );
        assert!(
            processes_exit(&pids).await,
            "the leader and its descendant must be gone: {pids:?}"
        );
    }

    /// **`SIGINT` to the box is forwarded to the workload's group, and the box keeps waiting.** The
    /// leader traps `SIGINT` and exits zero on its own, and the run reports that zero. Its
    /// background child inherits `SIGINT` ignored, as `sh` gives every async command, so the sweep
    /// after the leader's exit is what ends it.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_interrupt_to_the_box_reaches_the_workloads_group() {
        let (outcome, pids) = box_signalled_after_spawn(
            libc::SIGINT,
            tokio::signal::unix::SignalKind::interrupt(),
            r#"trap 'exit 0' INT; sleep 3600 & printf '%s %s' "$$" "$!" > "$1"; wait"#,
        )
        .await;

        let code = outcome.expect("the run reports the workload's status");
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", std::process::ExitCode::SUCCESS),
            "the workload left on its own trap"
        );
        assert!(
            processes_exit(&pids).await,
            "the leader and its descendant must be gone: {pids:?}"
        );
    }

    /// Every arm of a schema install states its outcome, including the arm that stops the box.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fatal_schema_install_records_the_server_it_refused() {
        let operator = tempfile::tempdir().expect("operator home");
        let root = crate::record::layout::testing::box_root(operator.path(), "codex");
        let record = record(&root);
        let (mut hosted, collector) = open_hosted_recording(&operator, &root, &record);
        let registry = hosted
            .discovery
            .as_ref()
            .expect("the discovery host exists")
            .registry();

        registry.testing_fail_next_staging_durably();
        registry
            .testing_stage_catalog("alpha", "read")
            .expect("the finalizer starts");

        let failure = tokio::time::timeout(std::time::Duration::from_secs(10), hosted.stopped())
            .await
            .expect("the fatal staging failure reaches this box");
        assert!(
            failure
                .to_string()
                .contains("policy staging history failure"),
            "{failure}"
        );

        collector.drained().await;
        let control = control_records(&operator.path().join("records.jsonl"));
        assert!(
            control.contains(&(
                "schema_installed".to_string(),
                "refused".to_string(),
                "alpha".to_string()
            )),
            "a fatal staging failure must name the server on the control plane, or an operator \
             cannot attribute the stop to it: {control:?}"
        );
    }

    /// Every control-plane record in `path`, as `(operation, outcome, subject)`.
    #[cfg(unix)]
    fn control_records(path: &Path) -> Vec<(String, String, String)> {
        let text = std::fs::read_to_string(path).expect("the telemetry file is readable");
        let mut found = Vec::new();
        for line in text.lines() {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("each line is one OTLP request");
            for resource in parsed["resourceLogs"].as_array().into_iter().flatten() {
                for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                    if scope["scope"]["name"] != "strands-box.control" {
                        continue;
                    }
                    for entry in scope["logRecords"].as_array().into_iter().flatten() {
                        let read = |key: &str| {
                            entry["attributes"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .find(|attribute| attribute["key"] == key)
                                .and_then(|attribute| attribute["value"]["stringValue"].as_str())
                                .unwrap_or_default()
                                .to_string()
                        };
                        found.push((
                            read("strands.box.control.operation"),
                            read("strands.box.control.outcome"),
                            read("strands.box.control.subject"),
                        ));
                    }
                }
            }
        }
        found
    }

    /// A selection attachment: only its `telemetry_port` reaches tool selection.
    fn selection_attachment() -> Attachment {
        Attachment {
            proxy_port: 41080,
            telemetry_port: 44318,
            trust_bundle: None,
            phantoms: Vec::new(),
        }
    }

    fn selection_record(tools: &[(&str, &[&str])]) -> Record {
        let spec = |command: &[&str]| ProcessSpec {
            command: command.iter().map(|part| (*part).to_string()).collect(),
            workspace: None,
            env: Default::default(),
            filesystem: Default::default(),
            network: None,
        };
        let agent = spec(&["/bin/sh"]);
        Record {
            version: crate::record::config::RECORD_VERSION,
            box_id: "box-0123456789abcdef".to_string(),
            box_dir: PathBuf::from("/var/lib/boxes/probe"),
            name: "probe".to_string(),
            policy: None,
            agent: Some(agent),
            tool: tools
                .iter()
                .map(|(label, command)| ((*label).to_string(), spec(command)))
                .collect(),
            egress: Default::default(),
            remote_mcp: Default::default(),
            mcp: Vec::new(),
            contained_mcp: Default::default(),
            telemetry: Default::default(),
        }
    }

    /// **The longest `command` prefix the invocation matches selects the tool**, and the arguments
    /// after that prefix are the tool's trailing ones.
    #[test]
    fn the_longest_matching_command_prefix_selects_the_tool() {
        let record = selection_record(&[("sh", &["/bin/sh"]), ("sh-c", &["/bin/sh", "-c"])]);

        let sh = Path::new("/bin/sh").canonicalize().expect("sh exists");

        let selected = select_tool(
            &record,
            &selection_attachment(),
            &sh,
            &["-c".to_string(), "printf x".to_string()],
        )
        .expect("the invocation matches two tools");
        assert_eq!(selected.table, "[tool.sh-c]");
        assert_eq!(selected.trailing, ["printf x"]);

        let selected = select_tool(&record, &selection_attachment(), &sh, &["-x".to_string()])
            .expect("the shorter prefix still matches");
        assert_eq!(selected.table, "[tool.sh]");
        assert_eq!(selected.trailing, ["-x"]);
    }

    /// **A `${...}` in a tool's `command` is compared expanded**, so the invocation the operator
    /// intends selects the tool. The translator expands the same argument, so a literal comparison
    /// here would make such a tool unselectable by any real argv.
    #[test]
    fn a_tool_whose_command_holds_a_token_is_selected_by_the_expanded_argument() {
        let record = selection_record(&[(
            "probe",
            &[
                "/bin/sh",
                "--endpoint=${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}",
            ],
        )]);
        let sh = Path::new("/bin/sh").canonicalize().expect("sh exists");
        let attachment = selection_attachment();
        let expanded = format!(
            "--endpoint=http://127.0.0.1:{}/v1/traces",
            attachment.telemetry_port
        );

        let selected = select_tool(&record, &attachment, &sh, &[expanded, "tail".to_string()])
            .expect("the expanded argument matches the tool");
        assert_eq!(selected.table, "[tool.probe]");
        assert_eq!(selected.trailing, ["tail"]);

        let literal = select_tool(
            &record,
            &attachment,
            &sh,
            &["--endpoint=${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}".to_string()],
        );
        assert!(
            literal.is_err(),
            "the unexpanded spelling is not what the tool runs"
        );
    }

    /// **A token no build expands refuses by name**, and a malformed table hides no sibling.
    #[test]
    fn a_tool_command_with_an_unexpandable_token_is_refused_by_name() {
        let record = selection_record(&[("probe", &["/bin/sh", "--endpoint=${NOT_A_CORE_NAME}"])]);
        let sh = Path::new("/bin/sh").canonicalize().expect("sh exists");

        let error = select_tool(&record, &selection_attachment(), &sh, &[])
            .err()
            .expect("an unexpandable token is refused");

        let message = error.to_string();
        assert!(message.contains("[tool.probe]"), "{message}");
        assert!(message.contains("NOT_A_CORE_NAME"), "{message}");
        assert!(
            !message.contains("no `[tool.<name>] command` matches"),
            "the refusal must name the token rather than report a non-match: {message}"
        );

        // A second table whose command expands still selects, so the malformed one is held rather
        // than fatal.
        let both = selection_record(&[
            ("probe", &["/bin/sh", "--endpoint=${NOT_A_CORE_NAME}"]),
            ("plain", &["/bin/sh"]),
        ]);
        let selected = select_tool(&both, &selection_attachment(), &sh, &[])
            .expect("the well-formed table still selects");
        assert_eq!(selected.table, "[tool.plain]");
    }

    /// **Every declared tool is selectable by the agent**: the file declaring a `[tool.<name>]` is
    /// what puts it in the agent's reach, with nothing else to name it.
    #[test]
    fn every_declared_tool_is_selectable_by_the_agent() {
        let record = selection_record(&[("sh", &["/bin/sh"])]);
        let sh = Path::new("/bin/sh").canonicalize().expect("sh exists");

        let selected = select_tool(&record, &selection_attachment(), &sh, &[])
            .expect("a declared tool is selected");

        assert_eq!(selected.table, "[tool.sh]");
    }

    /// **A program under one of the caller's own `exec` entries runs in the caller's boundary** when
    /// no table names it: the caller's spec with the program as its command, the arguments trailing.
    #[cfg(unix)]
    #[test]
    fn a_program_under_the_callers_exec_grant_runs_in_the_callers_boundary() {
        let root = tempfile::tempdir().expect("a directory");
        let target = root.path().join("target/debug");
        std::fs::create_dir_all(&target).expect("a target tree");
        let demo = target.join("demo");
        std::fs::copy(Path::new("/bin/sh").canonicalize().expect("sh"), &demo)
            .expect("a built binary");
        let demo = demo.canonicalize().expect("canonical");
        let mut record = selection_record(&[("sh", &["/bin/sh"])]);
        let agent = record.agent.as_mut().expect("an agent");
        agent.filesystem.exec = vec![root.path().join("target")];
        agent.filesystem.write = vec![root.path().to_path_buf()];
        let expected = agent.filesystem.clone();

        let selected = select_tool(
            &record,
            &selection_attachment(),
            &demo,
            &["--flag".to_string()],
        )
        .expect("the caller runs its own build output");

        assert_eq!(selected.table, "[agent]");
        assert_eq!(selected.spec.command, vec![demo.display().to_string()]);
        assert_eq!(selected.trailing, ["--flag"]);
        assert_eq!(selected.spec.filesystem, expected);
        assert_eq!(selected.spec.network, None);
    }

    /// **A program run under an `exec` grant stays on the gateway**, whatever the caller's spec
    /// holds, because the fallback takes no `network` from it.
    #[cfg(unix)]
    #[test]
    fn a_program_under_an_exec_grant_never_takes_native_egress() {
        let root = tempfile::tempdir().expect("a directory");
        let target = root.path().join("target/debug");
        std::fs::create_dir_all(&target).expect("a target tree");
        let demo = target.join("demo");
        std::fs::copy(Path::new("/bin/sh").canonicalize().expect("sh"), &demo)
            .expect("a built binary");
        let demo = demo.canonicalize().expect("canonical");
        let mut record = selection_record(&[("sh", &["/bin/sh"])]);
        let agent = record.agent.as_mut().expect("an agent");
        agent.filesystem.exec = vec![root.path().join("target")];
        agent.network = Some(crate::record::config::process::NetworkConfig {
            contain_egress: false,
        });

        let selected = select_tool(&record, &selection_attachment(), &demo, &[])
            .expect("the caller runs its own build output");

        assert_eq!(selected.table, "[agent]");
        assert_eq!(
            EgressMode::for_spec(&selected.spec),
            EgressMode::Gateway,
            "an exec-grant program takes the gateway"
        );
    }

    /// **A native tool's `egress:native` record precedes its run**, so a call the agent cancels or
    /// outlasts still leaves the record.
    #[test]
    fn a_native_tool_records_egress_native_before_it_runs() {
        let src = include_str!("hosted.rs");
        let spawner = src
            .split_once("fn tool_spawner(")
            .expect("hosted.rs defines tool_spawner")
            .1;
        let spawner = spawner
            .split_once("\nfn ")
            .map_or(spawner, |(body, _)| body);
        let record = spawner
            .find("\"egress:native\"")
            .expect("tool_spawner records egress:native");
        let run = spawner
            .find("LeafBox::run(")
            .expect("tool_spawner runs the leaf");
        assert!(
            record < run,
            "the egress:native record must precede LeafBox::run"
        );
    }

    /// **A program some table names never falls back to the caller**: an argument prefix that no
    /// table matches is refused, even under a caller `exec` entry.
    #[cfg(unix)]
    #[test]
    fn a_program_a_table_names_never_falls_back_to_the_caller() {
        let root = tempfile::tempdir().expect("a directory");
        let tools = root.path().join("tools");
        std::fs::create_dir_all(&tools).expect("a tools tree");
        let sh = tools.join("sh");
        std::fs::copy(Path::new("/bin/sh").canonicalize().expect("sh"), &sh).expect("a binary");
        let sh = sh.canonicalize().expect("canonical");
        let spelled = sh.display().to_string();
        let mut record = selection_record(&[("sh-c", &[spelled.as_str(), "-c"])]);
        record.agent.as_mut().expect("an agent").filesystem.exec = vec![tools.clone()];

        let error = select_tool(&record, &selection_attachment(), &sh, &["-x".to_string()])
            .err()
            .expect("a prefix no table matches is refused, not run as the caller");

        assert!(
            error
                .to_string()
                .contains("no `[tool.<name>] command` matches this program"),
            "{error}"
        );
    }

    /// **A program under a caller `deny` entry is refused** even inside a caller `exec` entry.
    #[cfg(unix)]
    #[test]
    fn a_denied_program_under_an_exec_entry_is_refused() {
        let root = tempfile::tempdir().expect("a directory");
        let target = root.path().join("target/debug");
        std::fs::create_dir_all(&target).expect("a target tree");
        let demo = target.join("demo");
        std::fs::copy(Path::new("/bin/sh").canonicalize().expect("sh"), &demo).expect("a binary");
        let demo = demo.canonicalize().expect("canonical");
        let mut record = selection_record(&[("sh", &["/bin/sh"])]);
        let agent = record.agent.as_mut().expect("an agent");
        agent.filesystem.exec = vec![root.path().join("target")];
        agent.filesystem.deny = vec![root.path().join("target/debug")];

        assert!(
            select_tool(&record, &selection_attachment(), &demo, &[]).is_err(),
            "a denied program must not run"
        );
    }

    /// **A `deny` entry this run cannot resolve refuses the program**, and an entry that names no
    /// file covers nothing.
    #[cfg(unix)]
    #[test]
    fn an_unresolvable_deny_entry_refuses_and_an_absent_one_does_not() {
        let root = tempfile::tempdir().expect("a directory");
        let target = root.path().join("target/debug");
        std::fs::create_dir_all(&target).expect("a target tree");
        let demo = target.join("demo");
        std::fs::copy(Path::new("/bin/sh").canonicalize().expect("sh"), &demo).expect("a binary");
        let demo = demo.canonicalize().expect("canonical");
        let barrier = root.path().join("barrier");
        std::fs::write(&barrier, b"not a directory").expect("a regular file");
        let mut record = selection_record(&[("sh", &["/bin/sh"])]);
        let agent = record.agent.as_mut().expect("an agent");
        agent.filesystem.exec = vec![root.path().join("target")];
        agent.filesystem.deny = vec![root.path().join("absent")];

        assert!(
            select_tool(&record, &selection_attachment(), &demo, &[]).is_ok(),
            "a `deny` entry that names no file covers nothing"
        );

        record
            .agent
            .as_mut()
            .expect("an agent")
            .filesystem
            .deny
            .push(barrier.join("under"));

        assert!(
            select_tool(&record, &selection_attachment(), &demo, &[]).is_err(),
            "a `deny` entry this run cannot resolve must refuse the program"
        );
    }

    /// **A program outside every caller `exec` entry is still refused** when no table names it.
    #[cfg(unix)]
    #[test]
    fn a_program_outside_every_exec_grant_is_still_refused() {
        let root = tempfile::tempdir().expect("a directory");
        std::fs::create_dir_all(root.path().join("target")).expect("a target tree");
        let elsewhere = root.path().join("elsewhere");
        std::fs::copy(Path::new("/bin/sh").canonicalize().expect("sh"), &elsewhere)
            .expect("a binary");
        let mut record = selection_record(&[("sh", &["/bin/sh"])]);
        record.agent.as_mut().expect("an agent").filesystem.exec = vec![root.path().join("target")];

        let error = select_tool(
            &record,
            &selection_attachment(),
            &elsewhere.canonicalize().expect("canonical"),
            &[],
        )
        .err()
        .expect("a program outside the exec entries is refused");

        assert!(
            error
                .to_string()
                .contains("no `[tool.<name>] command` matches this program"),
            "{error}"
        );
    }

    /// **The credential map is keyed by the identity the decision names**: a tool declared through a
    /// symbolic link is keyed by the file it resolves to, which is what the Shell canonicalizes a
    /// spelling or a bare name to.
    #[cfg(unix)]
    #[test]
    fn tool_credential_paths_are_keyed_by_the_programs_canonical_identity() {
        let elsewhere = tempfile::tempdir().expect("a directory");
        let link = elsewhere.path().join("aws-link");
        let target = Path::new("/bin/sh").canonicalize().expect("sh exists");
        std::os::unix::fs::symlink(&target, &link).expect("a link to the program");
        let spelled = link.display().to_string();
        let mut record = selection_record(&[("aws", &[spelled.as_str()])]);
        record
            .tool
            .get_mut("aws")
            .expect("the tool")
            .filesystem
            .read = vec![PathBuf::from("~/.aws")];

        let paths = crate::test_support::with_operator_home(elsewhere.path(), || {
            record.tool_credential_paths()
        });

        assert_eq!(
            paths.get(&target.display().to_string()),
            Some(&vec!["~/.aws".to_string()]),
            "{paths:?}"
        );
        assert!(
            !paths.contains_key("aws-link") && !paths.contains_key("aws"),
            "{paths:?}"
        );
    }

    /// **A tool starts in the caller's directory only inside its own reach**: the agent's workspace
    /// or a tree its lists name; anywhere else falls back to the agent's workspace.
    #[test]
    fn a_callers_directory_is_accepted_only_inside_the_tools_reach() {
        let root = tempfile::tempdir().expect("a directory");
        let root_path = root.path().canonicalize().expect("canonical");
        for relative in ["workspace/src", "vendor/sdk", "elsewhere"] {
            std::fs::create_dir_all(root_path.join(relative)).expect("a directory");
        }
        let workspace = root_path.join("workspace");
        let mut tool = ProcessSpec {
            command: vec!["/bin/sh".to_string()],
            workspace: None,
            env: Default::default(),
            filesystem: Default::default(),
            network: None,
        };
        tool.filesystem.read = vec![root_path.join("vendor")];

        assert_eq!(
            caller_directory(&workspace.join("src"), &tool, &workspace),
            workspace.join("src"),
            "inside the agent's workspace"
        );
        assert_eq!(
            caller_directory(&root_path.join("vendor/sdk"), &tool, &workspace),
            root_path.join("vendor/sdk"),
            "inside a tree the tool lists"
        );
        assert_eq!(
            caller_directory(&root_path.join("elsewhere"), &tool, &workspace),
            workspace,
            "a directory outside every root falls back"
        );
        assert_eq!(
            caller_directory(&root_path.join("absent"), &tool, &workspace),
            workspace,
            "a directory that does not resolve falls back"
        );
    }

    /// **Selection is by the identity the decision named, compared as given**: a same-named binary
    /// elsewhere, a link to the tool that the decision did not resolve, and a program no `command`
    /// names are all refused.
    #[cfg(unix)]
    #[test]
    fn selection_is_by_resolved_path_and_a_stranger_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let record = selection_record(&[("sh", &["/bin/sh"])]);
        let elsewhere = tempfile::tempdir().expect("a directory");
        let impostor = elsewhere.path().join("sh");
        std::fs::write(&impostor, "#!/bin/sh\n").expect("a same-named program");
        std::fs::set_permissions(&impostor, std::fs::Permissions::from_mode(0o755))
            .expect("it is executable");
        let link = elsewhere.path().join("link-to-sh");
        std::os::unix::fs::symlink(Path::new("/bin/sh").canonicalize().expect("sh"), &link)
            .expect("a link to the tool");

        for program in [impostor.as_path(), link.as_path(), Path::new("/bin/true")] {
            let error = select_tool(&record, &selection_attachment(), program, &[])
                .err()
                .unwrap_or_else(|| panic!("{} must not select a tool", program.display()));
            assert!(
                error
                    .to_string()
                    .contains("no `[tool.<name>] command` matches this program"),
                "{error}"
            );
        }
    }
}
