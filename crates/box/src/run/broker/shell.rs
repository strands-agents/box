//! The Shell interpreter: how one is built, and the confinement it is refused without.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use policy::{GovernedBox, PolicyEngine, Principal, ShellPolicyInterceptor};
use strands_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, EffectResult, FsOperation, Shell,
};

use crate::run::broker::invalid_input;
use crate::run::broker::mcp::DiscoveryRegistry;
use crate::run::broker::protocol::MAX_CAPTURE_STREAM_BYTES;
use crate::run::broker::reach::{Reach, Refused};
use crate::run::contain::boundary::environment::WORKLOAD_USER;
use crate::run::telemetry::{DecisionRecorder, EffectiveDecision, ObservationCapture};

/// The Shell's own wall-clock bound on a single command. Must stay under the transport's
/// `SERVE_REQUEST_TIMEOUT`, which a `const` assert there enforces.
pub(super) const SHELL_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// The most command text the broker will accept into the Shell.
const SHELL_MAX_INPUT: usize = 256 * 1024;
const SHELL_MAX_FILE_SIZE: usize = 10 * 1024 * 1024;
const SHELL_MAX_INODES: usize = 10_000;

/// How the hosted Shell reaches the network: through this box's own egress gateway.
///
/// `HostedBox::open` supplies one, sourced from the box's `MitmHandle`. The Shell dials the
/// proxy rather than an origin directly, so its outbound HTTP meets the same `net:connect`
/// and `http:request` policy the workload's traffic does — one authority, not a second path
/// around the gateway (docs/design/decisions.md#shell-network-goes-through-the-egress-gateway).
/// `None` keeps the Shell's network off, which is the broker-test default and the fail-closed
/// posture when the box has no intercept CA.
#[derive(Clone)]
pub(crate) struct EgressRouting {
    /// The gateway's proxy URL, `http://127.0.0.1:{port}` on the box's TCP loopback transport.
    pub(crate) proxy_target: String,
    /// The gateway's intercept CA certificate, read from the opened Box identity.
    pub(crate) ca_pem: Arc<Vec<u8>>,
}

/// Everything needed to build the hosted Shell, kept so one can be rebuilt.
pub(super) struct ShellSpec {
    /// The Shell's own bound on one command.
    pub(super) command_timeout: Duration,
    /// The broker's backstop deadline on one Call, distinct from `command_timeout`. The Shell's own
    /// timeout normally fires first (and reports an `Exit`); this catches a Call that outlives it
    /// and answers `DeniedKind::Timeout`.
    pub(super) request_timeout: Duration,
    /// What both interpreters may name, and the one resolver over it.
    pub(super) reach: Arc<Reach>,
    /// The box's one authority, shared rather than opened here.
    pub(super) policy: Arc<PolicyEngine>,
    /// The box every request on this socket is judged as.
    pub(super) governed: GovernedBox,

    /// Credential path spellings keyed by the host binary that receives them.
    pub(super) spawn_credentials: BTreeMap<String, Vec<String>>,

    /// The MCP servers this box declared, from its stored record.
    pub(super) mcp: Arc<Vec<crate::record::config::mcp::McpServer>>,

    /// Lazy discovery state shared by every MCP connection in this run.
    pub(super) mcp_registry: Arc<DiscoveryRegistry>,

    /// Where a local MCP server is started: `private/mcp`, which the workload cannot write.
    pub(super) mcp_working_directory: std::path::PathBuf,

    /// The validated identity of the local MCP working directory.
    pub(super) mcp_working_directory_handle: Option<Arc<std::fs::File>>,

    /// Starts a stdio server as a contained streaming leaf; `None` only when the box declares no
    /// stdio server (every stdio server is contained).
    pub(super) mcp_leaf_launcher: Option<Arc<crate::run::hosted::McpLeafLauncher>>,

    /// How the Shell reaches the network. `Some` routes outbound HTTP through this box's egress
    /// gateway; `None` leaves the network off.
    pub(super) egress: Option<EgressRouting>,

    /// Where final policy enforcement point decisions are submitted.
    pub(super) recorder: Arc<crate::run::telemetry::DecisionRecorder>,

    /// The hook that runs a host binary in a contained leaf box. `None` leaves the
    /// vendored crate's built-in spawn, which the box never wants; the box always installs it.
    pub(super) host_spawner: Option<strands_shell::os::HostSpawner>,
}

impl ShellSpec {
    /// Build a Shell confined exactly as the host requires.
    pub(super) fn build(&self) -> io::Result<Shell> {
        self.build_on(self.backend()?, &self.recorder)
    }

    pub(super) fn backend(&self) -> io::Result<Arc<dyn strands_shell::os::Kernel>> {
        use strands_shell::vfs_config::{BindEntry, BindMode, VfsConfig, build_vfs};
        use strands_shell::vfs_kernel::{EgressProxy, VfsKernel};

        let config = VfsConfig {
            bind: self
                .reach
                .shell_binds()
                .into_iter()
                .map(|(source, destination)| BindEntry {
                    mode: BindMode::Direct,
                    source: source.to_string(),
                    destination: destination.to_string(),
                    readonly: false,
                })
                .collect(),
            ..VfsConfig::default()
        };
        let mut vfs = build_vfs(&config)?;
        vfs.max_file_size = SHELL_MAX_FILE_SIZE;
        vfs.max_inodes = SHELL_MAX_INODES;
        let mut backend = VfsKernel::new(vfs);
        backend.network_enabled = self.egress.is_some();
        backend.egress_proxy = self.egress.as_ref().map(|egress| EgressProxy {
            target: egress.proxy_target.clone(),
            ca_pem: egress.ca_pem.as_ref().clone(),
            // A refusal the gateway originates must reach a command as a refusal, not as the
            // origin's answer.
            refusal_header: Some(egress_gateway::PROXY_ORIGIN_HEADER.to_string()),
        });
        backend.script_interpreter = Some(self.script_interpreter());
        backend.host_spawner = self.host_spawner.clone();
        Ok(Arc::new(backend))
    }

    pub(super) fn build_on(
        &self,
        backend: Arc<dyn strands_shell::os::Kernel>,
        recorder: &Arc<DecisionRecorder>,
    ) -> io::Result<Shell> {
        // Two interceptors, one above the other. PolicyEngine decides first; the reachable set is a
        // deny-only floor **beneath** it, so no `permit` can open a path outside the agent's home
        let interceptor = ReachFloor::over(
            Arc::clone(&self.reach),
            Arc::clone(recorder),
            // **Reporting under the operator home, so a rule reads `~/<relative>`.** A policy is
            // checked into the operator's repository and has to hold in every clone; a host path
            match self.reach.reported_home() {
                Some(home) => {
                    ShellPolicyInterceptor::into_handle_reporting_under_with_spawn_credentials(
                        Arc::clone(&self.policy),
                        Principal::agent(),
                        self.governed.clone(),
                        home,
                        self.spawn_credentials.clone(),
                    )
                }
                None => ShellPolicyInterceptor::into_handle_with_spawn_credentials(
                    Arc::clone(&self.policy),
                    Principal::agent(),
                    self.governed.clone(),
                    self.spawn_credentials.clone(),
                ),
            },
        );
        // One bind per reachable root, each writable and passed through, so **policy decides a
        // write rather than the mount deciding first**.
        let binds = self.reach.shell_binds();
        let mut builder = Shell::builder();
        for (source, destination) in &binds {
            builder = builder.bind_direct(*source, *destination);
        }
        let builder = builder
            .effect_interceptor(interceptor)
            .max_input(SHELL_MAX_INPUT)
            .max_output(MAX_CAPTURE_STREAM_BYTES)
            .max_file_size(SHELL_MAX_FILE_SIZE)
            .max_inodes(SHELL_MAX_INODES)
            .timeout(self.command_timeout);
        // Route outbound HTTP through this box's egress gateway, so a Shell `curl` meets the
        // same `net:connect`/`http:request` policy the workload's own traffic does.
        // With no gateway the network stays off — a fail-closed refusal, never a direct dial
        // around the only governed route the box has.
        let builder = match &self.egress {
            Some(egress) => builder
                // Named before the proxy, which reads it: a refusal the gateway originates must
                // reach a command as a refusal, not as the origin's answer.
                .egress_refusal_header(egress_gateway::PROXY_ORIGIN_HEADER)
                .egress_proxy_pem(egress.proxy_target.clone(), egress.ca_pem.as_ref().clone())?,
            None => builder.disable_network(),
        };
        let mut shell = builder
            .kernel(Arc::new(super::kernel::CallKernel::new(
                backend,
                recorder.request_context(),
            )))
            .build()?;
        verify_direct_binds(&shell, &binds)?;
        shell.proc.cwd = PathBuf::from(self.reach.working_directory());
        shell.set_env("PWD", self.reach.working_directory());
        shell.set_env("HOME", self.reach.home_variable());
        shell.set_env("USER", WORKLOAD_USER);
        Ok(shell)
    }

    fn script_interpreter(&self) -> strands_shell::os::ScriptInterpreter {
        let reach = Arc::clone(&self.reach);
        let policy = Arc::clone(&self.policy);
        let governed = self.governed.clone();
        let recorder = Arc::clone(&self.recorder);
        let egress = self.egress.clone();
        std::sync::Arc::new(move |source: String| {
            let reach = Arc::clone(&reach);
            let policy = Arc::clone(&policy);
            let governed = governed.clone();
            let egress = egress.clone();
            let recorder = Arc::clone(&recorder);
            Box::pin(async move {
                let outcome = crate::run::broker::python::drive_monty(
                    source,
                    crate::run::broker::python::PYTHON_ORIGIN.to_string(),
                    &reach,
                    &policy,
                    &governed,
                    egress.as_ref(),
                    &recorder,
                )
                .await;
                Ok::<_, std::io::Error>(strands_shell::os::ScriptOutcome {
                    status: outcome.status,
                    stdout: outcome.stdout,
                    stderr: outcome.stderr,
                })
            })
        })
    }
}

/// The bind mode the box requires, as the vendored crate spells it in a `BindInfo`.
const REQUIRED_BIND_MODE: &str = "direct";

/// Refuse a Shell whose binds are not exactly the declared set, all host pass-throughs.
fn verify_direct_binds(shell: &Shell, declared: &[(&str, &str)]) -> io::Result<()> {
    let binds = &shell.config().binds;
    if binds.len() != declared.len() {
        return Err(invalid_input(format!(
            "the hosted Shell must have {} direct binds; found {}",
            declared.len(),
            binds.len(),
        )));
    }
    for (built, (source, destination)) in binds.iter().zip(declared) {
        if built.source != *source || built.destination != *destination {
            return Err(invalid_input(format!(
                "the hosted Shell binds {} at {}; the box declared {source} at {destination}",
                built.source, built.destination
            )));
        }
        if built.mode != REQUIRED_BIND_MODE {
            return Err(invalid_input(format!(
                "the hosted Shell's bind of {} at {} is mode {:?}; the box requires {:?}",
                built.source, built.destination, built.mode, REQUIRED_BIND_MODE
            )));
        }
    }
    Ok(())
}

/// The reachable set, as a deny-only floor over the Shell's own admission seam.
struct ReachFloor {
    reach: Arc<Reach>,
    inner: Arc<dyn EffectInterceptor>,
    recorder: Arc<DecisionRecorder>,
}

impl ReachFloor {
    fn over(
        reach: Arc<Reach>,
        recorder: Arc<DecisionRecorder>,
        inner: Arc<dyn EffectInterceptor>,
    ) -> Arc<dyn EffectInterceptor> {
        Arc::new(Self {
            reach,
            inner,
            recorder,
        })
    }

    /// Approve every host-backed path this effect touches.
    fn approve(&self, effect: &EffectAttempt<'_>) -> Result<(), Refused> {
        match effect {
            // No path, so nothing for this floor to confine. What a command *does* arrives
            // here again as one filesystem attempt per effect.
            EffectAttempt::ShellRun { .. } | EffectAttempt::ShellSpawn { .. } => Ok(()),
            EffectAttempt::Filesystem { path, operation } => {
                self.approve_one(path, mutates(*operation))
            }
            EffectAttempt::FilesystemPair {
                from,
                to,
                operation,
            } => match operation {
                strands_shell::FsPairOperation::Rename { .. } => self
                    .approve_one(from, true)
                    .and_then(|()| self.approve_one(to, true)),
                strands_shell::FsPairOperation::Symlink => self
                    .approve_one(from, false)
                    .and_then(|()| self.approve_one(to, true)),
                _ => self
                    .approve_one(from, true)
                    .and_then(|()| self.approve_one(to, true)),
            },
            // An attempt this box does not map never reaches here: the policy adapter
            // beneath refuses it with `PermissionDenied` before the floor is asked.
            _ => Ok(()),
        }
    }

    /// Approve one path, or pass a name the host does not back.
    fn approve_one(&self, named: &str, mutates: bool) -> Result<(), Refused> {
        let named = Path::new(named);
        if !self.reach.names_a_host_path(named) {
            return Ok(());
        }
        let approved = if mutates {
            self.reach.approve_mutation(named, &named.to_string_lossy())
        } else {
            self.reach.approve(named, &named.to_string_lossy())
        };
        approved.map(|_approved| ())
    }
}

fn mutates(operation: FsOperation) -> bool {
    match operation {
        FsOperation::WriteContent { .. }
        | FsOperation::CreateDir
        | FsOperation::RemoveFile
        | FsOperation::RemoveDir
        | FsOperation::SetPermissions { .. } => true,
        FsOperation::ReadContent
        | FsOperation::ReadMetadata { .. }
        | FsOperation::Enumerate
        | FsOperation::ChangeDir
        | FsOperation::Exec
        | FsOperation::Locate
        | FsOperation::ReadLink => false,
        _ => true,
    }
}

struct DecisionSubject {
    action: &'static str,
    resource: String,
    /// What the decision was about, under the standard names. `None` where the resource says it all.
    reported: Option<telemetry::Subject>,
}

fn decision_subject(effect: &EffectAttempt<'_>, home: Option<&Path>) -> Option<DecisionSubject> {
    match effect {
        EffectAttempt::ShellRun {
            program,
            args,
            literal,
            cwd,
            ..
        } => Some(DecisionSubject {
            action: r#"Box::Action::"shell:exec""#,
            resource: (*program).to_string(),
            reported: Some(telemetry::Subject::process(program, args, literal, cwd)),
        }),
        EffectAttempt::ShellSpawn {
            program_path,
            args,
            literal,
            cwd,
            ..
        } => Some(DecisionSubject {
            action: r#"Box::Action::"shell:spawn""#,
            resource: reported_path(program_path, home),
            reported: Some(telemetry::Subject::process(
                &reported_path(program_path, home),
                args,
                literal,
                cwd,
            )),
        }),
        // A `Locate` is a capability check, so it is no decision to record.
        EffectAttempt::Filesystem {
            operation: FsOperation::Locate,
            ..
        } => None,
        EffectAttempt::Filesystem { path, operation } => Some(DecisionSubject {
            action: fs_action(*operation),
            resource: reported_path(path, home),
            reported: None,
        }),
        EffectAttempt::FilesystemPair { to, operation, .. } => Some(DecisionSubject {
            action: match operation {
                strands_shell::FsPairOperation::Rename { .. } => r#"Box::Action::"fs:move""#,
                strands_shell::FsPairOperation::Symlink => r#"Box::Action::"fs:write""#,
                _ => r#"Box::Action::"fs:other""#,
            },
            resource: reported_path(to, home),
            reported: None,
        }),
        _ => None,
    }
}

fn fs_action(operation: FsOperation) -> &'static str {
    match operation {
        FsOperation::ReadContent
        | FsOperation::ReadMetadata { .. }
        | FsOperation::Enumerate
        | FsOperation::ReadLink
        | FsOperation::ChangeDir
        | FsOperation::Exec => r#"Box::Action::"fs:read""#,
        FsOperation::WriteContent { .. }
        | FsOperation::CreateDir
        | FsOperation::SetPermissions { .. } => r#"Box::Action::"fs:write""#,
        FsOperation::RemoveFile | FsOperation::RemoveDir => r#"Box::Action::"fs:delete""#,
        _ => r#"Box::Action::"fs:other""#,
    }
}

fn reported_path(path: &str, home: Option<&Path>) -> String {
    let Some(home) = home else {
        return path.to_string();
    };
    match Path::new(path).strip_prefix(home) {
        Ok(relative) if relative.as_os_str().is_empty() => "~".to_string(),
        Ok(relative) => format!("~/{}", relative.display()),
        Err(_) => path.to_string(),
    }
}

impl EffectInterceptor for ReachFloor {
    /// Hand-written rather than `#[async_trait]`, which the box does not depend on.
    fn intercept<'this, 'effect, 'attempt, 'future>(
        &'this self,
        effect: &'effect EffectAttempt<'attempt>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn EffectPermit>>> + Send + 'future>>
    where
        'this: 'future,
        'effect: 'future,
        'attempt: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            let subject =
                decision_subject(effect, self.reach.reported_home().map(std::path::Path::new));
            // PolicyEngine first, always. The floor cannot widen what policy refused, and asking
            // it first would let an unreachable path skip the decision — so a rule counting
            let capture = ObservationCapture::begin();
            let intercepted = self.inner.intercept(effect).await;
            let determined = capture.last();
            let permit = match intercepted {
                Ok(permit) => permit,
                Err(error) => {
                    if let Some(subject) = subject {
                        self.recorder.record(
                            EffectiveDecision::gate_deny(
                                subject.action,
                                subject.resource,
                                "shell-policy",
                                error.to_string(),
                                determined.as_ref(),
                            )
                            .about(subject.reported),
                        );
                    }
                    return Err(error);
                }
            };
            match self.approve(effect) {
                Ok(()) => {
                    if let Some(subject) = subject {
                        self.recorder.record(
                            EffectiveDecision::gate_permit(
                                subject.action,
                                subject.resource,
                                "shell-policy",
                                determined.as_ref(),
                            )
                            .about(subject.reported),
                        );
                    }
                    Ok(permit)
                }
                Err(refused) => {
                    if let Some(subject) = subject {
                        self.recorder.record(
                            EffectiveDecision::enforcement_deny(
                                subject.action,
                                subject.resource,
                                "reach-floor",
                                refused.to_string(),
                            )
                            .about(subject.reported),
                        );
                    }
                    // The attempt happened and did not, so it is recorded as failed rather
                    // than dropped: a rule counting attempts must still see it. A recording
                    let _ = permit
                        .record_outcome(EffectOutcome::Kernel(EffectResult::Failed(
                            io::ErrorKind::PermissionDenied,
                        )))
                        .await;
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        refused.to_string(),
                    ))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use policy::Policy;

    use crate::record::config::AuthoritySource;
    use crate::run::telemetry::{EffectiveRule, EffectiveVerdict, PolicyDecisionObserver};
    use crate::test_support::open_policy;

    /// **The box's label table agrees with the policy adapter on every kernel verb listed here,
    /// no listed verb reaches `fs:other`, and `Locate` is no decision on either side.** The policy
    /// crate's `tests/shell_fs_vocabulary.rs` pins the same lists against the vendored source.
    #[tokio::test]
    async fn every_kernel_verb_labels_the_action_the_policy_adapter_decides() {
        const FS_OTHER: &str = r#"Box::Action::"fs:other""#;
        const FS_READ: &str = r#"Box::Action::"fs:read""#;
        let policy = Arc::new(
            open_policy(vec![Policy {
                origin: std::path::PathBuf::from("<test>"),
                text: "permit(principal, action, resource);".to_string(),
            }])
            .observed_by(Arc::new(PolicyDecisionObserver)),
        );
        let adapter = ShellPolicyInterceptor::into_handle(
            policy,
            Principal::agent(),
            GovernedBox::assigned("codex"),
        );

        for operation in [
            FsOperation::ReadContent,
            FsOperation::WriteContent {
                create: true,
                truncate: true,
            },
            FsOperation::ReadMetadata {
                follow_symlinks: true,
            },
            FsOperation::Enumerate,
            FsOperation::Exec,
            FsOperation::RemoveFile,
            FsOperation::RemoveDir,
            FsOperation::CreateDir,
            FsOperation::SetPermissions { mode: 0o644 },
            FsOperation::ChangeDir,
            FsOperation::ReadLink,
        ] {
            let effect = EffectAttempt::Filesystem {
                path: "/home/strands-box/a.txt",
                operation,
            };
            let capture = ObservationCapture::begin();
            drop(
                adapter
                    .intercept(&effect)
                    .await
                    .expect("the catch-all permit admits every verb"),
            );
            let decided = capture.last().expect("the adapter decided");
            assert_ne!(
                decided.action(),
                FS_OTHER,
                "{operation:?} has a named action"
            );
            assert_eq!(fs_action(operation), decided.action(), "{operation:?}");
            assert_eq!(
                decision_subject(&effect, None)
                    .expect("a filesystem effect has a subject")
                    .action,
                decided.action(),
                "{operation:?}"
            );
            assert_eq!(
                mutates(operation),
                decided.action() != FS_READ,
                "{operation:?} mutates exactly when it does not ride fs:read"
            );
        }

        let locate = EffectAttempt::Filesystem {
            path: "/home/strands-box/a.txt",
            operation: FsOperation::Locate,
        };
        let capture = ObservationCapture::begin();
        drop(
            adapter
                .intercept(&locate)
                .await
                .expect("the catch-all permit admits a Locate"),
        );
        assert!(
            capture.last().is_none(),
            "a Locate decides nothing in the adapter"
        );
        assert!(
            decision_subject(&locate, None).is_none(),
            "a Locate has no decision subject in the box"
        );
        assert!(!mutates(FsOperation::Locate), "a Locate mutates nothing");

        for operation in [
            strands_shell::FsPairOperation::Rename {
                destination_exists: false,
                destination_is_dir: false,
            },
            strands_shell::FsPairOperation::Rename {
                destination_exists: true,
                destination_is_dir: false,
            },
            strands_shell::FsPairOperation::Rename {
                destination_exists: true,
                destination_is_dir: true,
            },
            strands_shell::FsPairOperation::Symlink,
        ] {
            let effect = EffectAttempt::FilesystemPair {
                from: "/home/strands-box/a.txt",
                to: "/home/strands-box/b.txt",
                operation,
            };
            let capture = ObservationCapture::begin();
            drop(
                adapter
                    .intercept(&effect)
                    .await
                    .expect("the catch-all permit admits every pair verb"),
            );
            let decided = capture.last().expect("the adapter decided the target leg");
            assert_ne!(
                decided.action(),
                FS_OTHER,
                "{operation:?} has a named action"
            );
            assert_eq!(
                decision_subject(&effect, None)
                    .expect("a pair effect has a subject")
                    .action,
                decided.action(),
                "{operation:?}"
            );
        }
    }

    /// An agent home and one bind, both real directories, with a Shell-shaped `Reach` over them.
    fn fixture() -> (tempfile::TempDir, Arc<Reach>) {
        let root = tempfile::tempdir().expect("a fixture root");
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::create_dir(resolved.join("home")).expect("the agent's home");
        std::fs::create_dir(resolved.join("my-service")).expect("the workspace");
        let reach =
            Reach::over(&resolved.join("home"), None, None).expect("the reachable set is usable");
        (root, Arc::new(reach))
    }

    /// A floor over that fixture. The inner interceptor is never consulted by `approve`.
    fn floor(reach: Arc<Reach>) -> ReachFloor {
        let policy = Arc::new(open_policy(Vec::<Policy>::new()));
        ReachFloor {
            reach,
            inner: ShellPolicyInterceptor::into_handle(
                policy,
                Principal::agent(),
                GovernedBox::assigned("codex"),
            ),
            recorder: DecisionRecorder::discarding(),
        }
    }

    /// A floor over `text`, observed, with the recorder its decisions reach.
    fn recording_floor(reach: Arc<Reach>, text: &str) -> (ReachFloor, Arc<DecisionRecorder>) {
        let policy = Arc::new(
            open_policy(vec![Policy {
                origin: std::path::PathBuf::from("<test>"),
                text: text.to_string(),
            }])
            .observed_by(Arc::new(PolicyDecisionObserver)),
        );
        let recorder = DecisionRecorder::discarding();
        (
            ReachFloor {
                reach,
                inner: ShellPolicyInterceptor::into_handle(
                    policy,
                    Principal::agent(),
                    GovernedBox::assigned("codex"),
                ),
                recorder: Arc::clone(&recorder),
            },
            recorder,
        )
    }

    /// **A Shell record names the authored policy that decided the effect.** The gate's own label
    /// said only that the Shell asked; an audit reader needs the rule that answered.
    #[tokio::test]
    async fn a_shell_record_names_the_policy_that_decided_the_effect() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::write(resolved.join("home/ok.txt"), "kept").expect("a fixture file");
        std::fs::write(resolved.join("home/elsewhere.txt"), "kept").expect("a second file");
        let (floor, recorder) = recording_floor(
            reach,
            r#"
                @id("read-the-fixture") @description("one file")
                permit(principal, action == Box::Action::"fs:read", resource)
                when { context.input.path like "*/ok.txt" };
            "#,
        );

        let permitted = resolved.join("home/ok.txt").display().to_string();
        drop(
            floor
                .intercept(&EffectAttempt::Filesystem {
                    path: &permitted,
                    operation: strands_shell::FsOperation::ReadContent,
                })
                .await
                .expect("the authored permit admits the read"),
        );
        let refused = resolved.join("home/elsewhere.txt").display().to_string();
        floor
            .intercept(&EffectAttempt::Filesystem {
                path: &refused,
                operation: strands_shell::FsOperation::ReadContent,
            })
            .await
            .err()
            .expect("no permit names the second file");

        let recorded = recorder.recorded();
        assert_eq!(recorded.len(), 2);

        let (action, resource, rule, verdict, _) = recorded[0].parts();
        assert_eq!(action, r#"Box::Action::"fs:read""#);
        assert_eq!(resource, permitted);
        assert!(
            matches!(rule, EffectiveRule::Policy(_)),
            "the permit names the authored rule rather than the gate: {rule:?}"
        );
        assert_eq!(verdict, EffectiveVerdict::Permit);
        assert_eq!(recorded[0].cause().as_str(), "permitted");
        let [attribution] = recorded[0].attribution() else {
            panic!("one determining policy");
        };
        assert_eq!(
            attribution.annotation_id.as_deref(),
            Some("read-the-fixture")
        );
        assert!(!attribution.token.is_empty());

        // A refusal no rule named still reports its class, and names no policy.
        let (_, _, _, verdict, _) = recorded[1].parts();
        assert_eq!(verdict, EffectiveVerdict::Deny);
        assert_eq!(recorded[1].cause().as_str(), "no_match");
        assert!(recorded[1].attribution().is_empty());
    }

    /// **The policy interception beneath the floor completes in one poll**, which is what makes the
    /// observation capture around it hold: the capture is a thread-local, so a suspension there
    /// would let a concurrent Program's verdict land in this one's attribution.
    #[test]
    fn the_policy_interception_beneath_the_floor_never_suspends() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::write(resolved.join("home/ok.txt"), "kept").expect("a fixture file");
        std::fs::write(resolved.join("home/elsewhere.txt"), "kept").expect("a second file");
        // **Both verdicts, because each is its own exit from the adapter.** A permit is the arm the
        // hazard lives on: the floor builds its record from the captured verdict *after* the await.
        let (floor, _recorder) = recording_floor(
            reach,
            r#"
                @id("read-the-fixture")
                permit(principal, action == Box::Action::"fs:read", resource)
                when { context.input.path like "*/ok.txt" };
            "#,
        );

        for name in ["home/ok.txt", "home/elsewhere.txt"] {
            let path = resolved.join(name).display().to_string();
            let attempt = EffectAttempt::Filesystem {
                path: &path,
                operation: strands_shell::FsOperation::ReadContent,
            };
            let mut deciding = std::pin::pin!(floor.inner.intercept(&attempt));
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(
                matches!(
                    std::future::Future::poll(deciding.as_mut(), &mut context),
                    std::task::Poll::Ready(_)
                ),
                "deciding {name} must reach a verdict without yielding, or the capture around it \
                 spans a suspension point"
            );
        }
    }

    /// The Shell had no canonicity check, and now has the same one Monty has.
    #[cfg(unix)]
    #[test]
    fn the_floor_refuses_a_symlink_leading_out_of_the_reachable_set() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        let secret = resolved.join("outside.pem");
        std::fs::write(&secret, "s").expect("a file outside the set");
        std::os::unix::fs::symlink(&secret, resolved.join("home/link")).expect("a symlink out");
        std::fs::write(resolved.join("home/real.txt"), "r").expect("an ordinary file");

        let floor = floor(reach);
        let link = resolved.join("home/link").display().to_string();
        let refusal = floor
            .approve(&EffectAttempt::Filesystem {
                path: &link,
                operation: strands_shell::FsOperation::ReadContent,
            })
            .expect_err("a link out of the set is not the identity policy judged");
        assert!(
            refusal.to_string().starts_with(&link),
            "the refusal must name the caller's spelling: {refusal}"
        );

        let real = resolved.join("home/real.txt").display().to_string();
        floor
            .approve(&EffectAttempt::Filesystem {
                path: &real,
                operation: strands_shell::FsOperation::ReadContent,
            })
            .expect("an ordinary file inside the home is reachable");
    }

    /// The Shell's own virtual inodes are not host-backed, so the floor has nothing to
    /// confine there and must not refuse them.
    #[test]
    fn the_floor_passes_a_name_the_host_does_not_back() {
        let (_root, reach) = fixture();
        let floor = floor(reach);

        for virtual_only in ["/dev/null", "/tmp/scratch", "/bin/ls"] {
            floor
                .approve(&EffectAttempt::Filesystem {
                    path: virtual_only,
                    operation: strands_shell::FsOperation::ReadContent,
                })
                .expect("a virtual-only inode is the virtual filesystem's own floor");
        }
    }

    /// A resolved command carries no path of its own, so the floor admits it and judges its
    /// effects.
    #[test]
    fn the_floor_admits_a_resolved_command() {
        let (_root, reach) = fixture();
        let floor = floor(reach);
        floor
            .approve(&EffectAttempt::ShellRun {
                command: "cat /workspace/main.rs",
                program: "cat",
                args: &["/workspace/main.rs".to_string()],
                literal: &[true],
                cwd: "/workspace",
            })
            .expect("a command submission carries no path");
    }

    #[tokio::test]
    async fn the_reach_floor_replaces_a_policy_permit_with_one_final_denial() {
        let root = tempfile::tempdir().expect("a fixture root");
        let shared = root.path().canonicalize().expect("the root resolves");
        // The operator's own home, which is what an agent reads unless `[agent] env.HOME` names
        // another directory. A home inside trusted Box state is refused before a box runs.
        let home = shared.to_path_buf();
        let box_root = shared.join("boxes/codex");
        let refused = box_root.join("private/secret.txt");
        std::fs::create_dir_all(refused.parent().expect("the refused parent"))
            .expect("this box's private directory");
        std::fs::write(&refused, "secret").expect("the refused file");
        let reach = Arc::new(crate::test_support::with_operator_home(&shared, || {
            Reach::over_box(&home, Some(&shared), Some(&shared), &box_root, &[])
                .expect("the reachable set is usable")
        }));
        let policy = Arc::new(
            open_policy(vec![Policy {
                origin: PathBuf::from("permit.dw"),
                text: r#"@id("read-anything")
                         permit(principal, action == Box::Action::"fs:read", resource);"#
                    .to_string(),
            }])
            // Observed, so the permit the floor overrides is available to attribute and the record
            // below has to leave it out rather than merely have nothing to name.
            .observed_by(Arc::new(PolicyDecisionObserver)),
        );
        let recorder = DecisionRecorder::discarding();
        let floor = ReachFloor {
            reach,
            inner: ShellPolicyInterceptor::into_handle_reporting_under(
                policy,
                Principal::agent(),
                GovernedBox::assigned("codex"),
                &shared,
            ),
            recorder: Arc::clone(&recorder),
        };
        let refused_text = refused.to_string_lossy();

        let error = match floor
            .intercept(&EffectAttempt::Filesystem {
                path: &refused_text,
                operation: strands_shell::FsOperation::ReadContent,
            })
            .await
        {
            Ok(_) => panic!("the deny-only floor must narrow the policy permit"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let recorded = recorder.recorded();
        let [decision] = recorded.as_slice() else {
            panic!("the PEP must submit exactly one effective decision");
        };
        let (action, resource, rule, verdict, reason) = decision.parts();
        assert_eq!(action, r#"Box::Action::"fs:read""#);
        assert_eq!(resource, "~/boxes/codex/private/secret.txt");
        assert_eq!(rule, &EffectiveRule::Enforcement("reach-floor"));
        assert_eq!(verdict, EffectiveVerdict::Deny);
        assert!(reason.is_some_and(|reason| reason.contains("no policy may open")));
        assert_eq!(decision.cause().as_str(), "enforcement");
        assert!(
            decision.attribution().is_empty(),
            "the permit the floor overrode is not what decided"
        );
    }

    /// A `PATH` candidate inside trusted Box state is refused by the floor with no decision
    /// recorded, and one beside it passes.
    #[tokio::test]
    async fn a_locate_inside_trusted_box_state_is_beneath_the_floor_and_records_no_decision() {
        let root = tempfile::tempdir().expect("a fixture root");
        let shared = root.path().canonicalize().expect("the root resolves");
        let workspace = shared.join("project");
        std::fs::create_dir_all(&workspace).expect("the project");
        std::fs::write(workspace.join("tool"), "#!/bin/sh\n").expect("a project candidate");
        let box_root = shared.join("boxes/codex");
        std::fs::create_dir_all(box_root.join("bin")).expect("the box directory's bin");
        std::fs::write(box_root.join("bin/tool"), "#!/bin/sh\n").expect("a planted candidate");
        let reach = Arc::new(crate::test_support::with_operator_home(&shared, || {
            Reach::over_box(&shared, Some(&shared), Some(&workspace), &box_root, &[])
                .expect("the reachable set is usable")
        }));
        let permit = format!(
            r#"@id("workspace") permit(principal, action == Box::Action::"fs:read", resource)
               when {{ context.input.path like "{}/*" }};"#,
            workspace.display()
        );
        let (floor, recorder) = recording_floor(reach, &permit);

        let planted = box_root.join("bin/tool").to_string_lossy().into_owned();
        let error = floor
            .intercept(&EffectAttempt::Filesystem {
                path: &planted,
                operation: strands_shell::FsOperation::Locate,
            })
            .await
            .err()
            .expect("a candidate inside trusted Box state is beneath the floor");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("no policy may open"), "{error}");

        let beside = workspace.join("tool").to_string_lossy().into_owned();
        floor
            .intercept(&EffectAttempt::Filesystem {
                path: &beside,
                operation: strands_shell::FsOperation::Locate,
            })
            .await
            .expect("a candidate in the project passes the floor");

        assert!(
            recorder.recorded().is_empty(),
            "a Locate is no decision, refused or passed: {:?}",
            recorder.recorded().len()
        );
    }

    /// **The loaded authority is beneath the floor under a workspace permit, on every route the
    /// Shell offers**: a read, a metadata probe, and a write of either source, and a removal of
    /// the directory holding them, all end in the floor's refusal with no permit attributed.
    #[tokio::test]
    async fn the_loaded_authority_is_beneath_the_floor_under_a_workspace_permit() {
        let root = tempfile::tempdir().expect("a fixture root");
        let shared = root.path().canonicalize().expect("the root resolves");
        let workspace = shared.join("project");
        let authority = workspace.join(".strands-box");
        std::fs::create_dir_all(&authority).expect("the project's authority directory");
        std::fs::write(authority.join("policy.dw"), "permit(...)").expect("the active policy");
        std::fs::write(authority.join("box.toml"), "name = \"p\"\n").expect("the configuration");
        std::fs::write(workspace.join("README.md"), "docs").expect("a project file");
        let sources = [
            AuthoritySource::read(&authority.join("box.toml"), "config")
                .expect("the configuration loads")
                .0,
            AuthoritySource::read(&authority.join("policy.dw"), "policy")
                .expect("the policy loads")
                .0,
        ];
        let box_root = shared.join("boxes/codex");
        std::fs::create_dir_all(&box_root).expect("the box directory");
        let reach = Arc::new(crate::test_support::with_operator_home(&shared, || {
            Reach::over_box(
                &shared,
                Some(&shared),
                Some(&workspace),
                &box_root,
                &sources,
            )
            .expect("the reachable set is usable")
        }));
        // The permit names the project as this recorder reports it, absolute, so the floor is what
        // refuses and not a rule that never matched.
        let permit = format!(
            r#"@id("workspace") permit(principal, action in [Box::Action::"fs:read",
               Box::Action::"fs:write", Box::Action::"fs:delete"], resource)
               when {{ context.input.path like "{}/*" }};"#,
            workspace.display()
        );
        let (floor, recorder) = recording_floor(reach, &permit);
        let policy = authority.join("policy.dw").to_string_lossy().into_owned();
        let config = authority.join("box.toml").to_string_lossy().into_owned();
        let directory = authority.to_string_lossy().into_owned();
        let routes = [
            (policy.as_str(), strands_shell::FsOperation::ReadContent),
            (config.as_str(), strands_shell::FsOperation::ReadContent),
            (
                policy.as_str(),
                strands_shell::FsOperation::ReadMetadata {
                    follow_symlinks: true,
                },
            ),
            (directory.as_str(), strands_shell::FsOperation::RemoveDir),
            (
                policy.as_str(),
                strands_shell::FsOperation::WriteContent {
                    create: true,
                    truncate: true,
                },
            ),
        ];
        for (path, operation) in routes {
            let error = floor
                .intercept(&EffectAttempt::Filesystem { path, operation })
                .await
                .err()
                .unwrap_or_else(|| panic!("{path} {operation:?} must be beneath the floor"));
            assert_eq!(
                error.kind(),
                io::ErrorKind::PermissionDenied,
                "{path} {operation:?}"
            );
            assert!(
                error.to_string().contains("no policy may open"),
                "{path} {operation:?}: {error}"
            );
        }
        let recorded = recorder.recorded();
        assert_eq!(recorded.len(), routes.len());
        for decision in &recorded {
            let (_, _, rule, verdict, _) = decision.parts();
            assert_eq!(rule, &EffectiveRule::Enforcement("reach-floor"));
            assert_eq!(verdict, EffectiveVerdict::Deny);
            assert!(
                decision.attribution().is_empty(),
                "the permit is not what decided"
            );
        }
        // The permit still reaches the project beside the authority, and the directory holding
        // the sources is policy's to enumerate: only the sources themselves sit beneath the floor.
        for (path, operation) in [
            (
                workspace.join("README.md").to_string_lossy().into_owned(),
                strands_shell::FsOperation::ReadContent,
            ),
            (directory.clone(), strands_shell::FsOperation::Enumerate),
        ] {
            floor
                .intercept(&EffectAttempt::Filesystem {
                    path: &path,
                    operation,
                })
                .await
                .unwrap_or_else(|error| panic!("{path} {operation:?} is policy's: {error}"));
        }
    }

    /// The mode half of the same guard, also proven by introducing the defect.
    #[test]
    fn a_snapshotted_bind_refuses_to_serve() {
        let (_root, reach) = fixture();
        let binds = reach.shell_binds();
        let (source, destination) = binds[0];
        // `bind`, not `bind_direct`: the vendored crate's default, which snapshots.
        let builder = Shell::builder().bind(source, destination);
        let snapshotted = builder.build().expect("a snapshotting Shell still builds");

        let refusal = verify_direct_binds(&snapshotted, &binds)
            .expect_err("a snapshot diverges from every other view of the directory")
            .to_string();
        assert!(
            refusal.contains("copy") && refusal.contains("direct"),
            "the refusal must name the mode built and the mode required: {refusal}"
        );
    }
}
