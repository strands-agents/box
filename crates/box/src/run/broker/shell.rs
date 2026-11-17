//! The Shell interpreter: how one is built, and the confinement it is refused without.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use box_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, EffectResult, FsOperation,
};
use policy::{GovernedBox, PolicyEngine, Principal, ShellPolicyInterceptor};
use strands_shell::Shell;

use crate::run::broker::invalid_input;
use crate::run::broker::mcp::DiscoveryRegistry;
use crate::run::broker::reach::{Reach, Refused};
use crate::run::contain::boundary::environment::WORKLOAD_USER;
use crate::run::credential::ProvisionedVariable;
use crate::run::telemetry::{DecisionRecorder, EffectiveDecision, ObservationCapture};
use box_shell::{Filesystem, ScriptOutcome, ScriptRunner, ShellKernel};

pub(super) const SHELL_MAX_FILE_SIZE: usize = 10 * 1024 * 1024;
pub(super) const SHELL_MAX_INODES: usize = 10_000;
const SHELL_MAX_DEPTH: u32 = 64;
const SHELL_MAX_FDS: usize = 128;
const SHELL_MAX_BACKGROUND_JOBS: usize = 8;
const SHELL_MAX_PIPELINE: usize = 16;

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

/// One Call's Shell, and the kernel it runs on.
pub(crate) struct HostedShell {
    pub(crate) shell: Shell,
    pub(crate) kernel: Arc<ShellKernel>,
}

/// Everything needed to build the hosted Shell, kept so one can be rebuilt.
pub(super) struct ShellSpec {
    pub(super) max_input: usize,
    /// The most stdin one Shell Program receives.
    pub(super) max_stdin: usize,
    pub(super) max_output: usize,
    /// The Shell's own bound on one submitted Shell call.
    pub(super) command_timeout: Option<Duration>,
    /// The broker's backstop deadline on one Call, distinct from `command_timeout`. The Shell's own
    /// timeout normally fires first (and reports an `Exit`); this catches a Call that outlives it
    /// and answers `DeniedKind::Timeout`.
    pub(super) request_timeout: Option<Duration>,
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

    /// Every variable a route provisions, which each new Shell holds beneath its own names.
    pub(super) phantoms: Vec<ProvisionedVariable>,

    /// Where final policy enforcement point decisions are submitted.
    pub(super) recorder: Arc<crate::run::telemetry::DecisionRecorder>,

    /// The hook that runs a host binary in a contained leaf box. `None` refuses every host binary.
    pub(super) host_spawner: Option<crate::run::hosted::ToolSpawner>,

    /// The `[tool]` file each declared bare name runs, in place of a host `PATH` lookup.
    pub(super) host_programs: box_shell::HostPrograms,
}

impl ShellSpec {
    /// Build a Shell confined exactly as the host requires.
    pub(super) fn build(&self) -> io::Result<HostedShell> {
        self.build_on(self.backend()?, &self.recorder)
    }

    /// One Program's filesystem: the Shell's own, with each reachable root served from the host.
    pub(super) fn backend(&self) -> io::Result<Arc<Filesystem>> {
        Ok(Arc::new(Filesystem::serving(
            shell_filesystem()?,
            &self.reach.shell_binds(),
        )?))
    }

    pub(super) fn build_on(
        &self,
        backend: Arc<Filesystem>,
        recorder: &Arc<DecisionRecorder>,
    ) -> io::Result<HostedShell> {
        // Two interceptors, one above the other. PolicyEngine decides first; the reachable set is a
        // deny-only floor **beneath** it, so no `permit` can open a path outside the agent's home
        let interceptor = ReachFloor::over(
            Arc::clone(&self.reach),
            Arc::clone(recorder),
            self.host_spawner.clone(),
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
        verify_direct_binds(&backend, &self.reach.shell_binds())?;
        let correlation = recorder.request_context();
        let mut kernel = ShellKernel::over(backend, interceptor)
            .programs(Arc::clone(&self.host_programs))
            .python(
                self.max_output,
                self.script_interpreter(correlation.clone()),
            );
        // With no gateway the network stays off: a fail-closed refusal, never a direct dial.
        if let Some(egress) = &self.egress {
            super::kernel::verify_gateway_ca(egress)?;
            kernel = kernel.network(Arc::new(super::kernel::GatewayNetwork::new(
                egress.clone(),
                correlation.clone(),
            )));
        }
        if let Some(spawner) = &self.host_spawner {
            kernel = kernel.spawner(within(correlation, spawner.spawn()));
        }
        let kernel = Arc::new(kernel);
        let mut shell =
            Shell::with_kernel(Arc::clone(&kernel) as Arc<dyn strands_shell::os::Kernel>);
        apply_limits(&mut shell.proc, self.max_input, self.max_output);
        shell.proc.deadline = deadline(self.command_timeout)?;
        shell.proc.cwd = PathBuf::from(self.reach.working_directory());
        // Each route's phantom, beneath the Shell's own names, in the order `environment::compose`
        // keeps (docs/design/decisions.md#the-box-is-the-credential-boundary).
        for phantom in &self.phantoms {
            shell.set_env(phantom.name.as_str(), phantom.value.as_str());
        }
        shell.set_env("PWD", self.reach.working_directory());
        shell.set_env("HOME", self.reach.home_variable());
        shell.set_env("USER", WORKLOAD_USER);
        Ok(HostedShell { shell, kernel })
    }

    fn script_interpreter(&self, correlation: telemetry::Correlation) -> ScriptRunner {
        let reach = Arc::clone(&self.reach);
        let policy = Arc::clone(&self.policy);
        let governed = self.governed.clone();
        let recorder = Arc::clone(&self.recorder);
        let egress = self.egress.clone();
        Arc::new(move |source: String| {
            let reach = Arc::clone(&reach);
            let policy = Arc::clone(&policy);
            let governed = governed.clone();
            let egress = egress.clone();
            let recorder = Arc::clone(&recorder);
            let correlation = correlation.clone();
            Box::pin(async move {
                let monty = crate::run::broker::python::drive_monty(
                    source,
                    crate::run::broker::python::PYTHON_ORIGIN.to_string(),
                    &reach,
                    &policy,
                    &governed,
                    egress.as_ref(),
                    &recorder,
                );
                let outcome = correlation.scope(monty).await;
                ScriptOutcome {
                    status: outcome.status,
                    stdout: outcome.stdout,
                    stderr: outcome.stderr,
                }
            })
        })
    }
}

/// `spawner`, run inside one Call's trace context.
fn within(
    correlation: telemetry::Correlation,
    spawner: box_shell::HostSpawner,
) -> box_shell::HostSpawner {
    Arc::new(move |spawn| {
        let correlation = correlation.clone();
        let spawned = spawner(spawn);
        Box::pin(async move { correlation.scope(spawned).await })
    })
}

/// The Shell's own filesystem, under its file size and inode caps.
pub(super) fn shell_filesystem() -> io::Result<strands_shell::vfs::Vfs> {
    let mut vfs =
        strands_shell::vfs_config::build_vfs(&strands_shell::vfs_config::VfsConfig::default())?;
    vfs.max_file_size = SHELL_MAX_FILE_SIZE;
    vfs.max_inodes = SHELL_MAX_INODES;
    Ok(vfs)
}

/// The limits one Shell process runs under.
pub(super) fn apply_limits(
    proc: &mut strands_shell::os::Process,
    max_input: usize,
    max_output: usize,
) {
    proc.max_depth = SHELL_MAX_DEPTH;
    proc.max_output = max_output;
    proc.max_fds = SHELL_MAX_FDS;
    proc.max_bg_jobs = SHELL_MAX_BACKGROUND_JOBS;
    proc.max_pipeline = SHELL_MAX_PIPELINE;
    proc.max_input = max_input;
}

/// The deadline of a Call starting now, or none when the Shell timeout is unlimited.
pub(super) fn deadline(timeout: Option<Duration>) -> io::Result<Option<tokio::time::Instant>> {
    timeout
        .map(|timeout| {
            tokio::time::Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| invalid_input("the Shell timeout overflows the clock"))
        })
        .transpose()
}

/// Refuse a mount table that is not exactly the declared set.
fn verify_direct_binds(filesystem: &Filesystem, declared: &[(&str, &str)]) -> io::Result<()> {
    let served: Vec<(&Path, &str)> = filesystem.binds().collect();
    if served.len() != declared.len() {
        return Err(invalid_input(format!(
            "the hosted Shell must serve {} host folders; found {}",
            declared.len(),
            served.len(),
        )));
    }
    for ((source, visible), (declared_source, declared_visible)) in served.iter().zip(declared) {
        if *source != Path::new(declared_source)
            || *visible != strands_shell::vfs::normalize(declared_visible)
        {
            return Err(invalid_input(format!(
                "the hosted Shell serves {} at {visible}; the box declared {declared_source} at \
                 {declared_visible}",
                source.display(),
            )));
        }
    }
    Ok(())
}

/// The reachable set, as a deny-only floor over the Shell's own admission seam.
struct ReachFloor {
    host_spawner: Option<crate::run::hosted::ToolSpawner>,
    reach: Arc<Reach>,
    inner: Arc<dyn EffectInterceptor>,
    recorder: Arc<DecisionRecorder>,
}

impl ReachFloor {
    fn over(
        reach: Arc<Reach>,
        recorder: Arc<DecisionRecorder>,
        host_spawner: Option<crate::run::hosted::ToolSpawner>,
        inner: Arc<dyn EffectInterceptor>,
    ) -> Arc<dyn EffectInterceptor> {
        Arc::new(Self {
            host_spawner,
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
                box_shell::FsPairOperation::Rename { .. } => self
                    .approve_one(from, true)
                    .and_then(|()| self.approve_one(to, true)),
                box_shell::FsPairOperation::Symlink => self
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

fn is_metadata_read(effect: &EffectAttempt<'_>) -> bool {
    matches!(
        effect,
        EffectAttempt::Filesystem {
            operation: FsOperation::ReadMetadata { .. },
            ..
        }
    )
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
    action: std::borrow::Cow<'static, str>,
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
            action: r#"Box::Action::"shell:exec""#.into(),
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
            action: r#"Box::Action::"shell:spawn""#.into(),
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
            action: fs_action(*operation).into(),
            resource: reported_path(path, home),
            reported: None,
        }),
        EffectAttempt::FilesystemPair { to, operation, .. } => Some(DecisionSubject {
            action: match operation {
                box_shell::FsPairOperation::Rename { .. } => r#"Box::Action::"fs:move""#,
                box_shell::FsPairOperation::Symlink => r#"Box::Action::"fs:write""#,
                _ => r#"Box::Action::"fs:other""#,
            }
            .into(),
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

struct SpawnDirectoryPermit {
    inner: Option<Box<dyn EffectPermit>>,
    working_directory: PathBuf,
}

impl EffectPermit for SpawnDirectoryPermit {
    fn spawn_working_directory(&self) -> Option<&Path> {
        Some(&self.working_directory)
    }

    fn record_outcome<'future>(
        mut self: Box<Self>,
        outcome: EffectOutcome,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'future>>
    where
        Self: 'future,
    {
        self.inner
            .take()
            .expect("the checked spawn owns its policy permit")
            .record_outcome(outcome)
    }

    fn mark_indeterminate(self: Box<Self>) {
        drop(self);
    }
}

impl Drop for SpawnDirectoryPermit {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.mark_indeterminate();
        }
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
            let spawn_directory = match (effect, &self.host_spawner) {
                (
                    EffectAttempt::ShellSpawn {
                        program,
                        program_path,
                        args,
                        cwd,
                        ..
                    },
                    Some(spawner),
                ) => Some(
                    spawner
                        .working_directory(
                            Path::new(program_path),
                            Path::new(program),
                            args,
                            Path::new(cwd),
                        )
                        .unwrap_or_else(|_| PathBuf::from(*cwd)),
                ),
                _ => None,
            };
            let checked = match (effect, spawn_directory.as_ref()) {
                (
                    EffectAttempt::ShellSpawn {
                        command,
                        program,
                        program_path,
                        args,
                        literal,
                        ..
                    },
                    Some(directory),
                ) => Some(EffectAttempt::ShellSpawn {
                    command,
                    program,
                    program_path,
                    args,
                    literal,
                    cwd: directory.to_str().expect("the checked directory is UTF-8"),
                }),
                _ => None,
            };
            let effect = checked.as_ref().unwrap_or(effect);
            let subject =
                decision_subject(effect, self.reach.reported_home().map(std::path::Path::new));
            // PolicyEngine first, always. The floor cannot widen what policy refused, and asking
            // it first would let an unreachable path skip the decision — so a rule counting
            let capture = ObservationCapture::begin();
            let intercepted = self.inner.intercept(effect).await;
            let determined = capture.last();
            // A grammar action decides a bound spawn in place of `shell:spawn`
            // (docs/design/decisions.md#a-grammar-action-replaces-shell-spawn).
            let subject = subject.map(|mut subject| {
                if let (EffectAttempt::ShellSpawn { .. }, Some(observed)) = (effect, &determined) {
                    subject.action = observed.action().to_string().into();
                }
                subject
            });
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
                    Ok(match spawn_directory {
                        Some(working_directory) => Box::new(SpawnDirectoryPermit {
                            inner: Some(permit),
                            working_directory,
                        })
                            as Box<dyn EffectPermit>,
                        None => permit,
                    })
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
                    // than dropped: a rule counting attempts must still see it. A metadata read
                    // of a path the host cannot resolve is an answer
                    // (docs/design/decisions.md#temporal-rules-are-enforced-against-recorded-history).
                    let outcome = if refused.is_unresolved() && is_metadata_read(effect) {
                        EffectResult::Completed
                    } else {
                        EffectResult::Failed(io::ErrorKind::PermissionDenied)
                    };
                    let _ = permit.record_outcome(EffectOutcome::Kernel(outcome)).await;
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

    #[derive(Clone, Copy)]
    enum RecordingMode {
        Complete,
        Fail,
        Suspend,
    }

    struct RecordingPermit {
        events: Arc<std::sync::Mutex<Vec<&'static str>>>,
        mode: RecordingMode,
    }

    struct PendingRecording(Option<Arc<std::sync::Mutex<Vec<&'static str>>>>);

    impl Drop for PendingRecording {
        fn drop(&mut self) {
            if let Some(events) = self.0.take() {
                events
                    .lock()
                    .expect("recorded events")
                    .push("cancelled recording");
            }
        }
    }

    impl EffectPermit for RecordingPermit {
        fn record_outcome<'future>(
            self: Box<Self>,
            outcome: EffectOutcome,
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'future>>
        where
            Self: 'future,
        {
            assert!(matches!(
                outcome,
                EffectOutcome::ShellCommand {
                    reported_status: 23
                }
            ));
            self.events.lock().expect("recorded events").push("record");
            let mut pending = PendingRecording(Some(Arc::clone(&self.events)));
            Box::pin(async move {
                let result = match self.mode {
                    RecordingMode::Complete => Ok(()),
                    RecordingMode::Fail => Err(io::Error::other("recording failed")),
                    RecordingMode::Suspend => std::future::pending().await,
                };
                pending.0.take();
                result
            })
        }

        fn mark_indeterminate(self: Box<Self>) {
            self.events
                .lock()
                .expect("recorded events")
                .push("indeterminate");
        }
    }

    fn directory_permit(
        events: &Arc<std::sync::Mutex<Vec<&'static str>>>,
        mode: RecordingMode,
    ) -> Box<dyn EffectPermit> {
        Box::new(SpawnDirectoryPermit {
            inner: Some(Box::new(RecordingPermit {
                events: Arc::clone(events),
                mode,
            })),
            working_directory: PathBuf::from("/checked/workspace"),
        })
    }

    #[test]
    fn a_checked_spawn_marks_every_exit_before_recording_indeterminate_once() {
        for exit in ["drop", "mark"] {
            let events = Arc::new(std::sync::Mutex::new(Vec::new()));
            let permit = directory_permit(&events, RecordingMode::Complete);
            assert_eq!(
                permit.spawn_working_directory(),
                Some(Path::new("/checked/workspace"))
            );
            match exit {
                "drop" => drop(permit),
                _ => permit.mark_indeterminate(),
            }
            assert_eq!(
                *events.lock().expect("recorded events"),
                ["indeterminate"],
                "{exit}"
            );
        }
    }

    #[test]
    fn cancelling_an_unpolled_spawn_recording_leaves_reconciliation_to_its_owner() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recording = directory_permit(&events, RecordingMode::Complete).record_outcome(
            EffectOutcome::ShellCommand {
                reported_status: 23,
            },
        );
        drop(recording);
        assert_eq!(
            *events.lock().expect("recorded events"),
            ["record", "cancelled recording"]
        );
    }

    #[tokio::test]
    async fn a_checked_spawn_forwards_the_outcome_and_recording_error_once() {
        for mode in [RecordingMode::Complete, RecordingMode::Fail] {
            let events = Arc::new(std::sync::Mutex::new(Vec::new()));
            let result = directory_permit(&events, mode)
                .record_outcome(EffectOutcome::ShellCommand {
                    reported_status: 23,
                })
                .await;
            assert_eq!(result.is_ok(), matches!(mode, RecordingMode::Complete));
            if let Err(error) = result {
                assert_eq!(error.to_string(), "recording failed");
            }
            assert_eq!(*events.lock().expect("recorded events"), ["record"]);
        }
    }

    #[test]
    fn cancelling_a_forwarded_spawn_recording_leaves_reconciliation_to_its_owner() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut recording = directory_permit(&events, RecordingMode::Suspend).record_outcome(
            EffectOutcome::ShellCommand {
                reported_status: 23,
            },
        );
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(recording.as_mut().poll(&mut context).is_pending());
        drop(recording);
        assert_eq!(
            *events.lock().expect("recorded events"),
            ["record", "cancelled recording"]
        );
    }

    /// **The box's label table agrees with the policy adapter on every kernel verb listed here,
    /// no listed verb reaches `fs:other`, and `Locate` is no decision on either side.** The policy
    /// crate's `tests/shell_fs_vocabulary.rs` pins the same lists against `crates/shell`.
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
            box_shell::FsPairOperation::Rename {
                destination_exists: false,
                destination_is_dir: false,
            },
            box_shell::FsPairOperation::Rename {
                destination_exists: true,
                destination_is_dir: false,
            },
            box_shell::FsPairOperation::Rename {
                destination_exists: true,
                destination_is_dir: true,
            },
            box_shell::FsPairOperation::Symlink,
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
            host_spawner: None,
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
                host_spawner: None,
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
                    operation: box_shell::FsOperation::ReadContent,
                })
                .await
                .expect("the authored permit admits the read"),
        );
        let refused = resolved.join("home/elsewhere.txt").display().to_string();
        floor
            .intercept(&EffectAttempt::Filesystem {
                path: &refused,
                operation: box_shell::FsOperation::ReadContent,
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
                operation: box_shell::FsOperation::ReadContent,
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
                operation: box_shell::FsOperation::ReadContent,
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
                operation: box_shell::FsOperation::ReadContent,
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
                    operation: box_shell::FsOperation::ReadContent,
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
            host_spawner: None,
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
                operation: box_shell::FsOperation::ReadContent,
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

    /// **A metadata read the reach floor refuses meets no `::response` precondition**, and an
    /// answered one does.
    #[tokio::test]
    async fn a_metadata_read_the_floor_refuses_meets_no_response_precondition() {
        let root = tempfile::tempdir().expect("a fixture root");
        let shared = root.path().canonicalize().expect("the root resolves");
        let box_root = shared.join("boxes/codex");
        let refused = box_root.join("private/secret.txt");
        std::fs::create_dir_all(refused.parent().expect("the refused parent"))
            .expect("this box's private directory");
        std::fs::write(&refused, "secret").expect("the refused file");
        let gated = shared.join("gated.txt");
        std::fs::write(&gated, "gated").expect("the gated file");
        let checked = shared.join("checked.txt");
        std::fs::write(&checked, "checked").expect("the checked file");
        let reach = Arc::new(crate::test_support::with_operator_home(&shared, || {
            Reach::over_box(&shared, Some(&shared), Some(&shared), &box_root, &[])
                .expect("the reachable set is usable")
        }));
        let policy = Arc::new(open_policy(vec![Policy {
            origin: PathBuf::from("precondition.dw"),
            text: r#"permit(principal, action == Box::Action::"fs:read", resource)
                     when { context.input.path != "~/gated.txt" };
                     permit(principal, action == Box::Action::"fs:read", resource)
                     when { context.input.path == "~/gated.txt" }
                     when temporal {
                         formerly within 60s
                         Box::Action::"fs:read"::response{ input.path: _, input.operation: Box::FsReadOperation::"read_metadata" }
                     };"#
            .to_string(),
        }]));
        let floor = ReachFloor {
            host_spawner: None,
            reach,
            inner: ShellPolicyInterceptor::into_handle_reporting_under(
                policy,
                Principal::agent(),
                GovernedBox::assigned("codex"),
                &shared,
            ),
            recorder: DecisionRecorder::discarding(),
        };
        let metadata = box_shell::FsOperation::ReadMetadata {
            follow_symlinks: true,
        };
        let refused_text = refused.to_string_lossy();
        let gated_text = gated.to_string_lossy();
        let checked_text = checked.to_string_lossy();
        let read_gated = EffectAttempt::Filesystem {
            path: &gated_text,
            operation: box_shell::FsOperation::ReadContent,
        };

        assert!(
            floor
                .intercept(&EffectAttempt::Filesystem {
                    path: &refused_text,
                    operation: metadata,
                })
                .await
                .is_err(),
            "the floor refuses a metadata read of private state"
        );
        assert!(
            floor.intercept(&read_gated).await.is_err(),
            "a refused metadata read is not a response"
        );

        floor
            .intercept(&EffectAttempt::Filesystem {
                path: &checked_text,
                operation: metadata,
            })
            .await
            .expect("a metadata read of a reachable file is permitted")
            .record_outcome(EffectOutcome::Kernel(EffectResult::Completed))
            .await
            .expect("outcome reporting is best effort");
        assert!(
            floor.intercept(&read_gated).await.is_ok(),
            "an answered metadata read meets the precondition"
        );
    }

    /// A floor over `shared` whose read of `~/gated.txt` needs an earlier `operation` response.
    fn precondition_floor(shared: &Path, box_root: &Path, operation: &str) -> ReachFloor {
        let reach = Arc::new(crate::test_support::with_operator_home(shared, || {
            Reach::over_box(shared, Some(shared), Some(shared), box_root, &[])
                .expect("the reachable set is usable")
        }));
        let policy = Arc::new(open_policy(vec![Policy {
            origin: PathBuf::from("precondition.dw"),
            text: format!(
                r#"permit(principal, action == Box::Action::"fs:read", resource)
                   when {{ context.input.path != "~/gated.txt" }};
                   permit(principal, action == Box::Action::"fs:read", resource)
                   when {{ context.input.path == "~/gated.txt" }}
                   when temporal {{
                       formerly within 60s
                       Box::Action::"fs:read"::response{{ input.path: _, input.operation: Box::FsReadOperation::"{operation}" }}
                   }};"#
            ),
        }]));
        ReachFloor {
            host_spawner: None,
            reach,
            inner: ShellPolicyInterceptor::into_handle_reporting_under(
                policy,
                Principal::agent(),
                GovernedBox::assigned("codex"),
                shared,
            ),
            recorder: DecisionRecorder::discarding(),
        }
    }

    /// **A metadata read under a missing folder meets a `::response` precondition**, and the same
    /// path read for content, beneath box state, or through a link does not.
    #[tokio::test]
    async fn a_metadata_read_under_a_missing_folder_meets_a_response_precondition() {
        let root = tempfile::tempdir().expect("a fixture root");
        let shared = root.path().canonicalize().expect("the root resolves");
        let box_root = shared.join("boxes/codex");
        std::fs::create_dir_all(box_root.join("private")).expect("this box's private directory");
        std::fs::write(shared.join("gated.txt"), "gated").expect("the gated file");
        std::fs::create_dir(shared.join("real")).expect("a real folder");
        std::os::unix::fs::symlink(shared.join("real"), shared.join("link"))
            .expect("a link in the home");
        std::os::unix::fs::symlink(box_root.join("private/nodir"), shared.join("dangle"))
            .expect("a dangling link into box state");
        let gated_text = shared.join("gated.txt").to_string_lossy().into_owned();
        let read_gated = EffectAttempt::Filesystem {
            path: &gated_text,
            operation: box_shell::FsOperation::ReadContent,
        };
        let metadata = box_shell::FsOperation::ReadMetadata {
            follow_symlinks: true,
        };
        let probe = |relative: &str| shared.join(relative).to_string_lossy().into_owned();

        let floor = precondition_floor(&shared, &box_root, "read_metadata");
        let absent = probe("absent-dir/x");
        assert!(
            floor
                .intercept(&EffectAttempt::Filesystem {
                    path: &absent,
                    operation: metadata,
                })
                .await
                .is_err(),
            "the floor still refuses a path it cannot resolve"
        );
        assert!(
            floor.intercept(&read_gated).await.is_ok(),
            "a metadata read under a missing folder is a response"
        );

        for relative in [
            "boxes/codex/private/nodir/x",
            "link/nodir/x",
            "dangle",
            "dangle/x",
        ] {
            let floor = precondition_floor(&shared, &box_root, "read_metadata");
            let refused = probe(relative);
            assert!(
                floor
                    .intercept(&EffectAttempt::Filesystem {
                        path: &refused,
                        operation: metadata,
                    })
                    .await
                    .is_err(),
                "the floor refuses {relative}"
            );
            assert!(
                floor.intercept(&read_gated).await.is_err(),
                "a metadata read of {relative} is not a response"
            );
        }

        let floor = precondition_floor(&shared, &box_root, "read_content");
        assert!(
            floor
                .intercept(&EffectAttempt::Filesystem {
                    path: &absent,
                    operation: box_shell::FsOperation::ReadContent,
                })
                .await
                .is_err(),
            "the floor refuses a content read under a missing folder"
        );
        assert!(
            floor.intercept(&read_gated).await.is_err(),
            "a content read under a missing folder is not a response"
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
                operation: box_shell::FsOperation::Locate,
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
                operation: box_shell::FsOperation::Locate,
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
            (policy.as_str(), box_shell::FsOperation::ReadContent),
            (config.as_str(), box_shell::FsOperation::ReadContent),
            (
                policy.as_str(),
                box_shell::FsOperation::ReadMetadata {
                    follow_symlinks: true,
                },
            ),
            (directory.as_str(), box_shell::FsOperation::RemoveDir),
            (
                policy.as_str(),
                box_shell::FsOperation::WriteContent {
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
                box_shell::FsOperation::ReadContent,
            ),
            (directory.clone(), box_shell::FsOperation::Enumerate),
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

    /// A mount table that is not the declared set refuses to serve.
    #[test]
    fn a_mount_table_that_is_not_the_declared_set_refuses_to_serve() {
        let (_root, reach) = fixture();
        let binds = reach.shell_binds();
        let serving = |binds: &[(&str, &str)]| {
            Filesystem::serving(shell_filesystem().expect("a filesystem"), binds).expect("serves")
        };
        verify_direct_binds(&serving(&binds), &binds).expect("the declared set serves");

        let (source, destination) = binds[0];
        let elsewhere = serving(&[(source, "/elsewhere")]);
        let refusal = verify_direct_binds(&elsewhere, &binds)
            .expect_err("a folder served at another name is refused")
            .to_string();
        assert!(
            refusal.contains("/elsewhere") && refusal.contains(destination),
            "the refusal names the folder served and the folder declared: {refusal}"
        );

        let missing = verify_direct_binds(&serving(&[]), &binds)
            .expect_err("a table that serves nothing is refused")
            .to_string();
        assert!(missing.contains("must serve"), "{missing}");
    }
}
