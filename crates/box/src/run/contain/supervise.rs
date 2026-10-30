//! The contained child's OS lifetime: its process group and the terminal.

use std::process::{ExitCode, ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::error::{BoxError, SuperviseError, TrampolineError};
use crate::record::layout::BoxRoot;
use crate::run::contain::boundary::Boundary;
use crate::run::contain::terminal::ForegroundTerminal;
use crate::run::contain::trampoline::{self, Trampoline};

/// How long a signalled group may take to leave before it is killed.
const STOP_GRACE: Duration = Duration::from_secs(1);

/// Prepare and start one contained workload after its required registration.
async fn spawn_registered(
    boundary: &Boundary,
    layout: &BoxRoot,
    configure_streams: impl FnOnce(&mut Command),
    own_terminal: bool,
    #[cfg(target_os = "linux")] relay_control: Option<&std::os::unix::net::UnixStream>,
    #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))] registration: Option<
        crate::run::macos_enforcement::Registration,
    >,
) -> Result<(ProcessGroup, Trampoline), BoxError> {
    #[cfg_attr(
        not(all(target_os = "macos", feature = "native-filesystem-policy")),
        allow(unused_mut)
    )]
    let (mut command, mut trampoline) = trampoline::command(trampoline::Launch {
        #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
        hold_for_registration: registration.is_some(),
        config_path: boundary.containment_config(),
        config_file: boundary.containment_config_file(),
        config_sha256: boundary.containment_digest(),
        target_environment: boundary.target_environment(),
        executable: boundary.executable(),
        arguments: boundary.arguments(),
        argument_zero: boundary.argument_zero(),
        working_directory: boundary.working_directory(),
        image_name: &|digest| {
            Ok(trampoline::ImageCache::new(
                layout.trampoline_image(digest),
                layout.open_trampoline_cache()?,
            ))
        },
        #[cfg(target_os = "linux")]
        relay_control,
    })?;
    configure_streams(&mut command);
    #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
    let gate = trampoline.take_launch_gate();
    #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
    if registration.is_some() != gate.is_some() {
        return Err(SuperviseError::Control {
            reason: "native launch gate and registration disagree".into(),
        }
        .into());
    }
    #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
    if let Some(registration) = &registration {
        registration
            .prepare_bootstrap(
                trampoline
                    .bootstrap()
                    .map_err(|source| SuperviseError::Spawn { source })?,
            )
            .map_err(|source| SuperviseError::Spawn { source })?;
    }
    #[cfg_attr(
        not(all(target_os = "macos", feature = "native-filesystem-policy")),
        allow(unused_mut)
    )]
    let mut group = ProcessGroup::spawn_with_terminal(command, own_terminal).await?;
    #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
    if let (Some(gate), Some(registration)) = (gate, registration) {
        let pid = match group.leader_pid() {
            Ok(pid) => pid,
            Err(error) => {
                let _ = group.stop().await;
                return Err(error);
            }
        };
        let mediated = boundary.native_filesystem_policy();
        let result = tokio::task::spawn_blocking(move || {
            gate.release(|| registration.set_mode(pid, mediated))
        })
        .await;
        let error = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error.to_string()),
            Err(error) => Some(error.to_string()),
        };
        if let Some(reason) = error {
            let _ = group.stop().await;
            return Err(SuperviseError::Control { reason }.into());
        }
    }
    Ok((group, trampoline))
}

/// The workload's child handle and the process group it leads, owned and ended as one.
pub(crate) struct ProcessGroup {
    child: tokio::process::Child,
    leader: u32,
    terminated: bool,
}

impl ProcessGroup {
    /// Spawn `command` as the leader of a new process group.
    #[cfg(test)]
    pub(crate) async fn spawn(command: Command) -> Result<Self, BoxError> {
        Self::spawn_with_terminal(command, false).await
    }

    async fn spawn_with_terminal(
        mut command: Command,
        own_terminal: bool,
    ) -> Result<Self, BoxError> {
        command.kill_on_drop(true);
        if own_terminal {
            #[cfg(target_os = "linux")]
            die_with_parent(&mut command);
            // SAFETY: stdio is set before this syscall-only hook; setsid precedes claiming fd 0 as the controlling terminal.
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        } else {
            isolate(&mut command);
        }
        let mut child = command
            .spawn()
            .map_err(|source| SuperviseError::Spawn { source })?;
        let Some(leader) = child.id() else {
            let _ = child.wait().await;
            return Err(SuperviseError::NoProcessId.into());
        };
        Ok(Self {
            child,
            leader,
            terminated: false,
        })
    }

    #[cfg(unix)]
    pub(crate) fn leader_pid(&self) -> Result<libc::pid_t, BoxError> {
        libc::pid_t::try_from(self.leader).map_err(|error| {
            SuperviseError::Control {
                reason: format!("invalid process id: {error}"),
            }
            .into()
        })
    }

    fn child_mut(&mut self) -> &mut tokio::process::Child {
        &mut self.child
    }

    #[cfg(unix)]
    fn signal_os(&self, signal: libc::c_int) -> std::io::Result<()> {
        let leader = libc::pid_t::try_from(self.leader).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })?;
        // SAFETY: kill does not dereference pointers. A negative pid addresses
        // the child-led process group.
        if unsafe { libc::kill(-leader, signal) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn signal(&self, signal: libc::c_int) -> Result<(), BoxError> {
        if self.terminated {
            return Ok(());
        }
        match self.signal_os(signal) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
            Err(error) => Err(SuperviseError::Control {
                reason: error.to_string(),
            }
            .into()),
        }
    }

    /// Whether any member of the group is still present.
    #[cfg(unix)]
    fn has_members(&self) -> bool {
        match self.signal_os(0) {
            Ok(()) => true,
            // EPERM: the leader pid recycled to a foreign owner after the last member left.
            Err(error) => !matches!(error.raw_os_error(), Some(libc::ESRCH) | Some(libc::EPERM)),
        }
    }

    #[cfg(not(unix))]
    fn has_members(&self) -> bool {
        false
    }

    /// Wait for the leader alone.
    pub(crate) async fn wait(&mut self) -> Result<ExitStatus, BoxError> {
        self.child
            .wait()
            .await
            .map_err(|source| SuperviseError::Wait { source }.into())
    }

    /// Wait for the leader and collect its piped stdout and stderr.
    async fn wait_with_output(&mut self) -> std::io::Result<std::process::Output> {
        let stdout = self.child.stdout.take();
        let stderr = self.child.stderr.take();
        let stopped = async {
            let status = self.child.wait().await?;
            self.release().await.map_err(std::io::Error::other)?;
            Ok::<_, std::io::Error>(status)
        };
        let (status, stdout, stderr) = tokio::try_join!(stopped, drain(stdout), drain(stderr))?;
        Ok(std::process::Output {
            status,
            stdout,
            stderr,
        })
    }

    /// End the whole group and reap the leader: `SIGTERM`, a bounded wait, then `SIGKILL`.
    pub(crate) async fn stop(&mut self) -> Result<ExitStatus, BoxError> {
        Ok(self.stop_with_output().await?.status)
    }

    /// [`stop`](Self::stop), collecting the leader's piped stdout and stderr with its status.
    async fn stop_with_output(&mut self) -> Result<std::process::Output, BoxError> {
        let stdout = self.child.stdout.take();
        let stderr = self.child.stderr.take();
        #[cfg(unix)]
        let _ = self.signal(libc::SIGTERM);
        #[cfg(not(unix))]
        let _ = self.child.start_kill();
        let status = match tokio::time::timeout(STOP_GRACE, self.child.wait()).await {
            Ok(status) => status,
            Err(_) => {
                let terminated = self.terminate();
                let _ = self.child.start_kill();
                let status = self.child.wait().await;
                terminated?;
                status
            }
        }
        .map_err(|source| SuperviseError::Wait { source })?;
        self.release().await?;
        // Every writer is gone, so the pipes close; the bound covers a writer that left the group.
        let (stdout, stderr) = tokio::time::timeout(STOP_GRACE, async {
            tokio::join!(drain(stdout), drain(stderr))
        })
        .await
        .unwrap_or_else(|_| (Ok(Vec::new()), Ok(Vec::new())));
        Ok(std::process::Output {
            status,
            stdout: stdout.map_err(|source| SuperviseError::Wait { source })?,
            stderr: stderr.map_err(|source| SuperviseError::Wait { source })?,
        })
    }

    /// End every member that outlived the leader: `SIGTERM`, a bounded wait, then `SIGKILL`.
    pub(crate) async fn release(&mut self) -> Result<(), BoxError> {
        if self.terminated {
            return Ok(());
        }
        if self.has_members() {
            #[cfg(unix)]
            self.signal(libc::SIGTERM)?;
            let deadline = tokio::time::Instant::now() + STOP_GRACE;
            while self.has_members() && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        self.terminate()
    }

    /// Move the child out for another owner that signals the group itself.
    fn into_child(self) -> tokio::process::Child {
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: `this` is never dropped, so `child` is moved out exactly once, and the two other
        // fields are `Copy` with nothing to run.
        unsafe { std::ptr::read(&this.child) }
    }

    pub(crate) fn terminate(&mut self) -> Result<(), BoxError> {
        if self.terminated {
            return Ok(());
        }
        #[cfg(unix)]
        {
            match self.signal_os(libc::SIGKILL) {
                Ok(()) => {
                    self.terminated = true;
                    Ok(())
                }
                // ESRCH: the group is already gone. EPERM: the leader pid
                // recycled to a foreign owner between the reap and this send —
                // measured on `macos-latest` under load. Both mean "our child
                // is not there to signal," so both close cleanly.
                Err(error)
                    if matches!(error.raw_os_error(), Some(libc::ESRCH) | Some(libc::EPERM)) =>
                {
                    self.terminated = true;
                    Ok(())
                }
                Err(error) => Err(SuperviseError::Control {
                    reason: error.to_string(),
                }
                .into()),
            }
        }
        #[cfg(not(unix))]
        {
            self.terminated = true;
            Ok(())
        }
    }
}

/// Everything a piped stream still holds, or nothing for an absent stream.
async fn drain(stream: Option<impl tokio::io::AsyncRead + Unpin>) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if let Some(mut stream) = stream {
        stream.read_to_end(&mut bytes).await?;
    }
    Ok(bytes)
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if self.terminated {
            return;
        }
        let _ = self.terminate();
        let _ = self.child.start_kill();
    }
}

#[cfg(unix)]
pub(crate) fn isolate(command: &mut Command) {
    command.process_group(0);
    #[cfg(target_os = "linux")]
    die_with_parent(command);
}

#[cfg(target_os = "linux")]
fn die_with_parent(command: &mut Command) {
    // Linux ties the signal to the spawning thread, which must outlive the supervised child.
    // SAFETY: getpid reads this process's identifier.
    let parent = unsafe { libc::getpid() };
    // SAFETY: the callback uses only process-control syscalls before exec.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
pub(crate) fn isolate(_command: &mut Command) {}

// ═══════════════════════════════════════════════════════════════════════════════
// Running the child to completion.

/// A running contained workload, and everything that must outlive it.
pub(crate) struct Contained {
    group: ProcessGroup,
    signals: Signals,

    /// The foreground terminal, when this run holds it. `None` for a piped run, where claiming it
    /// would take the foreground away from the caller's own process.
    terminal: Option<ForegroundTerminal>,
    trampoline: Trampoline,

    /// The assembled boundary, which keeps the containment config descriptor open through spawn.
    _boundary: Boundary,

    /// The Linux relays, held for exactly the workload's lifetime: the gateway's, then the
    /// collector's.
    #[cfg(target_os = "linux")]
    _relays: Vec<crate::run::netns_relay::NetnsRelay>,

    /// This box's trusted half. It outlives the workload it decides for: dropping it unbinds the
    /// broker socket, joins the gateway's thread, withdraws the live record, and releases the box
    /// lock. [`Contained::wait`] also watches its broker, because a boundary that stopped serving
    hosted: crate::run::hosted::HostedBox,
}

impl Contained {
    /// Spawn the workload in its own process group, holding the foreground
    /// terminal so job control and Ctrl-C behave as they would outside the box.
    pub(crate) async fn spawn(
        boundary: Boundary,
        layout: &BoxRoot,
        hosted: crate::run::hosted::HostedBox,
        terminal: Option<std::fs::File>,
        signals: Option<Signals>,
    ) -> Result<Self, BoxError> {
        Self::spawn_with(
            boundary,
            layout,
            hosted,
            Stdio::inherit,
            true,
            terminal,
            signals,
        )
        .await
    }

    /// Spawn an isolated workload without applying containment.
    #[cfg(all(test, unix))]
    pub(crate) async fn testing_spawn_uncontained(
        boundary: Boundary,
        hosted: crate::run::hosted::HostedBox,
    ) -> Result<Self, BoxError> {
        let trampoline = Trampoline::testing_complete()?;
        let mut command = Command::new(boundary.executable());
        command
            .args(boundary.arguments())
            .env_clear()
            .current_dir(boundary.working_directory())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let signals = Signals::listen()?;
        let group = ProcessGroup::spawn(command).await?;

        Ok(Self {
            group,
            signals,
            terminal: None,
            trampoline,
            _boundary: boundary,
            #[cfg(target_os = "linux")]
            _relays: Vec::new(),
            hosted,
        })
    }

    /// The one spawn body. `stdio` supplies stdin and stdout; stderr is always inherited.
    async fn spawn_with(
        boundary: Boundary,
        layout: &BoxRoot,
        hosted: crate::run::hosted::HostedBox,
        stdio: fn() -> Stdio,
        claim_terminal: bool,
        terminal: Option<std::fs::File>,
        signals: Option<Signals>,
    ) -> Result<Self, BoxError> {
        // The relay's control socket must exist before the trampoline is spawned,
        // because the trampoline sends its listening descriptor over it during
        #[cfg(target_os = "linux")]
        let (relay_box_side, relay_child_side) =
            crate::run::netns_relay::NetnsRelay::control_pair()?;

        let own_terminal = terminal.is_some();
        let mut signals = match signals {
            Some(signals) => signals,
            None => Signals::listen()?,
        };
        if own_terminal {
            signals.restore_default = false;
        }
        let (stdin, stdout, stderr) = match terminal {
            Some(file) => {
                let input = file
                    .try_clone()
                    .map_err(|source| SuperviseError::Spawn { source })?;
                let output = file
                    .try_clone()
                    .map_err(|source| SuperviseError::Spawn { source })?;
                (Stdio::from(input), Stdio::from(output), Stdio::from(file))
            }
            None => (stdio(), stdio(), Stdio::inherit()),
        };
        let (mut group, trampoline) = spawn_registered(
            &boundary,
            layout,
            |command| {
                command.stdin(stdin).stdout(stdout).stderr(stderr);
            },
            own_terminal,
            #[cfg(target_os = "linux")]
            Some(&relay_child_side),
            #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
            hosted.native_registration(),
        )
        .await?;
        let terminal = if claim_terminal && !own_terminal {
            match group.leader_pid().and_then(ForegroundTerminal::claim) {
                Ok(terminal) => Some(terminal),
                Err(error) => {
                    let _ = group.stop().await;
                    return Err(error);
                }
            }
        } else {
            None
        };

        // Start the relay only after the child is spawned. `NetnsRelay::start_each` blocks until
        // the descriptor arrives, and the descriptor comes *from* the trampoline.
        #[cfg(target_os = "linux")]
        let relays = {
            drop(relay_child_side);
            // **The same list the containment config was built from**, gateway first.
            match crate::run::netns_relay::NetnsRelay::start_each(
                relay_box_side,
                boundary.served_ports(),
            ) {
                Ok(relays) => relays,
                Err(error) => {
                    // No route out means every model request would fail. Tear the
                    // child down rather than run a workload that cannot work.
                    let _ = group.stop().await;
                    if let Some(mut terminal) = terminal {
                        let _ = terminal.restore();
                    }
                    return Err(error);
                }
            }
        };

        Ok(Self {
            group,
            signals,
            terminal,
            trampoline,
            _boundary: boundary,
            #[cfg(target_os = "linux")]
            _relays: relays,
            hosted,
        })
    }

    /// Wait for the workload, forwarding `SIGINT` and stopping it on `SIGTERM` or `SIGHUP`, and
    /// report its exit code.
    pub(crate) async fn wait(mut self) -> Result<ExitCode, BoxError> {
        // Release the box's copy of the status pipe first: until it is closed the
        // read below would block on the box itself.
        self.trampoline.close_setup_writer();

        // **The workload's exit races its boundary's failure.** With no daemon to unload a broken
        // box, this is what answers a broker that stopped serving: the run ends
        enum Completion {
            Workload(Result<ExitStatus, BoxError>),
            Hosted(BoxError),
        }
        let completion = tokio::select! {
            status = self.signals.wait_forwarding(&mut self.group) => {
                Completion::Workload(status)
            }
            failure = self.hosted.stopped() => Completion::Hosted(failure),
        };
        if matches!(completion, Completion::Hosted(_)) {
            let _ = self.group.stop().await;
        }
        let termination_result = self.group.release().await;
        let native_result = self.hosted.stop_native();
        // A piped run never claimed the terminal, so there is nothing to give back.
        let terminal_result = match self.terminal.as_mut() {
            Some(terminal) => terminal.restore(),
            None => Ok(()),
        };
        let setup_result = self.trampoline.setup_failure();

        // The drain moved to `command::run::execute`, which is the one point every exit reaches —
        // including the failures before a `HostedBox` exists. A run that ends in an error still
        // keeps its records, because this collector outlives the `?`-returns below.

        let status = match completion {
            Completion::Workload(result) => result?,
            Completion::Hosted(failure) => return Err(failure),
        };
        termination_result?;
        native_result?;
        terminal_result?;
        // A setup failure outranks the status: `exit 3` from a refused apply is
        // the trampoline's, not the workload's.
        if let Some(stage) = setup_result? {
            return Err(TrampolineError::SetupFailed {
                stage,
                detail: None,
            }
            .into());
        }
        Ok(exit_code(status))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// A leaf box: one host binary contained on its own, reusing the parent box's TCB.

/// The status and captured streams of a leaf box that ran to completion.
pub(crate) struct CapturedLeaf {
    pub(crate) status: i32,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

/// A contained leaf box: one host binary run on its own, reusing the parent box's TCB.
///
/// Unlike [`Contained`] it owns no `HostedBox`, so there is no second `PolicyEngine`, no broker to
/// watch, and no foreground terminal. On Linux it carries its own netns relay to the parent gateway
/// while it runs. The box's host-spawn hook calls [`run`](Self::run) and relays the
/// captured output back through the Shell.
pub(crate) struct LeafBox;

/// A contained leaf child, spawned in its own process group with — on Linux — its netns relays to
/// the parent gateway held for the child's lifetime. The shared prologue of the buffered
/// [`LeafBox::run`] and the streaming [`LeafBox::spawn_streaming`].
struct LaunchedLeaf {
    group: ProcessGroup,
    trampoline: Trampoline,
    #[cfg(target_os = "linux")]
    relays: Vec<crate::run::netns_relay::NetnsRelay>,
}

impl LeafBox {
    /// Build the trampoline, spawn the contained child in its own process group, and — on Linux —
    /// start the netns relays held for the child's lifetime. `stdin`/`stdout`/`stderr` are the
    /// child's stdio: the buffered run pipes stdout/stderr and nulls stdin; the streaming spawn
    /// pipes stdin/stdout for the JSON-RPC session and nulls stderr.
    async fn launch_contained(
        boundary: &Boundary,
        layout: &BoxRoot,
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
        #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))] registration: Option<
            crate::run::macos_enforcement::Registration,
        >,
    ) -> Result<LaunchedLeaf, BoxError> {
        // The relay's control socket must exist before the trampoline is spawned, because the
        // trampoline sends its listening descriptor over it during containment setup.
        #[cfg(target_os = "linux")]
        let (relay_box_side, relay_child_side) =
            crate::run::netns_relay::NetnsRelay::control_pair()?;

        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let (mut group, mut trampoline) = spawn_registered(
            boundary,
            layout,
            |command| {
                command.stdin(stdin).stdout(stdout).stderr(stderr);
            },
            false,
            #[cfg(target_os = "linux")]
            Some(&relay_child_side),
            #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
            registration,
        )
        .await?;

        // Start the relay only after the child is spawned: `start_each` blocks until the descriptor
        // arrives, and the descriptor comes from the trampoline. Held until the child exits.
        #[cfg(target_os = "linux")]
        let relays = {
            drop(relay_child_side);
            match crate::run::netns_relay::NetnsRelay::start_each(
                relay_box_side,
                boundary.served_ports(),
            ) {
                Ok(relays) => relays,
                Err(error) => {
                    // A trampoline that refused its config never sends the descriptor, so its own
                    // refusal, not the missing route, is the failure to report.
                    trampoline.close_setup_writer();
                    let output = group.stop_with_output().await;
                    if let Ok(Some(stage)) = trampoline.setup_failure() {
                        let stderr = output.map(|output| output.stderr).unwrap_or_default();
                        return Err(TrampolineError::SetupFailed {
                            stage,
                            detail: trampoline_message(&stderr),
                        }
                        .into());
                    }
                    return Err(error);
                }
            }
        };

        Ok(LaunchedLeaf {
            group,
            trampoline,
            #[cfg(target_os = "linux")]
            relays,
        })
    }

    /// Run a host binary in a leaf box, capture its output, and report status and streams.
    ///
    /// The binary runs contained through the trampoline, with the leaf's own environment and — on
    /// Linux — its own netns relay to the parent gateway. A containment setup failure is a
    /// [`TrampolineError::SetupFailed`], not a workload status. Buffered: the streams come back
    /// whole; a long-lived session uses [`spawn_streaming`](Self::spawn_streaming).
    pub(crate) async fn run(
        boundary: Boundary,
        layout: &BoxRoot,
        #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))] registration: Option<
            crate::run::macos_enforcement::Registration,
        >,
    ) -> Result<CapturedLeaf, BoxError> {
        // Captured, so the bytes come back to the Shell and leave through its own streams. stdin is
        // null: a leaf binary reads no stdin, and one that blocked would hold the Call to its deadline.
        let LaunchedLeaf {
            mut group,
            mut trampoline,
            #[cfg(target_os = "linux")]
                relays: _relays,
        } = Self::launch_contained(
            &boundary,
            layout,
            Stdio::null(),
            Stdio::piped(),
            Stdio::piped(),
            #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
            registration,
        )
        .await?;

        // The boundary keeps all launch inputs alive until the child exits.
        trampoline.close_setup_writer();
        let output = group.wait_with_output().await;
        let termination_result = group.release().await;
        let setup_result = trampoline.setup_failure();

        let output = output.map_err(|source| SuperviseError::Wait { source })?;
        termination_result?;
        // A setup failure outranks the status: a refused apply is the trampoline's, not the binary's.
        // Its message names what was refused, so the failure carries it out of the captured stream.
        if let Some(stage) = setup_result? {
            return Err(TrampolineError::SetupFailed {
                stage,
                detail: trampoline_message(&output.stderr),
            }
            .into());
        }
        let _ = &boundary;
        Ok(CapturedLeaf {
            status: captured_status(output.status),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    /// Return live streams after setup completes without a reported executable launch failure.
    pub(crate) async fn spawn_streaming(
        boundary: Boundary,
        layout: &BoxRoot,
        #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))] registration: Option<
            crate::run::macos_enforcement::Registration,
        >,
    ) -> Result<StreamingLeaf, BoxError> {
        // stderr is piped, not nulled: a containment setup failure must carry the trampoline's own
        // message as `detail`, the same reason the buffered `run` path reports. On success the
        // workload owns stderr for its whole life, so a drain task below discards it — an undrained
        // pipe would block the server once full. stdin and stdout are the JSON-RPC session's, kept
        // live for the server's lifetime.
        let LaunchedLeaf {
            mut group,
            trampoline,
            #[cfg(target_os = "linux")]
            relays,
        } = Self::launch_contained(
            &boundary,
            layout,
            Stdio::piped(),
            Stdio::piped(),
            Stdio::piped(),
            #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
            registration,
        )
        .await?;

        // The child owns its streams from spawn; take them before confirming setup.
        let stdin = group.child_mut().stdin.take();
        let stdout = group.child_mut().stdout.take();
        let mut stderr = group.child_mut().stderr.take();

        // The reader waits for completed preparation and channel closure, or a reported failure.
        let setup = tokio::task::spawn_blocking(move || {
            let mut trampoline = trampoline;
            trampoline.close_setup_writer();
            trampoline.setup_failure()
        })
        .await
        .map_err(|error| SuperviseError::Control {
            reason: format!("containment setup task failed: {error}"),
        })??;
        if let Some(stage) = setup {
            let _ = group.stop().await;
            // Setup failed before `exec`, so only the trampoline wrote to stderr and its last line
            // names what was refused — a bounded read, because the workload never ran. This is the
            // detail the buffered `run` path reports from its captured stderr.
            let detail = match stderr.as_mut() {
                Some(stderr) => {
                    let mut buffer = Vec::new();
                    let _ = stderr.read_to_end(&mut buffer).await;
                    trampoline_message(&buffer)
                }
                None => None,
            };
            return Err(TrampolineError::SetupFailed { stage, detail }.into());
        }

        // Drain stderr so a running server cannot block on a full pipe.
        if let Some(mut stderr) = stderr {
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
            });
        }

        Ok(StreamingLeaf {
            stdin,
            stdout,
            group,
            _boundary: boundary,
            #[cfg(target_os = "linux")]
            _relays: relays,
        })
    }
}

/// A contained MCP server running under its own leaf box, with live stdin/stdout for its JSON-RPC
/// session. The broker adopts it into a `RunningMcpServer` via [`into_parts`](Self::into_parts).
pub(crate) struct StreamingLeaf {
    stdin: Option<tokio::process::ChildStdin>,
    stdout: Option<tokio::process::ChildStdout>,
    group: ProcessGroup,

    /// The assembled boundary, which keeps the containment config descriptor open for the child's
    /// lifetime.
    _boundary: Boundary,

    /// The Linux relays to the parent gateway, held for exactly the server's lifetime.
    #[cfg(target_os = "linux")]
    _relays: Vec<crate::run::netns_relay::NetnsRelay>,
}

/// The live child, its streams, its leader pid, and what must outlive it — everything the broker
/// needs to drive a contained MCP server, with ownership taken from the [`StreamingLeaf`].
pub(crate) struct StreamingLeafParts {
    pub(crate) child: tokio::process::Child,
    pub(crate) stdin: tokio::process::ChildStdin,
    pub(crate) stdout: tokio::process::ChildStdout,
    pub(crate) leader: u32,
    pub(crate) retention: StreamingLeafRetention,
}

/// What a contained MCP server must keep alive while it runs, held by the broker beside the child:
/// the leaf's netns relays (Linux) and its boundary (the open containment-config descriptor). It
/// carries no signalling responsibility — the broker's handle owns the child and its group.
pub(crate) struct StreamingLeafRetention {
    _boundary: Boundary,
    #[cfg(target_os = "linux")]
    _relays: Vec<crate::run::netns_relay::NetnsRelay>,
}

impl StreamingLeaf {
    /// Take the child, its streams, and its leader out for the broker to own, which signals the
    /// group by pid from then on. `None` when the child exposed no live streams or has already gone.
    pub(crate) fn into_parts(mut self) -> Option<StreamingLeafParts> {
        let leader = self.group.child_mut().id()?;
        let stdin = self.stdin.take()?;
        let stdout = self.stdout.take()?;
        // Ownership of the child and its leader moves to the broker, which signals by pid.
        Some(StreamingLeafParts {
            child: self.group.into_child(),
            stdin,
            stdout,
            leader,
            retention: StreamingLeafRetention {
                _boundary: self._boundary,
                #[cfg(target_os = "linux")]
                _relays: self._relays,
            },
        })
    }
}

/// The trampoline's setup diagnostic, including continuation lines.
fn trampoline_message(stderr: &[u8]) -> Option<String> {
    const PREFIX: &str = "strands-box-contain-trampoline: ";
    // Containment's MissingReads caps its reason at 6000 bytes, leaving room for error framing.
    const MAXIMUM_CHARACTERS: usize = 8192;
    let text = String::from_utf8_lossy(stderr);
    let start = text
        .match_indices(PREFIX)
        .filter(|(offset, _)| *offset == 0 || text.as_bytes()[offset - 1] == b'\n')
        .last()
        .map(|(offset, _)| offset + PREFIX.len());
    let message = match start {
        Some(start) => text[start..].trim(),
        None => text
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())?
            .trim(),
    };
    Some(message.chars().take(MAXIMUM_CHARACTERS).collect())
}

/// A process's exit code, or `128 + signal` when it died from one.
fn captured_status(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            status.signal().map_or(128, |signal| 128 + signal)
        }
        #[cfg(not(unix))]
        {
            128
        }
    })
}

/// The signals the box answers for its workload, listened for before the workload exists.
pub(crate) struct Signals {
    restore_default: bool,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    /// Absent when the box inherited an ignored `SIGHUP`, as under `nohup`.
    #[cfg(unix)]
    hangup: Option<tokio::signal::unix::Signal>,
}

impl Signals {
    pub(crate) fn listen() -> Result<Self, BoxError> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let listen = |kind: SignalKind| {
                signal(kind).map_err(|source| BoxError::from(SuperviseError::Signal { source }))
            };
            let hangup = if is_ignored(libc::SIGHUP) {
                None
            } else {
                Some(listen(SignalKind::hangup())?)
            };
            Ok(Self {
                restore_default: true,
                interrupt: listen(SignalKind::interrupt())?,
                terminate: listen(SignalKind::terminate())?,
                hangup,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    /// Wait for the leader, forwarding `SIGINT` to its group and stopping the group on `SIGTERM`
    /// or `SIGHUP`.
    async fn wait_forwarding(&mut self, group: &mut ProcessGroup) -> Result<ExitStatus, BoxError> {
        #[cfg(unix)]
        {
            loop {
                let hangup = async {
                    match self.hangup.as_mut() {
                        Some(hangup) => hangup.recv().await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    status = group.wait() => return status,
                    received = self.interrupt.recv() => {
                        if received.is_none() {
                            return group.wait().await;
                        }
                        group.signal(libc::SIGINT)?;
                    }
                    received = self.terminate.recv() => {
                        return ended_by(received, libc::SIGTERM, self.restore_default, group).await;
                    }
                    received = hangup => return ended_by(received, libc::SIGHUP, self.restore_default, group).await,
                }
            }
        }
        #[cfg(not(unix))]
        {
            group.wait().await
        }
    }
}

/// Whether this process inherited `signal` as ignored.
#[cfg(unix)]
fn is_ignored(signal: libc::c_int) -> bool {
    // SAFETY: a zeroed `sigaction` is a valid value, and a null new action only reads the current one.
    unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        libc::sigaction(signal, std::ptr::null(), &mut current) == 0
            && current.sa_sigaction == libc::SIG_IGN
    }
}

/// The workload's own status once the box has been told to end by `signal`: `stop` ends the
/// group, so the status is its `SIGTERM` or `SIGKILL` death for either signal, and the signal's
/// default action is restored so a second delivery during teardown ends the box.
#[cfg(unix)]
async fn ended_by(
    received: Option<()>,
    signal: libc::c_int,
    restore_default: bool,
    group: &mut ProcessGroup,
) -> Result<ExitStatus, BoxError> {
    if received.is_none() {
        return group.wait().await;
    }
    let status = group.stop().await;
    // SAFETY: restoring the default disposition of a signal this process listened for.
    if restore_default {
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
        }
    }
    status
}

/// The workload's exit code, or `128 + signal` when it died from one.
fn exit_code(status: ExitStatus) -> ExitCode {
    let value = if let Some(code) = status.code().and_then(|code| u8::try_from(code).ok()) {
        code
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            status
                .signal()
                .and_then(|signal| u8::try_from(128 + signal).ok())
                .unwrap_or(255)
        }
        #[cfg(not(unix))]
        {
            1
        }
    };
    ExitCode::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SetupStage;
    use crate::test_support::{HELD_GROUP, SIGNALS, processes_exit, wait_for_pids};
    use std::os::unix::process::ExitStatusExt as _;

    /// **A leaf setup failure carries the trampoline's message**, which names the binary and the
    /// library the view could not resolve, rather than the stage alone.
    #[test]
    fn a_leaf_setup_failure_carries_the_trampolines_message() {
        let stderr = b"strands-box: [tool.cargo] runs /usr/bin/app\n\
            strands-box-contain-trampoline: containment apply failed: '/usr/bin/app' needs the \
            shared library 'libnope.so.1', which is not in its DT_RUNPATH\n";
        let detail = trampoline_message(stderr).expect("the trampoline wrote a line");
        assert!(
            detail.starts_with("containment apply failed: '/usr/bin/app' needs the shared library"),
            "{detail}"
        );
        let error: BoxError = TrampolineError::SetupFailed {
            stage: SetupStage::Apply,
            detail: Some(detail),
        }
        .into();
        let text = error.to_string();
        assert!(
            text.contains("libnope.so.1") && text.contains("/usr/bin/app"),
            "the failure names the library and the binary: {text}"
        );
        assert!(trampoline_message(b"").is_none());
    }

    #[test]
    fn a_startup_failure_preserves_grouped_reads_and_additive_guidance() {
        let stderr = b"earlier log\nstrands-box-contain-trampoline: containment apply failed: 2 dependencies lack read access\nDependency: /vendor/codec\nDependency: /vendor/storage\nKeep existing filesystem entries. Append these paths to read_file\nNo configuration files changed.\n";
        let detail = trampoline_message(stderr).unwrap();
        for required in [
            "/vendor/codec",
            "/vendor/storage",
            "Keep existing",
            "read_file",
            "No configuration files changed.",
        ] {
            assert!(detail.contains(required), "{detail}");
        }
        assert!(!detail.contains("earlier log"));
    }

    #[test]
    fn a_maximum_missing_read_reason_keeps_its_final_guidance() {
        // This fixture reaches MissingReads::require_complete's 6000-byte reason limit.
        let mut reason = "2 dependencies lack read access\nDependency: /vendor/界\nDependency: /vendor/storage\nRequested by: /project/".to_owned();
        let guidance = "\nKeep existing filesystem entries. Append these paths to read_file\nNo configuration files changed.";
        reason.push_str(&"x".repeat(6000 - reason.len() - guidance.len()));
        reason.push_str(guidance);
        let error = containment::ContainmentError::ApplyFailed {
            backend: "seatbelt".to_owned(),
            reason,
        };
        let expected = format!("containment apply failed: {error}");
        let stderr = format!("earlier log\nstrands-box-contain-trampoline: {expected}\n");
        let detail = trampoline_message(stderr.as_bytes()).unwrap();
        assert_eq!(detail, expected);
        assert!(detail.ends_with("No configuration files changed."));
    }

    #[test]
    fn a_normal_exit_reports_its_own_code() {
        assert_eq!(
            format!("{:?}", exit_code(ExitStatus::from_raw(7 << 8))),
            format!("{:?}", ExitCode::from(7))
        );
    }

    /// A signalled workload reports `128 + signal`, the shell convention, so a
    /// caller can tell a crash from a nonzero exit.
    #[test]
    fn a_signalled_exit_reports_128_plus_the_signal() {
        assert_eq!(
            format!("{:?}", exit_code(ExitStatus::from_raw(libc::SIGINT))),
            format!("{:?}", ExitCode::from(128 + libc::SIGINT as u8))
        );
    }

    #[test]
    fn a_signalled_leaf_reports_128_plus_the_signal() {
        assert_eq!(captured_status(ExitStatus::from_raw(7 << 8)), 7);
        assert_eq!(
            captured_status(ExitStatus::from_raw(libc::SIGKILL)),
            128 + libc::SIGKILL
        );
    }

    /// Signalling a group that has already gone is not an error: the workload
    /// exiting before the box signals it is the normal case, not a fault.
    #[tokio::test]
    async fn signalling_a_departed_group_succeeds() {
        let group = departed_group().await;

        assert!(
            group.signal(libc::SIGINT).is_ok(),
            "ESRCH must not be an error"
        );
    }

    /// A pid that cannot be a process group is refused rather than signalled.
    #[tokio::test]
    async fn an_out_of_range_process_id_is_refused() {
        let mut group = departed_group().await;
        group.leader = u32::MAX;

        let error = group
            .signal(libc::SIGINT)
            .expect_err("a pid that overflows pid_t must be refused");
        assert!(error.to_string().contains("process control"), "{error}");
    }

    /// Terminating twice is idempotent, so `Drop` after an explicit terminate
    /// cannot report a spurious failure.
    #[tokio::test]
    async fn terminating_twice_is_idempotent() {
        let mut group = departed_group().await;

        assert!(group.terminate().is_ok());
        assert!(group.terminate().is_ok());
    }

    /// A group whose leader has already exited and been reaped.
    async fn departed_group() -> ProcessGroup {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        let mut group = ProcessGroup::spawn(command).await.expect("spawn");
        group.wait().await.expect("the leader exits");
        group
    }

    /// A leader and one descendant that both ignore `SIGTERM`, with their pids in `path`.
    async fn group_ignoring_sigterm(path: &std::path::Path) -> (ProcessGroup, Vec<libc::pid_t>) {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(HELD_GROUP)
            .arg("group")
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let group = ProcessGroup::spawn(command).await.expect("spawn");
        let pids = wait_for_pids(path, 2)
            .await
            .expect("the group writes both pids");
        (group, pids)
    }

    /// **An inherited ignored `SIGHUP` stays ignored.** A box started under `nohup` must not stop
    /// its workload on the hangup its parent told it to ignore, so no listener is installed.
    #[tokio::test]
    async fn an_inherited_ignored_hangup_installs_no_listener() {
        let _signals = SIGNALS.lock().await;
        // SAFETY: a zeroed `sigaction` is a valid value; the previous disposition is saved and
        // restored before the lock drops.
        let previous = unsafe {
            let mut previous: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGHUP, std::ptr::null(), &mut previous),
                0
            );
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            previous
        };

        let listening = Signals::listen();

        // SAFETY: restoring the disposition read above.
        unsafe {
            libc::sigaction(libc::SIGHUP, &previous, std::ptr::null_mut());
        }
        let signals = listening.expect("the box listens");
        assert!(
            signals.hangup.is_none(),
            "an ignored SIGHUP gets no listener"
        );
    }

    #[tokio::test]
    async fn a_supplied_terminal_becomes_the_workloads_controlling_terminal() {
        use std::os::fd::{AsRawFd, FromRawFd};

        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty writes two descriptors; null options select the defaults.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: openpty returned two owned descriptors.
        let (master, slave) = unsafe {
            (
                std::fs::File::from_raw_fd(master),
                std::fs::File::from_raw_fd(slave),
            )
        };
        for descriptor in [&master, &slave] {
            // SAFETY: fcntl changes flags on these owned, open descriptors.
            assert_ne!(
                unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
                -1
            );
        }
        let mut command = Command::new("/bin/sleep");
        command
            .env_clear()
            .arg("60")
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave);
        let mut group = ProcessGroup::spawn_with_terminal(command, true)
            .await
            .unwrap();
        let leader = group.leader_pid().unwrap();
        // SAFETY: the child is alive and the owned PTY master stays open.
        unsafe {
            assert_eq!(libc::getsid(leader), leader);
            assert_eq!(libc::tcgetpgrp(master.as_raw_fd()), leader);
        }
        let status = tokio::time::timeout(Duration::from_secs(5), group.stop())
            .await
            .expect("terminal workload stops")
            .unwrap();
        assert!(!status.success(), "{status}");
    }

    #[tokio::test]
    async fn terminal_shutdown_preserves_the_hosts_signal_handlers() {
        let _signals = SIGNALS.lock().await;
        let _listening = Signals::listen().unwrap();
        for signal in [libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: initialized sigaction storage and a null action only read the disposition.
            let mut before: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sigaction(signal, std::ptr::null(), &mut before) },
                0
            );
            let mut command = Command::new("/bin/sleep");
            command.arg("60");
            let mut group = ProcessGroup::spawn(command).await.unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                ended_by(Some(()), signal, false, &mut group),
            )
            .await;
            // SAFETY: read the resulting disposition, then restore the saved action before assertions.
            let mut after: libc::sigaction = unsafe { std::mem::zeroed() };
            unsafe {
                assert_eq!(libc::sigaction(signal, std::ptr::null(), &mut after), 0);
                assert_eq!(libc::sigaction(signal, &before, std::ptr::null_mut()), 0);
            }
            assert!(!result.expect("shutdown is bounded").unwrap().success());
            assert_eq!(after.sa_sigaction, before.sa_sigaction);
        }
    }

    /// `stop` ends a group that ignores `SIGTERM`: the bounded wait runs out and `SIGKILL` follows,
    /// so the leader and its descendant are both gone when it returns.
    #[tokio::test]
    async fn stopping_a_group_that_ignores_sigterm_kills_every_member() {
        let directory = tempfile::tempdir().expect("a directory");
        let (mut group, pids) = group_ignoring_sigterm(&directory.path().join("pids")).await;

        let started = std::time::Instant::now();
        let status = tokio::time::timeout(Duration::from_secs(10), group.stop())
            .await
            .expect("stop is bounded")
            .expect("stop reaps the leader");

        assert!(!status.success(), "the leader was killed: {status:?}");
        assert!(
            processes_exit(&pids).await,
            "leader and descendant must be gone: {pids:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the grace is bounded: {:?}",
            started.elapsed()
        );
    }

    /// Dropping the group, which is what a `?` return after spawn does, ends every member.
    #[tokio::test]
    async fn dropping_a_group_ends_every_member() {
        let directory = tempfile::tempdir().expect("a directory");
        let (group, pids) = group_ignoring_sigterm(&directory.path().join("pids")).await;

        drop(group);

        assert!(
            processes_exit(&pids).await,
            "leader and descendant must be gone: {pids:?}"
        );
    }

    #[tokio::test]
    async fn captured_exit_stops_descendants_that_hold_the_output_open() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("pids");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                r#"trap '' TERM; sleep 3600 & printf '%s %s' "$$" "$!" > "$1"; printf 'done'; exit 7"#,
                "group",
            ])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut group = ProcessGroup::spawn(command).await.expect("spawn");
        let pids = wait_for_pids(&path, 2).await.expect("both pids");
        let result = tokio::time::timeout(Duration::from_secs(4), group.wait_with_output()).await;
        drop(group);
        assert!(processes_exit(&pids).await, "all children stop: {pids:?}");
        let output = result
            .expect("capture finishes after the leader exits")
            .expect("output");
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"done");
    }

    #[tokio::test]
    async fn cancelling_a_captured_wait_ends_every_member() {
        let directory = tempfile::tempdir().expect("a directory");
        let (mut group, pids) = group_ignoring_sigterm(&directory.path().join("pids")).await;
        let (started, waiting) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            started.send(()).expect("waiting receiver");
            group.wait_with_output().await
        });
        waiting.await.expect("capture starts");
        task.abort();
        assert!(task.await.expect_err("cancelled task").is_cancelled());
        assert!(processes_exit(&pids).await, "all children stop: {pids:?}");
    }

    #[tokio::test]
    async fn a_captured_wait_timeout_ends_every_member() {
        let directory = tempfile::tempdir().expect("a directory");
        let (mut group, pids) = group_ignoring_sigterm(&directory.path().join("pids")).await;
        let result = tokio::time::timeout(Duration::from_millis(20), async move {
            group.wait_with_output().await
        })
        .await;
        assert!(result.is_err(), "the workload outlives the timeout");
        assert!(processes_exit(&pids).await, "all children stop: {pids:?}");
    }
}
