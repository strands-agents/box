//! The broker's transport: one listener, one reader per connection, and dispatch on `Open`.
//!
//! Still threads `Arc<ShellSpec>` through four signatures, so it is not yet interpreter-agnostic;
//! `AGENTS.md` records what closing that costs.
//!
//! | Cause | Response |
//! |---|---|
//! | The client disconnects mid-Call | Drop that Program, keep accepting |
//! | A Call outlives its deadline | Answer the client, drop that Program |
//! | A Program cannot be built | Report it to that client, keep accepting |
//! | The listener fails | Terminate the daemon |

use std::collections::HashMap;
use std::io;
use std::path::Path;
// `Arc` for the spec: each connection runs on its own thread, so the spec itself crosses
// threads. (It was `Rc` while every Shell shared one `LocalSet`.)
use std::sync::Arc;
use std::time::Duration;

use policy::{GovernedBox, PolicyEngine};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::task::{JoinError, JoinSet};

use crate::error::{BoxError, ShellError};
use crate::record::config::{AuthoritySource, Record};
use crate::record::layout::BoxRoot;
use crate::run::broker::invalid_input;
use crate::run::broker::mcp::DiscoveryRegistry;
use crate::run::broker::program::{Chunk, DrainOutcome, Program, ProgramControl, ProgramOutput};
use crate::run::broker::protocol::{
    BOUNDARY_FAILURE_STATUS, Body, DeniedKind, Frame, Interpreter, MAX_PROGRAMS_PER_CONNECTION,
    PROTOCOL_VERSION, ProgramId, SignalKind, Stream, decode_payload, encode_payload, read_frame,
    write_frame,
};
use crate::run::broker::reach::Reach;
use crate::run::broker::shell::{EgressRouting, SHELL_COMMAND_TIMEOUT, ShellSpec};

/// How many client connections may be in flight at once.
const SERVE_CONNECTION_CAPACITY: usize = 64;

/// Bound on one framed read or write with an untrusted peer.
const SERVE_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on one Shell Call's framing, outside the interpreter's own deadline.
pub(super) const SERVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

const _: () = assert!(
    SERVE_REQUEST_TIMEOUT.as_nanos() > SHELL_COMMAND_TIMEOUT.as_nanos(),
    "the transport's bound must outlast the interpreter's, or a command stopped at its own \
     deadline is reported as a boundary failure"
);

/// How long a REQUEST-shaped connection may sit idle between frames before it is dropped.
const SERVE_TRANSPORT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// The same bound for a connection hosting an MCP server, which is SESSION-shaped.
const SERVE_MCP_IDLE_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);

const _: () = assert!(
    SERVE_MCP_IDLE_TIMEOUT.as_nanos() > SERVE_TRANSPORT_IDLE_TIMEOUT.as_nanos(),
    "an MCP session is idle by design, so its bound must outlast the request-shaped one"
);

/// How long this connection may sit idle, given whether it hosts an MCP server.
fn idle_timeout(hosts_mcp_server: bool) -> Duration {
    if hosts_mcp_server {
        SERVE_MCP_IDLE_TIMEOUT
    } else {
        SERVE_TRANSPORT_IDLE_TIMEOUT
    }
}

/// Named once because both the in-loop drain and the post-loop sweep report it.
const OUTPUT_BUDGET_SPENT: &str = "the program exceeded its output budget";

/// How many outbound frames may queue before a writer stalls its producer.
const OUTBOUND_FRAME_DEPTH: usize = 64;

/// How often a running Call is checked for a pending `Signal`.
const SIGNAL_POLL_INTERVAL: Duration = Duration::from_millis(10);

struct ConnectionTask<T> {
    task: Option<tokio::task::JoinHandle<T>>,
}

impl<T> ConnectionTask<T> {
    fn new(task: tokio::task::JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    async fn completed(&mut self) -> Result<T, tokio::task::JoinError> {
        self.task
            .as_mut()
            .expect("a connection task remains owned")
            .await
    }

    fn disarm(&mut self) {
        drop(self.task.take());
    }
}

impl<T> Drop for ConnectionTask<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// The daemon's broker: a bound listener and the task set serving it.
pub(crate) struct BrokerHost {
    /// The serving task. Aborted on drop, which also drops the listener it owns.
    shutdown: Option<oneshot::Sender<()>>,
    /// Resolves when the broker thread stops, carrying why.
    stopped: oneshot::Receiver<io::Error>,
    /// The broker's own thread, joined on `Drop`.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl BrokerHost {
    /// Bind the broker's socket on a dedicated thread and serve it until dropped.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        layout: &BoxRoot,
        record: &Record,
        workspace: &Path,
        home: &Path,
        policy: Arc<PolicyEngine>,
        registry: Arc<DiscoveryRegistry>,
        egress: Option<EgressRouting>,
        recorder: Arc<crate::run::telemetry::DecisionRecorder>,
        host_spawner: Option<strands_shell::os::HostSpawner>,
        mcp_leaf_launcher: Option<Arc<crate::run::hosted::McpLeafLauncher>>,
        protected_sources: &[AuthoritySource],
    ) -> Result<Self, BoxError> {
        let displayed_socket = layout.broker_socket();
        // The agent's workspace is the interpreters' working directory, and its `HOME` is what every
        // participant reads, so one directory has one name on both sides of the socket.
        let reach = Arc::new(
            Reach::over_box(
                home,
                layout.operator_home(),
                Some(workspace),
                layout.root(),
                protected_sources,
            )
            .map_err(|source| ShellError::Serve { source })?,
        );
        // The declared MCP servers, from the same record. The box places one alias per entry, so
        // this set and the alias set in `bin/` are the same list — a name outside it names nothing
        let declared_mcp = Arc::new(record.mcp.clone());
        let spawn_credentials = record.tool_credential_paths();
        // Resolved here, where the `BoxRoot` is in hand. `BoxRoot::open` created it.
        let mcp_working_directory = layout.mcp_working_directory();
        let mcp_working_directory_handle = Arc::new(layout.open_mcp_working_directory()?);

        // Refuse rather than adopt: the liveness lock proves no daemon holds this path,
        // so anything at it is a corpse — but binding over a *live* one would serve
        if layout.path_exists(&displayed_socket)? {
            return Err(ShellError::Serve {
                source: io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "broker socket already exists: {}",
                        displayed_socket.display()
                    ),
                ),
            }
            .into());
        }
        let listener = layout
            .bind_broker_listener()
            .map_err(|source| ShellError::Bind { source })?;
        listener
            .set_nonblocking(true)
            .map_err(|source| ShellError::Bind { source })?;

        let (ready_sender, ready_receiver) = std::sync::mpsc::channel::<io::Result<()>>();
        let (shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();
        let (stopped_sender, stopped_receiver) = oneshot::channel::<io::Error>();

        // The box every request on this socket is judged as. One socket serves one box,
        // so the name is settled here, from the root the daemon is loading. Nothing on the wire
        let governed = GovernedBox::assigned(layout.name());

        let thread = std::thread::Builder::new()
            .name("strands-box-broker".to_string())
            .spawn(move || {
                let outcome = host(
                    listener,
                    reach,
                    policy,
                    governed,
                    spawn_credentials,
                    McpHosting {
                        declared: declared_mcp,
                        registry,
                        working_directory: mcp_working_directory,
                        working_directory_handle: mcp_working_directory_handle,
                        leaf_launcher: mcp_leaf_launcher,
                    },
                    egress,
                    recorder,
                    host_spawner,
                    &ready_sender,
                    shutdown_receiver,
                );
                // Report why the broker stopped, so the daemon can fail closed. A send
                // failure means the daemon is already gone, which needs no report.
                if let Err(error) = outcome {
                    let _ = stopped_sender.send(error);
                }
            })
            .map_err(|source| ShellError::Serve { source })?;

        // Block until the thread has bound, or failed to. `recv` also errors if the
        // thread died before reporting, so a panic during setup surfaces here rather than
        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                shutdown: Some(shutdown_sender),
                stopped: stopped_receiver,
                thread: Some(thread),
            }),
            Ok(Err(source)) => Err(ShellError::Bind { source }.into()),
            Err(_) => Err(ShellError::Serve {
                source: io::Error::other("the broker thread stopped before binding"),
            }
            .into()),
        }
    }

    /// Wait for the broker to stop, which only happens on failure.
    pub(crate) async fn stopped(&mut self) -> BoxError {
        let source = match (&mut self.stopped).await {
            Ok(error) => error,
            Err(_) => io::Error::other("the broker thread stopped without reporting"),
        };
        ShellError::Serve { source }.into()
    }
}

impl Drop for BrokerHost {
    /// Signal the broker thread and wait for it.
    fn drop(&mut self) {
        drop(self.shutdown.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Decide `shell:spawn` for starting `server`, on the program the start will exec.
fn authorize_mcp_start(
    spec: &ShellSpec,
    server: &crate::record::config::mcp::McpServer,
    program_path: &std::path::Path,
    arguments: &[String],
    working_directory: &std::path::Path,
    credential_reads: &[String],
) -> io::Result<()> {
    let home = spec.reach.reported_home();
    let reported = |path: &std::path::Path| -> String {
        match home.and_then(|home| path.strip_prefix(home).ok()) {
            Some(relative) if relative.as_os_str().is_empty() => "~".to_string(),
            Some(relative) => format!("~/{}", relative.display()),
            None => path.display().to_string(),
        }
    };
    let program_path = reported(program_path);
    let cwd = reported(working_directory);
    let command = std::iter::once(server.program())
        .chain(server.arguments().iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let decision = spec.policy.decide(
        &spec.governed,
        &policy::Principal::agent(),
        &policy::Request::ShellSpawn {
            command: &command,
            program: server.program(),
            program_path: &program_path,
            credential_reads,
            args: arguments,
            cwd: &cwd,
        },
    );
    spec.recorder
        .record(crate::run::telemetry::EffectiveDecision::from_policy(
            r#"Box::Action::"shell:spawn""#,
            &program_path,
            &decision,
        ));
    match &decision {
        policy::Decision::Allow { .. } => Ok(()),
        policy::Decision::Deny { .. } => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("MCP server {:?} may not start: {decision}", server.name),
        )),
    }
}

/// Start one MCP server for this connection.
async fn start_mcp_server(
    spec: &ShellSpec,
    server: &crate::record::config::mcp::McpServer,
) -> io::Result<(
    crate::run::broker::mcp::RunningMcpServer,
    tokio::process::ChildStdout,
)> {
    // **`HOME` is the operator's, and the working directory is the box's.** The two answer
    // different questions, and passing the box home for both made the module's own stated purpose
    let home = spec
        .reach
        .reported_home()
        .unwrap_or_else(|| spec.reach.home_variable());
    // Every stdio server is contained: it is started as a streaming leaf through the trampoline,
    // confined and (unless it opted into native egress) with its egress forced to the parent
    // gateway. Its containment is confirmed to have reached `exec` before its streams are returned.
    // The uncontained child below is reached only when no leaf launcher is present (a box with no
    // stdio servers) or on a non-unix build, and by the tests that exercise that start directly.
    #[cfg(unix)]
    if let Some(launcher) = spec.mcp_leaf_launcher.as_deref()
        && launcher.contains(&server.name)
    {
        let boundary = launcher
            .prepare(&server.name)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let credential_reads = launcher.credential_reads(&server.name, Path::new(home));
        authorize_mcp_start(
            spec,
            server,
            boundary.program_identity(),
            boundary.arguments(),
            boundary.working_directory(),
            &credential_reads,
        )?;
        let shares_proc = boundary.shares_proc();
        let leaf = launcher
            .spawn(boundary)
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        // A server that shares the container's `/proc` can list the container's processes; record
        // it after `spawn` succeeds, like `egress:native` below, so a failed launch leaves none.
        if shares_proc {
            spec.recorder
                .record(crate::run::telemetry::EffectiveDecision::shared_proc(
                    server.name.clone(),
                ));
        }
        // A native-egress server bypasses the gateway, so its outbound traffic is never mediated,
        // credential-injected, or journaled. Record that downgrade at the enforcement point, naming
        // the server, so an operator can reconstruct that this server's egress is untracked — the
        // record is what makes the hole auditable rather than silent. It is emitted only after
        // `spawn` succeeds (the leaf reached `exec`), so a server that failed to start leaves no
        // false "egressed" entry.
        if launcher.is_native_egress(&server.name) {
            spec.recorder.record(
                crate::run::telemetry::EffectiveDecision::enforcement_permit(
                    "egress:native",
                    server.name.clone(),
                    "native-egress",
                ),
            );
        }
        return crate::run::broker::mcp::RunningMcpServer::from_leaf(server, leaf);
    }
    authorize_mcp_start(
        spec,
        server,
        Path::new(server.program()),
        server.arguments(),
        &spec.mcp_working_directory,
        &[],
    )?;
    // **NOT the box home.** The box home is the workload's own read-write grant, so starting an
    // uncontained child there let the agent plant the child's configuration with its own syscalls
    match spec.mcp_working_directory_handle.as_deref() {
        Some(directory) => {
            crate::run::broker::mcp::RunningMcpServer::start_in_opened_directory(
                server,
                Path::new(home),
                directory,
            )
            .await
        }
        None => {
            crate::run::broker::mcp::RunningMcpServer::start(
                server,
                Path::new(home),
                &spec.mcp_working_directory,
            )
            .await
        }
    }
}

#[cfg(test)]
fn poll_disconnect_with(
    mut operation: impl FnMut() -> io::Result<libc::c_short>,
) -> io::Result<bool> {
    loop {
        match operation() {
            Ok(revents) => return Ok(revents & (libc::POLLHUP | libc::POLLERR) != 0),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Probe the Shell, bind the broker's socket, and serve until told to stop.
struct McpHosting {
    /// The servers `mcp.toml` declared, as the record stored them.
    declared: Arc<Vec<crate::record::config::mcp::McpServer>>,
    /// Lazy discovery state shared by this run.
    registry: Arc<DiscoveryRegistry>,
    /// `private/mcp`, which the workload cannot write.
    working_directory: std::path::PathBuf,
    /// The validated directory identity.
    working_directory_handle: Arc<std::fs::File>,
    /// Starts a stdio server as a contained leaf. Present whenever the box declares any stdio
    /// server (every one is contained); `None` only when it declares none, and in that case no
    /// server ever reaches the uncontained start.
    leaf_launcher: Option<Arc<crate::run::hosted::McpLeafLauncher>>,
}

// Private thread entry point. It threads the box's serving inputs one per parameter, the
// same shape `host.rs`'s module doc already records as known debt; egress routing adds one
// more. Bundling them would hide which value each stage needs, so the count is accepted here.
#[allow(clippy::too_many_arguments)]
fn host(
    listener: std::os::unix::net::UnixListener,
    reach: Arc<Reach>,
    policy: Arc<PolicyEngine>,
    governed: GovernedBox,
    spawn_credentials: std::collections::BTreeMap<String, Vec<String>>,
    mcp_hosting: McpHosting,
    egress: Option<EgressRouting>,
    recorder: Arc<crate::run::telemetry::DecisionRecorder>,
    host_spawner: Option<strands_shell::os::HostSpawner>,
    ready: &std::sync::mpsc::Sender<io::Result<()>>,
    shutdown: oneshot::Receiver<()>,
) -> io::Result<()> {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(io::Error::other(format!(
                "create the broker runtime: {error}"
            ))));
            return Err(error);
        }
    };

    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        let spec = ShellSpec {
            command_timeout: SHELL_COMMAND_TIMEOUT,
            request_timeout: SERVE_REQUEST_TIMEOUT,
            reach,
            policy,
            governed,
            spawn_credentials,
            mcp: mcp_hosting.declared,
            mcp_registry: mcp_hosting.registry,
            mcp_working_directory: mcp_hosting.working_directory,
            mcp_working_directory_handle: Some(mcp_hosting.working_directory_handle),
            mcp_leaf_launcher: mcp_hosting.leaf_launcher,
            egress,
            recorder,
            host_spawner,
        };
        // Built once here and dropped immediately — a *probe*, not the serving Shell.
        if let Err(error) = spec.build() {
            let _ = ready.send(Err(error));
            return Err(io::Error::other("the Shell could not be built"));
        }

        let listener = match UnixListener::from_std(listener) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = ready.send(Err(error));
                return Err(io::Error::other("the broker socket could not be adopted"));
            }
        };

        // Bound and policed: the daemon may now publish itself.
        let _ = ready.send(Ok(()));

        serve(listener, Arc::new(spec), async {
            let _ = shutdown.await;
        })
        .await
    })
}

/// Accept clients until the listener fails, serving each on its own task.
async fn serve(
    listener: UnixListener,
    spec: Arc<ShellSpec>,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    let mut clients = JoinSet::new();
    let (stop_clients, _) = tokio::sync::watch::channel(false);
    tokio::pin!(shutdown);
    let outcome = loop {
        // At capacity, reap before accepting rather than queueing without bound.
        if clients.len() >= SERVE_CONNECTION_CAPACITY {
            tokio::select! {
                result = clients.join_next() => {
                    if let Some(result) = result {
                        report_client_result(result);
                    }
                }
                () = &mut shutdown => break Ok(()),
            }
            continue;
        }

        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let spec = Arc::clone(&spec);
                    // Read at accept, while the descriptor is still ours and before any frame is
                    // parsed, so the value cannot depend on anything the client said.
                    let peer = peer_pid(&stream);
                    // Each connection gets its OWN thread and its own current-thread runtime.
                    let shutdown = stop_clients.subscribe();
                    clients.spawn_blocking(move || {
                        run_connection_on_own_thread(stream, spec, peer, shutdown)
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => break Err(error),
            },
            completed = clients.join_next(), if !clients.is_empty() => {
                if let Some(result) = completed {
                    report_client_result(result);
                }
            }
            () = &mut shutdown => break Ok(()),
        }
    };
    stop_clients.send_replace(true);
    while let Some(result) = clients.join_next().await {
        report_client_result(result);
    }
    outcome
}

/// Drive one connection to completion on this thread, with its own current-thread runtime.
fn run_connection_on_own_thread(
    stream: UnixStream,
    spec: Arc<ShellSpec>,
    peer: Option<i32>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    // Take the stream out of this reactor so the new runtime can adopt it.
    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(true)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let local = tokio::task::LocalSet::new();
    runtime.block_on(async move {
        let outcome = local
            .run_until(async move {
                let stream = UnixStream::from_std(std_stream)?;
                handle_connection(stream, spec, peer, shutdown).await
            })
            .await;

        let _ = tokio::time::timeout(SERVE_IO_TIMEOUT, local).await;
        outcome
    })
}

/// Serve one connection: read its first frame, then speak the transport.
async fn handle_connection(
    mut stream: UnixStream,
    spec: Arc<ShellSpec>,
    peer: Option<i32>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    // Peeked untyped so an unaccepted version is *refused by name* rather than failing
    // `deny_unknown_fields` as an unexplained parse error.
    if *shutdown.borrow_and_update() {
        return Ok(());
    }
    let peeked = tokio::select! {
        peeked = tokio::time::timeout(
            SERVE_IO_TIMEOUT,
            read_frame::<serde_json::Value, _>(&mut stream),
        ) => peeked.map_err(|_| timed_out("read the first transport frame"))??,
        changed = shutdown.changed() => {
            let _ = changed;
            return Ok(());
        }
    };
    let Some(peeked) = peeked else {
        return Ok(());
    };

    let claimed = peeked
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    if claimed != u64::from(PROTOCOL_VERSION) {
        let (_reader, mut writer) = stream.into_split();
        let refusal = Frame {
            version: PROTOCOL_VERSION,
            program: 0,
            body: Body::Denied {
                kind: DeniedKind::VersionMismatch,
                reason: format!(
                    "unsupported protocol version {claimed}; this box speaks {PROTOCOL_VERSION}"
                ),
            },
        };
        return tokio::time::timeout(SERVE_IO_TIMEOUT, write_frame(&mut writer, &refusal))
            .await
            .map_err(|_| timed_out("write a version refusal"))?;
    }

    serve_transport(stream, spec, peeked, peer, shutdown).await
}

/// Serve one connection speaking the transport protocol
/// (docs/design/decisions.md#a-box-is-one-kernel-and-many-programs).
async fn serve_transport(
    stream: UnixStream,
    spec: Arc<ShellSpec>,
    first: serde_json::Value,
    peer: Option<i32>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let (mut reader, writer) = stream.into_split();
    // One writer task owning the socket's write half, because the reader and every running Call
    // both need to emit frames and two owners of one half is not expressible. This is also what
    let (frames, outbound) = tokio::sync::mpsc::channel::<OutboundFrame>(OUTBOUND_FRAME_DEPTH);
    let mut pump = ConnectionTask::new(tokio::task::spawn_local(pump_frames(writer, outbound)));
    // Where a finished Call hands back the Program it borrowed.
    let (finished, mut completions) =
        tokio::sync::mpsc::channel::<Completed>(MAX_PROGRAMS_PER_CONNECTION);
    let (mcp_finished, mut mcp_completions) =
        tokio::sync::mpsc::channel::<CompletedMcp>(MAX_PROGRAMS_PER_CONNECTION);
    // Every Program opened on this connection lives in this map, so returning from this function —
    // for any reason: a clean close, a protocol error, an idle timeout, a dropped peer — drops all
    let mut programs: HashMap<ProgramId, ProgramSlot> = HashMap::new();
    // A Program whose Call is in flight. Its id stays here so `Input`, `InputEof`, and `Signal`
    // still reach it, and so a second `Call` for it can be refused rather than queued.
    let mut running: HashMap<ProgramId, RunningCall> = HashMap::new();
    // Counts the Calls accepted on this connection, so each carries an identity its own
    // completion can be matched against. Never reused and never reset.
    let mut calls_accepted: u64 = 0;
    // Counts successful MCP opens for the same reason. A closed id can be opened again before its
    // old completion reaches this loop.
    let mut mcp_opened: u64 = 0;
    // Open Python Programs. A set rather than a map, because a stateless interpreter has nothing
    // per-Program to hold — what the id buys is that `Open`, `Close`, and the cap count it.
    let mut python: std::collections::HashSet<ProgramId> = std::collections::HashSet::new();
    // One entry per open MCP server. Separate from `programs` because an MCP server is a child
    // process rather than a Shell, and separate from `python` because it is stateful: the child
    let mut mcp: std::collections::HashMap<
        ProgramId,
        OpenMcpProgram<crate::run::broker::mcp::McpProgram>,
    > = std::collections::HashMap::new();
    let mut pending = Some(first);

    let outcome = async {
        loop {
            if *shutdown.borrow_and_update() {
                return Ok(());
            }
            // Either the peeked frame or the next one off the wire. A finished Call is taken first, so
            // its Program is back in `programs` before any frame naming it is handled.
            let frame: Frame = match pending.take() {
                Some(value) => serde_json::from_value(value)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
                None => loop {
                    tokio::select! {
                        biased;
                        // `recv` is cancel-safe, and a completion is never lost: the sender is held by
                        // a task that has already finished writing its output.
                        Some(done) = completions.recv() => {
                            // Only a Program still *registered* as running gets its slot back. A
                            // `Close` arriving mid-Call removes the id, and its Call task still
                            let is_current = running
                                .get(&done.id)
                                .is_some_and(|current| current.sequence == done.sequence);
                            if is_current {
                                running.remove(&done.id);
                                programs.insert(done.id, done.slot);
                                send(&frames, done.id, Body::Exit { status: done.status }).await?;
                            }
                        }
                        Some(done) = mcp_completions.recv() => {
                            let Some(mut completed) = remove_completed_mcp(&mut mcp, done) else {
                                continue;
                            };
                            return completed.join().await;
                        }
                        // The writer task failing is fatal: with no writer nothing can be answered.
                        result = pump.completed() => {
                            pump.disarm();
                            return match result {
                                Ok(inner) => inner,
                                Err(error) => Err(io::Error::other(error)),
                            };
                        }
                        changed = shutdown.changed() => {
                            let _ = changed;
                            return Ok(());
                        }
                        next = tokio::time::timeout(
                            idle_timeout(!mcp.is_empty()),
                            read_frame::<Frame, _>(&mut reader),
                        ) => {
                            match next.map_err(|_| timed_out("read a transport frame"))?? {
                                Some(frame) => break frame,
                                // A clean close ends the connection, which reaps every Program on it.
                                None => return Ok(()),
                            }
                        }
                    }
                },
            };

            if frame.version != PROTOCOL_VERSION {
                return Err(invalid_input(format!(
                    "unsupported transport version {}; expected {PROTOCOL_VERSION}",
                    frame.version
                )));
            }
            if frame.body.is_daemon_only() {
                // The peer pid is a *diagnostic* here, never an authorization input: it says which
                // program misbehaved so an operator can find it. `box_pinning_feasibility.rs` P3 proves
                return Err(invalid_input(format!(
                    "a transport client may not send a daemon-only frame{}",
                    describe_peer(peer)
                )));
            }

            let id = frame.program;
            match frame.body {
                Body::Open { mode: interpreter } => {
                    // Both questions span every kind — see `is_already_open` for what spanning only
                    // some of them cost.
                    if is_already_open(id, &programs, &running, &python, &mcp) {
                        return Err(invalid_input(format!(
                            "transport program {id} is already open"
                        )));
                    }
                    if open_program_count(&programs, &running, &python, &mcp)
                        >= MAX_PROGRAMS_PER_CONNECTION
                    {
                        // Denied rather than fatal: the programs already open keep serving.
                        deny(
                            &frames,
                            id,
                            DeniedKind::OverBudget,
                            &format!(
                                "at most {MAX_PROGRAMS_PER_CONNECTION} programs per connection"
                            ),
                        )
                        .await?;
                        continue;
                    }
                    // `Interpreter` is closed, so this match is exhaustive by construction and a new
                    // kind cannot be added without an exec-authority decision.
                    if let Interpreter::Python = interpreter {
                        python.insert(id);
                        continue;
                    }
                    // One MCP server, started outside the cage.
                    if let Interpreter::Mcp { server } = &interpreter {
                        let admitted =
                            match crate::run::broker::mcp::admit_server(&spec.mcp, server) {
                                Ok(admitted) => admitted,
                                Err(error) => {
                                    deny(&frames, id, DeniedKind::Internal, &error.to_string())
                                        .await?;
                                    continue;
                                }
                            };
                        if let Err(error) = spec.mcp_registry.admit_open(&admitted.name) {
                            deny(&frames, id, DeniedKind::Internal, &error.to_string()).await?;
                            return Ok(());
                        }
                        let next_mcp_opened = mcp_opened
                            .checked_add(1)
                            .ok_or_else(|| invalid_input("too many MCP programs were opened"))?;
                        match start_mcp_server(&spec, admitted).await {
                            Ok((running, stdout)) => {
                                let sequence = mcp_opened;
                                mcp_opened = next_mcp_opened;
                                let (program, completion) =
                                    crate::run::broker::mcp::McpProgram::spawn(
                                        running,
                                        stdout,
                                        Arc::clone(&spec.mcp_registry),
                                        frames.clone(),
                                        id,
                                        Arc::clone(&spec.policy),
                                        spec.governed.clone(),
                                        Arc::clone(&spec.recorder),
                                    );
                                let finished = mcp_finished.clone();
                                tokio::task::spawn_local(async move {
                                    let _ = completion.await;
                                    let _ = finished.send(CompletedMcp { id, sequence }).await;
                                });
                                mcp.insert(id, OpenMcpProgram { sequence, program });
                            }
                            Err(error) => {
                                // Denied rather than fatal: this program's failure, not the box's.
                                deny(&frames, id, DeniedKind::Internal, &error.to_string()).await?;
                            }
                        }
                        continue;
                    }
                    let opened = spec.backend().and_then(|backend| {
                        let shell = spec.build_on(Arc::clone(&backend), &spec.recorder)?;
                        Program::adopt(shell).map(|program| (backend, program))
                    });
                    match opened {
                        Ok((backend, (program, output, control))) => {
                            programs.insert(
                                id,
                                ProgramSlot {
                                    backend,
                                    program,
                                    output,
                                    control,
                                },
                            );
                        }
                        // This program's failure, not the box's.
                        Err(error) => {
                            deny(
                                &frames,
                                id,
                                DeniedKind::Internal,
                                &format!("the program could not be started: {error}"),
                            )
                            .await?;
                        }
                    }
                }
                Body::Call {
                    source,
                    correlation,
                } => {
                    let correlation = *correlation;
                    if mcp.contains_key(&id) {
                        deny(
                        &frames,
                        id,
                        DeniedKind::TransportError,
                        "an MCP program answers frames on its stdin rather than a Call; send Input",
                    )
                    .await?;
                        continue;
                    }
                    if python.contains(&id) {
                        let recorder = spec.recorder.for_request(correlation);
                        // Stateless, so it runs inline: there is no Program state a concurrent reader
                        // must reach, and no `Input`/`Signal` the interpreter can observe.
                        let outcome = crate::run::broker::python::run_python(
                            source,
                            &spec.reach,
                            &spec.policy,
                            &spec.governed,
                            spec.egress.as_ref(),
                            &recorder,
                        )
                        .await;
                        for (stream, text) in [
                            (Stream::Stdout, outcome.stdout),
                            (Stream::Stderr, outcome.stderr),
                        ] {
                            if !text.is_empty() {
                                send(
                                    &frames,
                                    id,
                                    Body::Output {
                                        stream,
                                        data: encode_payload(text.as_bytes()),
                                    },
                                )
                                .await?;
                            }
                        }
                        send(
                            &frames,
                            id,
                            Body::Exit {
                                status: outcome.status,
                            },
                        )
                        .await?;
                        continue;
                    }
                    if running.contains_key(&id) {
                        // One Call per Program at a time, like a shell's one foreground command.
                        deny(
                            &frames,
                            id,
                            DeniedKind::FlowControl,
                            "the program is already running a call",
                        )
                        .await?;
                        continue;
                    }
                    let Some(mut slot) = programs.remove(&id) else {
                        deny(
                            &frames,
                            id,
                            DeniedKind::TransportError,
                            &format!("transport program {id} is not open"),
                        )
                        .await?;
                        continue;
                    };
                    let recorder = spec.recorder.for_request(correlation.clone());
                    match spec.build_on(Arc::clone(&slot.backend), &recorder) {
                        Ok(shell) => slot.program.use_shell(shell),
                        Err(error) => {
                            programs.insert(id, slot);
                            deny(&frames, id, DeniedKind::Internal, &error.to_string()).await?;
                            continue;
                        }
                    }
                    // The control handle stays reachable, so `Input`, `InputEof`, and `Signal` still
                    // find this Program while its Call runs. Moving the slot into the task is what
                    let sequence = calls_accepted;
                    calls_accepted += 1;
                    running.insert(
                        id,
                        RunningCall {
                            sequence,
                            control: slot.control.clone(),
                        },
                    );
                    let frames = frames.clone();
                    let finished = finished.clone();
                    let request_timeout = spec.request_timeout;
                    tokio::task::spawn_local(async move {
                        let status = correlation
                            .scope(run_call(&mut slot, &source, id, request_timeout, &frames))
                            .await
                            .unwrap_or(BOUNDARY_FAILURE_STATUS);
                        // A send failure means the connection is already gone, which drops the slot
                        // and reaps the Program — the same outcome by a shorter path.
                        let _ = finished
                            .send(Completed {
                                id,
                                sequence,
                                slot,
                                status,
                            })
                            .await;
                    });
                }
                Body::Input { data } if mcp.contains_key(&id) => {
                    let Some(running) = mcp.get(&id) else {
                        return Err(invalid_input(format!("transport program {id} is not open")));
                    };
                    let bytes = decode_payload(&data)?;
                    if let Err(error) = running.program.input(bytes).await {
                        deny(
                            &frames,
                            id,
                            DeniedKind::Internal,
                            &format!("the MCP server stopped: {error}"),
                        )
                        .await?;
                    }
                }
                Body::InputEof if mcp.contains_key(&id) => {
                    if let Some(running) = mcp.get(&id) {
                        let _ = running.program.eof().await;
                    }
                }
                Body::Close if mcp.contains_key(&id) => {
                    if let Some(mut running) = mcp.remove(&id) {
                        running.program.stop_and_wait().await?;
                    }
                }
                // **A Python Program is asked about before `control_for`.** It lives in its own set, and
                // `control_for` consults only `programs` and `running` — so `Input` reported "not open"
                // for a Program that was open, and `InputEof` and `Signal` were dropped in silence,
                // leaving no way to interrupt a running script.
                Body::Input { .. } | Body::InputEof | Body::Signal { .. }
                    if python.contains(&id) =>
                {
                    deny(
                    &frames,
                    id,
                    DeniedKind::TransportError,
                    "a Python program reads no input and observes no signal: it runs one Call to \
                     completion and reports its output",
                )
                .await?;
                }
                Body::Input { data } => {
                    let bytes = decode_payload(&data)?;
                    // **Denied rather than fatal, and this one was measured.** An `Err` here takes the
                    // whole connection down, and that is exactly what happened to a denied MCP server:
                    let Some(control) = control_for(&programs, &running, id) else {
                        deny(
                            &frames,
                            id,
                            DeniedKind::TransportError,
                            &format!("transport program {id} is not open"),
                        )
                        .await?;
                        continue;
                    };
                    // A full stdin channel is the client outrunning its own program; report it rather
                    // than dropping the bytes silently.
                    if control.feed_stdin(&bytes).is_err() {
                        deny(
                            &frames,
                            id,
                            DeniedKind::FlowControl,
                            "the program is not reading input fast enough",
                        )
                        .await?;
                    }
                }
                Body::InputEof => {
                    if let Some(control) = control_for(&programs, &running, id) {
                        control.close_stdin();
                    }
                }
                Body::Signal { kind } => {
                    let SignalKind::Interrupt = kind;
                    if let Some(control) = control_for(&programs, &running, id) {
                        control.signal();
                    }
                }
                Body::Close => {
                    // Dropping the slot drops the Shell, releasing its descriptors and abandoning its
                    // background jobs — the Program level's whole lifetime.
                    programs.remove(&id);
                    python.remove(&id);
                    // A Program mid-Call cannot be dropped here: its slot lives in the Call task. Ask
                    // that Call to end and close its stdin, so the task finishes and drops the Shell
                    if let Some(current) = running.remove(&id) {
                        current.control.signal();
                        current.control.close_stdin();
                    }
                }
                // Refused above; unreachable, and kept explicit so a new daemon body cannot fall
                // through into the client path.
                Body::Output { .. } | Body::Exit { .. } | Body::Denied { .. } => {
                    return Err(invalid_input("a transport client may not send that frame"));
                }
            }
        }
    }
    .await;

    let cleanup = finish_mcp_servers(&mut mcp).await;
    drop(frames);
    let writer = finish_writer(&mut pump).await;
    first_error(outcome, cleanup, writer)
}

async fn finish_mcp_servers(
    servers: &mut HashMap<ProgramId, OpenMcpProgram<crate::run::broker::mcp::McpProgram>>,
) -> io::Result<()> {
    let mut first_error = None;
    for (_, mut running) in servers.drain() {
        if let Err(error) = running.program.stop_and_wait().await {
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn finish_writer(pump: &mut ConnectionTask<io::Result<()>>) -> io::Result<()> {
    let Some(mut task) = pump.task.take() else {
        return Ok(());
    };
    match tokio::time::timeout(SERVE_IO_TIMEOUT, &mut task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(io::Error::other(error)),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(timed_out("finish the transport writer"))
        }
    }
}

fn first_error(
    outcome: io::Result<()>,
    cleanup: io::Result<()>,
    writer: io::Result<()>,
) -> io::Result<()> {
    outcome.and(cleanup).and(writer)
}

/// One open Program plus the handle that reaches it while a Call runs.
fn is_already_open(
    id: ProgramId,
    programs: &HashMap<ProgramId, ProgramSlot>,
    running: &HashMap<ProgramId, RunningCall>,
    python: &std::collections::HashSet<ProgramId>,
    mcp: &std::collections::HashMap<ProgramId, OpenMcpProgram<crate::run::broker::mcp::McpProgram>>,
) -> bool {
    programs.contains_key(&id)
        || running.contains_key(&id)
        || python.contains(&id)
        || mcp.contains_key(&id)
}

/// How many Programs this connection holds, across every kind. See [`is_already_open`].
fn open_program_count(
    programs: &HashMap<ProgramId, ProgramSlot>,
    running: &HashMap<ProgramId, RunningCall>,
    python: &std::collections::HashSet<ProgramId>,
    mcp: &std::collections::HashMap<ProgramId, OpenMcpProgram<crate::run::broker::mcp::McpProgram>>,
) -> usize {
    programs.len() + running.len() + python.len() + mcp.len()
}

struct ProgramSlot {
    backend: Arc<dyn strands_shell::os::Kernel>,
    program: Program,
    output: ProgramOutput,
    control: ProgramControl,
}

/// A finished Call handing its Program back to the reader.
struct Completed {
    id: ProgramId,
    /// Which Call finished. Compared against the Call now in flight at `id`, so a stale
    /// completion cannot be mistaken for it — see `RunningCall::sequence`.
    sequence: u64,
    slot: ProgramSlot,
    status: i32,
}

/// One in-flight Call: which Call it is, and the handle that reaches its Program while it runs.
struct RunningCall {
    /// Which Call this is on this connection, counted from zero and never reused.
    sequence: u64,
    control: ProgramControl,
}

struct OpenMcpProgram<T> {
    sequence: u64,
    program: T,
}

struct CompletedMcp {
    id: ProgramId,
    sequence: u64,
}

fn remove_completed_mcp<T>(
    programs: &mut HashMap<ProgramId, OpenMcpProgram<T>>,
    completed: CompletedMcp,
) -> Option<T> {
    let is_current = programs
        .get(&completed.id)
        .is_some_and(|current| current.sequence == completed.sequence);
    is_current
        .then(|| programs.remove(&completed.id))
        .flatten()
        .map(|current| current.program)
}

pub(super) struct OutboundFrame {
    pub(super) frame: Frame,
    pub(super) release: Option<crate::run::broker::mcp::DiscoveryReleaseGuard>,
}

/// Write every outbound frame, in the order it was queued.
async fn pump_frames<W>(
    writer: W,
    outbound: tokio::sync::mpsc::Receiver<OutboundFrame>,
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    pump_frames_with_timeout(writer, outbound, SERVE_IO_TIMEOUT).await
}

async fn pump_frames_with_timeout<W>(
    mut writer: W,
    mut outbound: tokio::sync::mpsc::Receiver<OutboundFrame>,
    io_timeout: Duration,
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;

    while let Some(outbound) = outbound.recv().await {
        let written = tokio::time::timeout(io_timeout, async {
            write_frame(&mut writer, &outbound.frame).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| timed_out("write and flush a transport frame"))?;
        drop(outbound.release);
        written?;
    }
    Ok(())
}

/// The control handle for a Program, whether it is idle or running a Call.
fn control_for<'a>(
    programs: &'a HashMap<ProgramId, ProgramSlot>,
    running: &'a HashMap<ProgramId, RunningCall>,
    id: ProgramId,
) -> Option<&'a ProgramControl> {
    programs
        .get(&id)
        .map(|slot| &slot.control)
        .or_else(|| running.get(&id).map(|current| &current.control))
}

/// Report a transport refusal, which never carries a policy decision.
async fn deny(
    frames: &tokio::sync::mpsc::Sender<OutboundFrame>,
    id: ProgramId,
    kind: DeniedKind,
    reason: &str,
) -> io::Result<()> {
    send(
        frames,
        id,
        Body::Denied {
            kind,
            reason: reason.to_string(),
        },
    )
    .await
}

/// The connection's writer is gone, so nothing can be answered.
fn closed_transport() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the transport writer closed")
}

/// Drive one Call, forwarding output as it is produced.
async fn run_call(
    slot: &mut ProgramSlot,
    command: &str,
    id: ProgramId,
    request_timeout: Duration,
    frames: &tokio::sync::mpsc::Sender<OutboundFrame>,
) -> io::Result<i32> {
    let deadline = tokio::time::Instant::now() + request_timeout;
    let control = slot.control.clone();

    // Split the borrows: the Call takes `&mut program`, the chunker takes `&mut output`. Separate
    // fields, so both are live at once — which is why `Program` and `ProgramOutput` are different
    let ProgramSlot {
        program, output, ..
    } = slot;
    let mut call = Box::pin(program.call(command));
    let mut over_budget = false;

    // Drained inside the loop, so a chunk reaches the client while the Call is still running.
    let outcome = loop {
        tokio::select! {
            outcome = &mut call => break Some(outcome),
            chunk = output.next_chunk(), if !over_budget => {
                let mut pending = Vec::new();
                if output.admit(chunk, &mut pending) == DrainOutcome::CapReached {
                    over_budget = true;
                    deny(frames, id, DeniedKind::OverBudget, OUTPUT_BUDGET_SPENT).await?;
                }
                flush(frames, id, &mut pending).await?;
            }
            // Poll for a signal rather than awaiting it, because the flag is not a future.
            _ = tokio::time::sleep(SIGNAL_POLL_INTERVAL) => {
                // Dropping the Call future is the stop: `select!` abandons the losing branch, so
                // leaving this loop releases it.
                if control.is_cancelled() {
                    break None;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                deny(frames, id, DeniedKind::Timeout, "the call exceeded its deadline").await?;
                break None;
            }
        }
    };
    drop(call);

    // Whatever the program wrote after the last poll. `drain_ready` rather than awaiting: the
    // senders live on the Shell, which outlives the Call, so the channels never reach end-of-stream
    let mut pending = Vec::new();
    while let Some(chunk) = output.drain_ready() {
        if over_budget {
            break;
        }
        if output.admit(chunk, &mut pending) == DrainOutcome::CapReached {
            over_budget = true;
            deny(frames, id, DeniedKind::OverBudget, OUTPUT_BUDGET_SPENT).await?;
        }
    }
    flush(frames, id, &mut pending).await?;

    let Some(outcome) = outcome else {
        // Interrupted or expired: the boundary status says which side ended it.
        return Ok(BOUNDARY_FAILURE_STATUS);
    };
    Ok(outcome.status)
}

/// Write every buffered chunk as an `Output` frame, oldest first.
async fn flush(
    frames: &tokio::sync::mpsc::Sender<OutboundFrame>,
    id: ProgramId,
    pending: &mut Vec<Chunk>,
) -> io::Result<()> {
    for chunk in pending.drain(..) {
        send(
            frames,
            id,
            Body::Output {
                stream: chunk.stream,
                data: encode_payload(&chunk.data),
            },
        )
        .await?;
    }
    Ok(())
}

/// Write one frame, bounded like every other write to an untrusted peer.
async fn send(
    frames: &tokio::sync::mpsc::Sender<OutboundFrame>,
    id: ProgramId,
    body: Body,
) -> io::Result<()> {
    frames
        .send(OutboundFrame {
            frame: Frame {
                version: PROTOCOL_VERSION,
                program: id,
                body,
            },
            release: None,
        })
        .await
        .map_err(|_| closed_transport())
}

/// The pid of the process on the other end, as the kernel reports it.
#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    use std::os::fd::AsRawFd as _;

    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `length` bytes into `pid`, which is exactly that size, and
    // the descriptor is owned by `stream` for the duration of the call.
    let outcome = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast::<libc::c_void>(),
            &raw mut length,
        )
    };
    (outcome != -1).then_some(pid)
}

/// The Linux spelling: `SO_PEERCRED` at `SOL_SOCKET`, yielding pid, uid, and gid.
#[cfg(target_os = "linux")]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    use std::os::fd::AsRawFd as _;

    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `length` bytes into `credentials`, which is exactly that
    // size, and the descriptor is owned by `stream` for the duration of the call.
    let outcome = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast::<libc::c_void>(),
            &raw mut length,
        )
    };
    (outcome != -1).then_some(credentials.pid)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn peer_pid(_stream: &UnixStream) -> Option<i32> {
    None
}

/// Render a peer for a diagnostic, or nothing when it is unknown.
fn describe_peer(peer: Option<i32>) -> String {
    peer.map(|pid| format!(" (peer pid {pid})"))
        .unwrap_or_default()
}

/// Report one client's outcome.
fn report_client_result(result: Result<io::Result<()>, JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("strands-box broker: rejected client: {error}"),
        Err(error) => eprintln!("strands-box broker: client task failed: {error}"),
    }
}

fn timed_out(operation: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{operation} timed out"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::broker::protocol::Stream;

    use std::path::{Path, PathBuf};

    /// **The native-egress downgrade is recorded only after `spawn` succeeds.** A server that fails
    /// to launch never egressed, so it must leave no `egress:native` record (the record
    /// exists to keep the hole *honest*). The contained-leaf branch needs a real leaf to
    /// exercise at runtime — there is no launcher seam to stub — so this pins the source order: in
    /// `start_mcp_server`, the `recorder.record(...)` for `egress:native` must appear *after* the
    /// `launcher.spawn(...)` call, so a future reorder that emits it before the `?` fails here.
    #[test]
    fn the_native_egress_record_is_emitted_after_launch_succeeds() {
        let src = include_str!("host.rs");
        let launch = src
            .find(".spawn(boundary)")
            .expect("start_mcp_server calls launcher.spawn(boundary)");
        let record = src
            .find("\"egress:native\"")
            .expect("start_mcp_server records the egress:native downgrade");
        assert!(
            record > launch,
            "the egress:native record must be emitted after spawn() returns Ok, so a failed \
             launch leaves no false downgrade record"
        );
    }

    /// **A shared-`/proc` MCP server is recorded only after `spawn` succeeds**, for the same reason
    /// as `egress:native`: a server that never started never listed the container's processes.
    #[test]
    fn the_shared_proc_record_is_emitted_after_launch_succeeds() {
        let src = include_str!("host.rs");
        let launch = src
            .find(".spawn(boundary)")
            .expect("start_mcp_server calls launcher.spawn(boundary)");
        // Split, so this test's own text is not what `find` matches.
        let record = src
            .find(concat!("EffectiveDecision::", "shared_proc("))
            .expect("start_mcp_server records a shared /proc");
        assert!(
            record > launch,
            "the proc:shared record must be emitted after spawn() returns Ok"
        );
    }

    use policy::{Policy, Principal};

    fn runtime() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        (runtime, tokio::task::LocalSet::new())
    }

    struct GatedFlushWriter {
        flushes: usize,
        entered: Option<oneshot::Sender<()>>,
        release: oneshot::Receiver<io::Result<()>>,
    }

    impl tokio::io::AsyncWrite for GatedFlushWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            self.flushes += 1;
            if self.flushes == 1 {
                return std::task::Poll::Ready(Ok(()));
            }
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            match std::future::Future::poll(std::pin::Pin::new(&mut self.release), context) {
                std::task::Poll::Ready(Ok(outcome)) => std::task::Poll::Ready(outcome),
                std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the flush gate closed",
                ))),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct GuardedDiscovery {
        _marker: tempfile::TempDir,
        _spec: Arc<ShellSpec>,
        program: crate::run::broker::mcp::McpProgram,
        completion: tokio::sync::watch::Receiver<crate::run::broker::mcp::CompletionOutcome>,
        frame: OutboundFrame,
    }

    async fn guarded_discovery_frame() -> GuardedDiscovery {
        let marker = tempfile::tempdir().expect("marker");
        let script = r#"while IFS= read -r frame; do
case "$frame" in
  *'"method":"initialize"'*)
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"test-mcp","version":"1"}}}'
    ;;
  *'"method":"tools/list"'*)
    id=$(printf '%s\n' "$frame" | sed -nE 's/.*"id":("[^"]*"|[0-9]+).*/\1/p')
    printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"PrivateSearch","inputSchema":{"type":"object"}}]}}\n' "$id"
    ;;
esac
done"#;
        let spec = mcp_spec_with_server(
            marker.path(),
            vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()],
        );
        let (running, stdout) = start_mcp_server(&spec, &spec.mcp[0])
            .await
            .expect("the MCP server starts");
        let (frames, mut output) =
            tokio::sync::mpsc::channel::<OutboundFrame>(OUTBOUND_FRAME_DEPTH);
        let (program, _completion) = crate::run::broker::mcp::McpProgram::spawn(
            running,
            stdout,
            Arc::clone(&spec.mcp_registry),
            frames,
            1,
            Arc::clone(&spec.policy),
            spec.governed.clone(),
            Arc::clone(&spec.recorder),
        );
        let completion = spec.mcp_registry.completion();

        program
            .input(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n"
                    .to_vec(),
            )
            .await
            .expect("send initialize");
        let initialized = tokio::time::timeout(Duration::from_secs(2), output.recv())
            .await
            .expect("initialize response deadline")
            .expect("initialize response");
        assert!(initialized.release.is_none());
        program
            .input(
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n"
                    .to_vec(),
            )
            .await
            .expect("send initialized");
        program
            .input(
                b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n"
                    .to_vec(),
            )
            .await
            .expect("send tools/list");
        let frame = loop {
            let frame = tokio::time::timeout(Duration::from_secs(2), output.recv())
                .await
                .expect("discovery response deadline")
                .expect("discovery response");
            if frame.release.is_some() {
                break frame;
            }
        };

        GuardedDiscovery {
            _marker: marker,
            _spec: spec,
            program,
            completion,
            frame,
        }
    }

    fn gated_frame_pump(
        frame: OutboundFrame,
        io_timeout: Duration,
    ) -> (
        tokio::task::JoinHandle<io::Result<()>>,
        oneshot::Receiver<()>,
        oneshot::Sender<io::Result<()>>,
    ) {
        let (flush_entered, entered) = oneshot::channel();
        let (release_flush, flush_released) = oneshot::channel();
        let writer = GatedFlushWriter {
            flushes: 0,
            entered: Some(flush_entered),
            release: flush_released,
        };
        let (queued, outbound) = tokio::sync::mpsc::channel(1);
        queued
            .try_send(frame)
            .unwrap_or_else(|_| panic!("queue discovery response"));
        drop(queued);
        (
            tokio::task::spawn_local(pump_frames_with_timeout(writer, outbound, io_timeout)),
            entered,
            release_flush,
        )
    }

    async fn wait_for_gated_flush(entered: oneshot::Receiver<()>) {
        tokio::time::timeout(Duration::from_secs(2), entered)
            .await
            .expect("the writer reaches flush before the test deadline")
            .expect("the writer reaches flush");
    }

    fn assert_discovery_completion_pending(
        completion: &mut tokio::sync::watch::Receiver<crate::run::broker::mcp::CompletionOutcome>,
    ) {
        assert!(matches!(
            *completion.borrow_and_update(),
            crate::run::broker::mcp::CompletionOutcome::Pending
        ));
    }

    async fn wait_for_discovery_completion(
        completion: &mut tokio::sync::watch::Receiver<crate::run::broker::mcp::CompletionOutcome>,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(
                    *completion.borrow_and_update(),
                    crate::run::broker::mcp::CompletionOutcome::Finished
                ) {
                    break;
                }
                completion
                    .changed()
                    .await
                    .expect("completion remains observable");
            }
        })
        .await
        .expect("the terminal writer outcome releases the completion barrier");
    }

    /// Open a policy from literal text, for tests that need specific rules.
    fn open_policy_text(text: &str) -> Arc<PolicyEngine> {
        Arc::new(crate::test_support::open_policy(vec![Policy {
            origin: PathBuf::from("worker-lifetime-test.dw"),
            text: text.to_string(),
        }]))
    }

    /// The command deadline used by tests that must observe a timeout.
    const SHORT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);

    /// A spec for the connection-lifetime tests.
    fn connection_spec(marker_directory: &Path) -> Arc<ShellSpec> {
        spec_with(
            marker_directory,
            SHELL_COMMAND_TIMEOUT,
            SERVE_REQUEST_TIMEOUT,
        )
    }

    /// A spec for tests that must observe the Shell command deadline.
    fn short_connection_spec(marker_directory: &Path) -> Arc<ShellSpec> {
        spec_with(
            marker_directory,
            SHORT_COMMAND_TIMEOUT,
            SERVE_REQUEST_TIMEOUT,
        )
    }

    fn mcp_spec_with_server(marker_directory: &Path, command: Vec<String>) -> Arc<ShellSpec> {
        mcp_spec_with_policy(
            marker_directory,
            command,
            r#"
                permit (principal, action == Box::Action::"mcp:call", resource);
                permit (principal, action == Box::Action::"shell:spawn", resource);
                forbid (principal, action == Box::Action::"mcp:call", resource)
                when {
                    context.input has tool && context.input.tool == "PrivateSearch"
                };
            "#,
        )
    }

    fn mcp_spec_with_policy(
        marker_directory: &Path,
        command: Vec<String>,
        policy: &str,
    ) -> Arc<ShellSpec> {
        let schema = policy::generate_mcp_schema(
            "test-mcp",
            r#"{
                "result": {
                    "tools": [{
                        "name": "PrivateSearch",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "isDeep": {"type": "boolean"},
                                "query": {"type": "string"}
                            },
                            "required": ["query"]
                        }
                    }]
                }
            }"#,
        )
        .expect("MCP schema generates");
        let mcp = Arc::new(vec![crate::record::config::mcp::McpServer {
            name: "test-mcp".to_string(),
            command,
        }]);
        let mcp_registry = crate::run::broker::mcp::DiscoveryRegistry::testing(&mcp);
        Arc::new(ShellSpec {
            command_timeout: SHELL_COMMAND_TIMEOUT,
            request_timeout: SERVE_REQUEST_TIMEOUT,
            reach: Arc::new(
                Reach::over(
                    &marker_directory
                        .canonicalize()
                        .expect("the marker directory resolves"),
                    None,
                    None,
                )
                .expect("the marker directory is reachable"),
            ),
            mcp,
            mcp_registry,
            mcp_working_directory: marker_directory.to_path_buf(),
            mcp_working_directory_handle: None,
            mcp_leaf_launcher: None,
            policy: Arc::new(crate::test_support::open_policy_with_mcp_schemas(
                vec![Policy {
                    origin: PathBuf::from("mcp-broker-test.dw"),
                    text: policy.to_string(),
                }],
                &[schema],
            )),
            governed: GovernedBox::assigned("codex"),
            spawn_credentials: Default::default(),
            egress: None,
            recorder: crate::run::telemetry::DecisionRecorder::discarding(),
            host_spawner: None,
        })
    }

    /// An uncontained start runs only when `shell:spawn` permits the declared program and its
    /// arguments.
    #[test]
    fn an_uncontained_start_is_decided_on_its_program_and_arguments() {
        let markers = tempfile::tempdir().expect("marker directory");
        let started = markers.path().join("started");
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(": > {}; exec cat", started.display()),
        ];
        let forbid = r#"
            permit (principal, action == Box::Action::"shell:spawn", resource);
            @id("no_marker_start")
            forbid (principal, action == Box::Action::"shell:spawn", resource)
            when {
                context.input.program == "/bin/sh" &&
                context.input.program_path == "/bin/sh" &&
                context.input has arg1 && context.input.arg1 == "-c" &&
                context.input.arg_count == 2
            };
        "#;
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let spec = mcp_spec_with_policy(markers.path(), command.clone(), forbid);
        let server = spec.mcp[0].clone();
        let refused = runtime.block_on(start_mcp_server(&spec, &server));
        let error = refused.err().expect("the forbidden start is refused");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("no_marker_start"), "{error}");
        std::thread::sleep(Duration::from_millis(200));
        assert!(!started.exists(), "a refused server never runs");

        let permit = r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#;
        let spec = mcp_spec_with_policy(markers.path(), command, permit);
        let server = spec.mcp[0].clone();
        let (running, _stdout) = runtime
            .block_on(start_mcp_server(&spec, &server))
            .expect("the permitted start runs");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !started.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(started.exists(), "the permitted server ran");
        drop(running);
    }

    /// A connection spec with both deadlines chosen. A timeout test sets `request_timeout` below
    /// `command_timeout` so the broker's backstop fires before the Shell's own bound.
    fn spec_with(
        marker_directory: &Path,
        command_timeout: Duration,
        request_timeout: Duration,
    ) -> Arc<ShellSpec> {
        Arc::new(ShellSpec {
            command_timeout,
            request_timeout,
            reach: Arc::new(
                Reach::over(
                    // Canonicalized because `Reach::over` refuses a home with a second
                    // spelling, and on macOS `$TMPDIR` is reached through `/private`.
                    &marker_directory
                        .canonicalize()
                        .expect("the marker directory resolves"),
                    // No shared home: these tests are about connection lifetime, so the marker
                    // directory alone is the reachable set.
                    None,
                    // No workspace either, so the marker directory is also the working directory.
                    None,
                )
                .expect("the marker directory is reachable"),
            ),
            // No MCP servers: these tests are about connection lifetime.
            mcp: Arc::new(Vec::new()),
            mcp_registry: crate::run::broker::mcp::DiscoveryRegistry::testing(&[]),
            // These tests declare no MCP server, so nothing is started from it. The marker
            // directory stands in, so the field names a real path rather than an empty one.
            mcp_working_directory: marker_directory.to_path_buf(),
            mcp_working_directory_handle: None,
            mcp_leaf_launcher: None,
            // A permissive policy, because these tests are about connection *lifetime*.
            policy: open_policy_text(
                r#"permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
                   permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
                   permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);"#,
            ),
            // The box a request on this socket is judged as. Production takes it from the box
            // root; a test names the same thing the fixture's rules are written for.
            governed: GovernedBox::assigned("codex"),
            spawn_credentials: Default::default(),
            // These tests exercise connection lifetime, not egress; the Shell's network stays
            // off, exactly as it was before egress routing existed.
            egress: None,
            recorder: crate::run::telemetry::DecisionRecorder::discarding(),
            host_spawner: None,
        })
    }

    /// Bind a listener, serve it with the real `serve`, and hand back its path.
    fn serving_socket(spec: Arc<ShellSpec>) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("socket directory");
        let socket = directory.path().join("box.sock");
        let listener = UnixListener::bind(&socket).expect("bind the test Shell socket");
        tokio::task::spawn_local(
            async move { serve(listener, spec, std::future::pending()).await },
        );
        (directory, socket)
    }

    #[test]
    fn peer_poll_retries_only_interrupted_errors() {
        let mut attempts = 0;
        let disconnected = poll_disconnect_with(|| {
            attempts += 1;
            if attempts == 1 {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(libc::POLLHUP)
            }
        })
        .expect("the second poll succeeds");

        assert!(disconnected, "POLLHUP must report a disconnected peer");
        assert_eq!(attempts, 2, "the interrupted poll must be retried once");

        let mut other_attempts = 0;
        let error = poll_disconnect_with(|| {
            other_attempts += 1;
            if other_attempts == 1 {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(libc::POLLHUP)
            }
        })
        .expect_err("a non-interrupted poll error must be returned");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            other_attempts, 1,
            "a non-interrupted poll error must not be retried"
        );
    }

    /// Open one Program and submit one Call on an un-split stream.
    async fn open_and_call(stream: &mut UnixStream, command: &str) {
        for body in [
            Body::Open {
                mode: Interpreter::Shell,
            },
            Body::Call {
                correlation: Default::default(),
                source: command.to_string(),
            },
        ] {
            write_frame(
                stream,
                &Frame {
                    version: PROTOCOL_VERSION,
                    program: 1,
                    body,
                },
            )
            .await
            .expect("write a transport frame");
        }
    }

    /// One Program, one Call, over a fresh connection: what an alias does.
    async fn submit(socket: &Path, command: &str) -> (String, i32) {
        let (mut reader, mut writer) = transport(socket).await;
        put(
            &mut writer,
            1,
            Body::Open {
                mode: Interpreter::Shell,
            },
        )
        .await;
        put(
            &mut writer,
            1,
            Body::Call {
                correlation: Default::default(),
                source: command.to_string(),
            },
        )
        .await;
        collect(&mut reader, 1).await
    }

    async fn wait_for_marker(path: &Path) {
        // Generous, because this only bounds a hang: coverage instrumentation under Package
        // Builder makes a 2 s budget for the Shell build plus first command too tight, so the
        // test flaked there while passing locally.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "Shell command did not create {}",
                path.display()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // ── Connection lifetime ───────────────────────────────────────────────────

    /// A client that abandons a running command costs only its own connection.
    #[test]
    fn an_abandoned_command_does_not_stop_the_boundary() {
        let marker_directory = tempfile::tempdir().expect("marker directory");
        let marker = marker_directory.path().join("started");
        let spec = connection_spec(marker_directory.path());
        let (runtime, local) = runtime();

        runtime.block_on(local.run_until(async {
            let (_directory, socket) = serving_socket(spec);

            // Abandon a command that is provably running: the marker proves execution began,
            // so this exercises the mid-command path rather than a pre-execution drop.
            let mut abandoned = UnixStream::connect(&socket).await.expect("connect");
            open_and_call(
                &mut abandoned,
                "printf started > \"$HOME/started\"; sleep 5",
            )
            .await;
            wait_for_marker(&marker).await;
            drop(abandoned);

            // The boundary must still answer, on a new connection.
            let response =
                tokio::time::timeout(Duration::from_secs(10), submit(&socket, "printf recovered"))
                    .await
                    .expect("the boundary survives an abandoned command");
            assert_eq!(response.0, "recovered");
        }));
    }

    /// A Call's status is returned only after its write is on the host.
    #[test]
    fn a_calls_write_is_on_the_host_when_its_status_returns() {
        const LENGTH: usize = 10 * 1024 * 1024 - 1;
        let marker_directory = tempfile::tempdir().expect("marker directory");
        let destination = marker_directory.path().join("dst");
        std::fs::write(marker_directory.path().join("src"), vec![b'x'; LENGTH])
            .expect("seed source");
        let spec = connection_spec(marker_directory.path());
        let (runtime, local) = runtime();

        runtime.block_on(local.run_until(async {
            let (_directory, socket) = serving_socket(spec);
            let (_, status) = submit(&socket, "cat \"$HOME/src\" > \"$HOME/dst\"").await;
            assert_eq!(status, 0, "the write succeeds");
            assert_eq!(
                std::fs::metadata(&destination)
                    .map(|m| m.len())
                    .unwrap_or(0),
                LENGTH as u64,
                "the host file holds every byte when the status returns"
            );
            let (seen, status) = submit(&socket, "wc -c < \"$HOME/dst\"").await;
            assert_eq!(status, 0, "the read succeeds");
            assert_eq!(
                seen.trim().parse::<usize>().expect("a byte count"),
                LENGTH,
                "the next Call sees every byte the previous Call wrote"
            );
        }));
    }

    /// A later request does not inherit an abandoned command's session state.
    #[test]
    fn a_later_request_does_not_inherit_abandoned_session_state() {
        let marker_directory = tempfile::tempdir().expect("marker directory");
        let marker = marker_directory.path().join("exported");
        let spec = connection_spec(marker_directory.path());
        let (runtime, local) = runtime();

        runtime.block_on(local.run_until(async {
            let (_directory, socket) = serving_socket(spec);

            let mut abandoned = UnixStream::connect(&socket).await.expect("connect");
            open_and_call(
                &mut abandoned,
                "export ABANDONED=leaked; printf x > \"$HOME/exported\"; sleep 5",
            )
            .await;
            wait_for_marker(&marker).await;
            drop(abandoned);

            let response = tokio::time::timeout(
                Duration::from_secs(10),
                submit(&socket, "printf 'abandoned=%s' \"$ABANDONED\""),
            )
            .await
            .expect("the boundary answers");
            assert_eq!(
                response.0, "abandoned=",
                "the export from the abandoned command must not survive"
            );
        }));
    }

    /// An expired deadline is reported to the client, and the boundary keeps serving.
    #[test]
    fn an_expired_command_is_reported_and_the_boundary_keeps_serving() {
        let marker_directory = tempfile::tempdir().expect("marker directory");
        let spec = short_connection_spec(marker_directory.path());
        let (runtime, local) = runtime();

        runtime.block_on(local.run_until(async {
            let (_directory, socket) = serving_socket(spec);

            // The vendored Shell's own `timeout` stops this and reports non-zero; the point
            // is that the client is answered at all rather than left waiting.
            let response = tokio::time::timeout(
                SHORT_COMMAND_TIMEOUT + Duration::from_secs(10),
                submit(&socket, "sleep 3600"),
            )
            .await
            .expect("the client is told rather than left hanging");
            assert_ne!(
                response.1, 0,
                "an expired command must not report success: {response:?}"
            );

            let alive = tokio::time::timeout(
                Duration::from_secs(10),
                submit(&socket, "printf still-serving"),
            )
            .await
            .expect("the boundary survives a timeout");
            assert_eq!(alive.0, "still-serving");
        }));
    }

    /// The broker's own deadline refuses a Call with `timeout`, distinct from the Shell's
    /// `command_timeout` (which reports an `Exit`).
    #[test]
    fn a_call_that_outlives_the_broker_deadline_is_denied_with_timeout() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let spec = spec_with(
                marker.path(),
                Duration::from_secs(10),
                Duration::from_millis(100),
            );
            let (_dir, socket) = serving_socket(spec);
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "sleep 5".to_string(),
                },
            )
            .await;

            let frame = read_frame::<Frame, _>(&mut reader)
                .await
                .expect("read")
                .expect("a frame");
            match frame.body {
                Body::Denied { kind, reason } => {
                    assert_eq!(
                        kind,
                        DeniedKind::Timeout,
                        "the broker's own deadline is a timeout"
                    );
                    assert!(
                        reason.contains("deadline"),
                        "the refusal must name the deadline: {reason:?}"
                    );
                }
                other => panic!("expected a timeout refusal, got {other:?}"),
            }
        }));
    }

    /// A client that closes before sending anything costs nothing and is not an error.
    #[test]
    fn a_connection_that_sends_nothing_builds_no_shell() {
        let marker_directory = tempfile::tempdir().expect("marker directory");
        let marker = marker_directory.path().join("must-not-exist");
        let spec = connection_spec(marker_directory.path());
        let (runtime, local) = runtime();

        runtime.block_on(local.run_until(async {
            let (_directory, socket) = serving_socket(spec);

            // Connect and close with no frame written.
            drop(UnixStream::connect(&socket).await.expect("connect"));

            // A live request proves the boundary survived the empty one.
            let response =
                tokio::time::timeout(Duration::from_secs(10), submit(&socket, "printf alive"))
                    .await
                    .expect("the boundary answers the live request");
            assert_eq!(response.0, "alive");
            assert!(
                !marker.exists(),
                "an empty connection must not have executed anything"
            );
        }));
    }

    /// A request naming an unknown protocol version is refused without building a Shell.
    #[test]
    fn an_unknown_protocol_version_is_refused() {
        let marker_directory = tempfile::tempdir().expect("marker directory");
        let spec = connection_spec(marker_directory.path());
        let (runtime, local) = runtime();

        runtime.block_on(local.run_until(async {
            let (_directory, socket) = serving_socket(spec);

            let mut stream = UnixStream::connect(&socket).await.expect("connect");
            write_frame(
                &mut stream,
                &Frame {
                    version: 99,
                    program: 1,
                    body: Body::Open {
                        mode: Interpreter::Shell,
                    },
                },
            )
            .await
            .expect("write the frame");
            let frame = read_frame::<Frame, _>(&mut stream)
                .await
                .expect("read the refusal")
                .expect("a frame");

            // Refused *by name*, which is the whole reason `version` survives: without it an
            // older client's frame fails `deny_unknown_fields` and the socket just closes.
            match frame.body {
                Body::Denied { kind, reason } => {
                    assert_eq!(
                        kind,
                        DeniedKind::VersionMismatch,
                        "a version mismatch must carry the version_mismatch code"
                    );
                    assert!(
                        reason.contains("unsupported protocol version 99")
                            && reason.contains(&PROTOCOL_VERSION.to_string()),
                        "the refusal must name both versions: {reason:?}"
                    );
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
            // Nothing ran: the connection was refused before a Program existed.
        }));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Transport: many Programs per connection, state across Calls,

    /// Open a transport connection and return its halves.
    async fn transport(
        socket: &Path,
    ) -> (
        tokio::net::unix::OwnedReadHalf,
        tokio::net::unix::OwnedWriteHalf,
    ) {
        UnixStream::connect(socket)
            .await
            .expect("connect")
            .into_split()
    }

    async fn put(writer: &mut tokio::net::unix::OwnedWriteHalf, program: ProgramId, body: Body) {
        write_frame(
            writer,
            &Frame {
                version: PROTOCOL_VERSION,
                program,
                body,
            },
        )
        .await
        .expect("write a transport frame");
    }

    /// Read frames until this Program exits, returning its stdout and status.
    async fn collect(
        reader: &mut tokio::net::unix::OwnedReadHalf,
        program: ProgramId,
    ) -> (String, i32) {
        let mut out = Vec::new();
        loop {
            let frame = read_frame::<Frame, _>(reader)
                .await
                .expect("read a transport frame")
                .expect("the daemon must answer before closing");
            assert_eq!(frame.program, program, "a frame named another program");
            match frame.body {
                Body::Output { data, .. } => {
                    out.extend_from_slice(&decode_payload(&data).expect("valid payload"));
                }
                Body::Exit { status } => {
                    return (String::from_utf8_lossy(&out).into_owned(), status);
                }
                Body::Denied { reason, .. } => panic!("unexpected denial: {reason}"),
                other => panic!("unexpected body: {other:?}"),
            }
        }
    }

    /// Read frames until the Program has printed `expected`, so a test can wait on the
    /// Program's own progress rather than on the clock.
    async fn await_output(
        reader: &mut tokio::net::unix::OwnedReadHalf,
        program: ProgramId,
        expected: &str,
    ) {
        let mut seen = Vec::new();
        loop {
            let frame = read_frame::<Frame, _>(reader)
                .await
                .expect("read a transport frame")
                .expect("the daemon must answer before closing");
            assert_eq!(frame.program, program, "a frame named another program");
            match frame.body {
                Body::Output { data, .. } => {
                    seen.extend_from_slice(&decode_payload(&data).expect("valid payload"));
                    if String::from_utf8_lossy(&seen).contains(expected) {
                        return;
                    }
                }
                Body::Exit { status } => panic!(
                    "the Program exited {status} before printing {expected:?}; saw {:?}",
                    String::from_utf8_lossy(&seen)
                ),
                other => panic!("unexpected body while waiting for {expected:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_background_effect_never_inherits_the_next_calls_trace() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            std::fs::write(marker.path().join("first.txt"), "first").unwrap();
            std::fs::write(marker.path().join("second.txt"), "second").unwrap();
            let spec = connection_spec(marker.path());
            let recorder = Arc::clone(&spec.recorder);
            let (_dir, socket) = serving_socket(spec);
            let (mut reader, mut writer) = transport(&socket).await;
            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            for (parent, source) in [
                (
                    "00-11111111111111111111111111111111-1111111111111111-01",
                    "(sleep 0.2; cat \"$HOME/first.txt\") &",
                ),
                (
                    "00-22222222222222222222222222222222-2222222222222222-01",
                    "sleep 0.5; cat \"$HOME/second.txt\"",
                ),
            ] {
                put(
                    &mut writer,
                    1,
                    Body::Call {
                        source: source.to_string(),
                        correlation: Box::new(telemetry::Correlation::from_headers(
                            Some(parent),
                            None,
                        )),
                    },
                )
                .await;
                assert_eq!(collect(&mut reader, 1).await.1, 0);
            }
            let records = recorder.recorded();
            let first: Vec<_> = records
                .iter()
                .filter(|record| record.parts().1.ends_with("/first.txt"))
                .collect();
            assert!(!first.is_empty(), "{records:?}");
            for record in first {
                let context = serde_json::to_value(record.correlation()).unwrap();
                assert_eq!(
                    context["traceparent"],
                    "00-11111111111111111111111111111111-1111111111111111-01",
                    "the background effect must keep its own caller"
                );
            }
            let second: Vec<_> = records
                .iter()
                .filter(|record| record.parts().1.ends_with("/second.txt"))
                .collect();
            assert!(!second.is_empty(), "{records:?}");
            for record in second {
                assert_eq!(
                    serde_json::to_value(record.correlation()).unwrap()["traceparent"],
                    "00-22222222222222222222222222222222-2222222222222222-01",
                    "a reused Program must use the new caller for its new effects"
                );
            }
            assert!(
                records.iter().any(|record| {
                    record.parts().1 == "cat"
                        && serde_json::to_value(record.correlation()).unwrap()["traceparent"]
                            == "00-22222222222222222222222222222222-2222222222222222-01"
                }),
                "the foreground command must keep its caller: {records:?}"
            );
        }));
    }

    /// A Program keeps its state across Calls on one connection.
    #[test]
    fn a_program_keeps_its_state_across_calls() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "export CARRIED=held".to_string(),
                },
            )
            .await;
            let (_, first) = collect(&mut reader, 1).await;
            assert_eq!(first, 0, "the export must succeed");

            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf \"carried=[%s]\" \"$CARRIED\"".to_string(),
                },
            )
            .await;
            let (text, status) = collect(&mut reader, 1).await;
            assert_eq!(status, 0);
            assert!(
                text.contains("carried=[held]"),
                "state set in one Call must survive into the next: {text:?}"
            );
        }));
    }

    /// Two Programs on ONE connection keep separate state.
    #[test]
    fn two_programs_on_one_connection_are_isolated() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            for id in [1, 2] {
                put(
                    &mut writer,
                    id,
                    Body::Open {
                        mode: Interpreter::Shell,
                    },
                )
                .await;
            }
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "export ONLY_MINE=one".to_string(),
                },
            )
            .await;
            let (_, status) = collect(&mut reader, 1).await;
            assert_eq!(status, 0);

            put(
                &mut writer,
                2,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf \"seen=[%s]\" \"$ONLY_MINE\"".to_string(),
                },
            )
            .await;
            let (text, _) = collect(&mut reader, 2).await;
            assert!(
                text.contains("seen=[]"),
                "program 2 must not see program 1's variable: {text:?}"
            );
        }));
    }

    /// A Call's output arrives as `Output` frames, chunked and stream-tagged.
    #[test]
    fn a_calls_output_arrives_as_tagged_chunks() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf to_stdout; printf to_stderr >&2".to_string(),
                },
            )
            .await;

            // Collect every frame, keeping the stream tag this time.
            let mut out = Vec::new();
            let mut err = Vec::new();
            loop {
                let frame = read_frame::<Frame, _>(&mut reader)
                    .await
                    .expect("read")
                    .expect("a frame");
                match frame.body {
                    Body::Output { stream, data } => {
                        let bytes = decode_payload(&data).expect("payload");
                        match stream {
                            Stream::Stdout => out.extend_from_slice(&bytes),
                            Stream::Stderr => err.extend_from_slice(&bytes),
                        }
                    }
                    Body::Exit { status } => {
                        assert_eq!(status, 0);
                        break;
                    }
                    other => panic!("unexpected body: {other:?}"),
                }
            }

            assert!(
                String::from_utf8_lossy(&out).contains("to_stdout"),
                "stdout must arrive tagged as stdout: {:?}",
                String::from_utf8_lossy(&out)
            );
            assert!(
                String::from_utf8_lossy(&err).contains("to_stderr"),
                "stderr must arrive tagged as stderr: {:?}",
                String::from_utf8_lossy(&err)
            );
        }));
    }

    /// Output arrives *before* the Call ends, not with its exit.
    #[test]
    fn output_arrives_while_the_call_is_still_running() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf EARLY; read release; printf LATE".to_string(),
                },
            )
            .await;

            await_output(&mut reader, 1, "EARLY").await;
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(b"continue\n"),
                },
            )
            .await;
            let (output, status) = collect(&mut reader, 1).await;
            assert!(
                output.contains("LATE"),
                "the Program must continue after receiving input: {output:?}"
            );
            assert_eq!(status, 0, "the Program must exit cleanly: {output:?}");
        }));
    }

    /// Bytes sent as `Input` reach the Program's standard input.
    #[test]
    fn input_frames_reach_the_programs_stdin() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(b"from_the_wire\n"),
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "read LINE; printf \"read=[%s]\" \"$LINE\"".to_string(),
                },
            )
            .await;

            let (text, _) = collect(&mut reader, 1).await;
            assert!(
                text.contains("read=[from_the_wire]"),
                "in-band stdin must reach the program: {text:?}"
            );
        }));
    }

    /// A `Signal` ends the Call and leaves the Program usable.
    #[test]
    fn a_signal_ends_the_call_but_not_the_program() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "export SURVIVES=yes; sleep 25".to_string(),
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            put(
                &mut writer,
                1,
                Body::Signal {
                    kind: SignalKind::Interrupt,
                },
            )
            .await;

            // The Call ends; *which* status it reports depends on who won the race, and both
            // answers are correct.
            let (_, status) = collect(&mut reader, 1).await;
            assert_ne!(status, 0, "an interrupted call must not report success");

            // The Program survives, and so does the state the interrupted Call set.
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf alive".to_string(),
                },
            )
            .await;
            let (text, status) = collect(&mut reader, 1).await;
            assert_eq!(status, 0, "the program must still serve after a signal");
            assert!(text.contains("alive"), "got {text:?}");
        }));
    }

    /// A request/reply session over one Program, using only the frames the protocol already has.
    #[test]
    fn a_program_serves_a_request_reply_session() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            // A line-oriented program: read a line, answer it, repeat. The shape of a stdio
            // server, an LSP, or a REPL.
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "while read line; do printf 'reply:%s\\n' \"$line\"; done".to_string(),
                },
            )
            .await;

            // Request 1 → reply 1, read before request 2 is sent. That ordering is the point: the
            // client is not batching, it is conversing.
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(b"one\n"),
                },
            )
            .await;
            let first = next_out(&mut reader).await;
            assert!(first.contains("reply:one"), "got {first:?}");

            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(b"two\n"),
                },
            )
            .await;
            let second = next_out(&mut reader).await;
            assert!(second.contains("reply:two"), "got {second:?}");

            // Closing stdin ends the loop, and the Call reports its own status.
            put(&mut writer, 1, Body::InputEof).await;
            let (_, status) = collect(&mut reader, 1).await;
            assert_eq!(status, 0, "the session must end cleanly");
        }));
    }

    /// The text of the next `Output` frame, skipping anything else.
    async fn next_out(reader: &mut tokio::net::unix::OwnedReadHalf) -> String {
        loop {
            let frame = read_frame::<Frame, _>(reader)
                .await
                .expect("read")
                .expect("a frame");
            if let Body::Output { data, .. } = frame.body {
                return String::from_utf8_lossy(&decode_payload(&data).expect("payload"))
                    .into_owned();
            }
        }
    }

    #[test]
    fn a_discovery_release_waits_for_a_successful_flush() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let GuardedDiscovery {
                _marker,
                _spec,
                mut program,
                mut completion,
                frame,
            } = guarded_discovery_frame().await;
            let (pump, entered, release_flush) = gated_frame_pump(frame, SERVE_IO_TIMEOUT);

            wait_for_gated_flush(entered).await;
            assert_discovery_completion_pending(&mut completion);

            release_flush
                .send(Ok(()))
                .expect("the successful flush is blocked");
            pump.await
                .expect("the writer task joins")
                .expect("the flush succeeds");
            wait_for_discovery_completion(&mut completion).await;
            program
                .stop_and_wait()
                .await
                .expect("the MCP server is reaped");
        }));
    }

    #[test]
    fn a_discovery_release_waits_for_flush_even_when_flush_fails() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let GuardedDiscovery {
                _marker,
                _spec,
                mut program,
                mut completion,
                frame,
            } = guarded_discovery_frame().await;
            let (pump, entered, release_flush) = gated_frame_pump(frame, SERVE_IO_TIMEOUT);

            wait_for_gated_flush(entered).await;
            assert_discovery_completion_pending(&mut completion);

            release_flush
                .send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "flush failed",
                )))
                .expect("the failed flush is blocked");
            let error = pump
                .await
                .expect("the writer task joins")
                .expect_err("flush must fail");
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            wait_for_discovery_completion(&mut completion).await;
            program
                .stop_and_wait()
                .await
                .expect("the MCP server is reaped");
        }));
    }

    #[test]
    fn a_discovery_release_waits_for_the_writer_timeout() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let GuardedDiscovery {
                _marker,
                _spec,
                mut program,
                mut completion,
                frame,
            } = guarded_discovery_frame().await;
            let (pump, entered, _release_flush) = gated_frame_pump(frame, Duration::from_secs(1));

            wait_for_gated_flush(entered).await;
            assert_discovery_completion_pending(&mut completion);

            let error = pump
                .await
                .expect("the writer task joins")
                .expect_err("the blocked flush must time out");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            wait_for_discovery_completion(&mut completion).await;
            program
                .stop_and_wait()
                .await
                .expect("the MCP server is reaped");
        }));
    }

    #[test]
    fn one_mcp_open_starts_the_declared_server_immediately() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let started = marker.path().join("server-started");
            let command = vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                r#"printf started > "$1"; exec cat"#.to_string(),
                "fake-mcp".to_string(),
                started.to_string_lossy().into_owned(),
            ];
            let spec = mcp_spec_with_server(marker.path(), command);
            let (_directory, socket) = serving_socket(spec);
            let (_reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                7,
                Body::Open {
                    mode: Interpreter::Mcp {
                        server: "/bin/sh".to_string(),
                    },
                },
            )
            .await;
            tokio::time::timeout(Duration::from_secs(2), async {
                while !started.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("Open starts the declared MCP server");
            put(&mut writer, 7, Body::Close).await;
        }));
    }

    #[test]
    fn a_cached_mcp_failure_denies_a_fresh_open_and_closes_its_connection() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let script = r#"IFS= read -r initialize
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"test-mcp","version":"1"}}}'
IFS= read -r initialized
IFS= read -r list
exit 17"#;
            let spec = mcp_spec_with_server(
                marker.path(),
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    script.to_string(),
                ],
            );
            let registry = Arc::clone(&spec.mcp_registry);
            let (_directory, socket) = serving_socket(spec);
            let (mut leader_reader, mut leader_writer) = transport(&socket).await;

            put(
                &mut leader_writer,
                1,
                Body::Open {
                    mode: Interpreter::Mcp {
                        server: "/bin/sh".to_string(),
                    },
                },
            )
            .await;
            put(
                &mut leader_writer,
                1,
                Body::Input {
                    data: encode_payload(
                        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
                    ),
                },
            )
            .await;
            let _ = next_out(&mut leader_reader).await;
            put(
                &mut leader_writer,
                1,
                Body::Input {
                    data: encode_payload(
                        b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
                    ),
                },
            )
            .await;
            put(
                &mut leader_writer,
                1,
                Body::Input {
                    data: encode_payload(
                        b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n",
                    ),
                },
            )
            .await;
            let failure = next_out(&mut leader_reader).await;
            assert!(failure.contains("\"code\":-32002"), "{failure}");
            assert!(registry.admit_open("test-mcp").is_err());
            drop(leader_reader);
            drop(leader_writer);

            let (mut reader, mut writer) = transport(&socket).await;
            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Mcp {
                        server: "/bin/sh".to_string(),
                    },
                },
            )
            .await;
            let refusal = tokio::time::timeout(
                Duration::from_secs(2),
                read_frame::<Frame, _>(&mut reader),
            )
            .await
            .expect("the cached failure must answer promptly")
            .expect("read the cached failure")
            .expect("the cached failure must send one frame");
            let Body::Denied { kind, reason } = refusal.body else {
                panic!("the cached failure must use a transport refusal");
            };
            assert_eq!(kind, DeniedKind::Internal);
            assert!(reason.contains("failed during"), "{reason}");
            let closed =
                tokio::time::timeout(Duration::from_secs(2), read_frame::<Frame, _>(&mut reader))
                    .await
                    .expect("the refused connection must close promptly")
                    .expect("read the refused connection");
            assert!(closed.is_none(), "the refusal must be terminal");
        }));
    }

    #[test]
    fn a_completed_mcp_exchange_closes_transport_without_alias_eof_and_preserves_cache() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let exit = marker.path().join("server-exit");
            let script = r#"IFS= read -r initialize
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"test-mcp","version":"1"}}}'
IFS= read -r initialized
IFS= read -r list
id=$(printf '%s\n' "$list" | sed -nE 's/.*"id":("[^"]*"|[0-9]+).*/\1/p')
printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"PrivateSearch","inputSchema":{"type":"object"}}]}}\n' "$id"
while test ! -e "$1"; do sleep 0.01; done"#;
            let mcp = Arc::new(vec![crate::record::config::mcp::McpServer {
                name: "test-mcp".to_string(),
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    script.to_string(),
                    "completed-mcp".to_string(),
                    exit.to_string_lossy().into_owned(),
                ],
            }]);
            let database = tempfile::tempdir().expect("policy database");
            let policy = Arc::new(
                PolicyEngine::open_staged(&policy::Operator::unanchored(),
                    vec![Policy {
                        origin: PathBuf::from("completed-mcp.dw"),
                        text: r#"
                            permit (
                                principal,
                                action == Box::Action::"mcp:call",
                                resource
                            );
                            permit (principal, action == Box::Action::"shell:spawn", resource);
                            permit (
                                principal,
                                action == test_mcp::Action::"PrivateSearch",
                                resource
                            );
                        "#
                        .to_string(),
                    }],
                    &database.path().join("dogwood.redb"),
                )
                .expect("the staged policy opens"),
            );
            let discovery =
                crate::run::broker::mcp::DiscoveryRegistryHost::start(&mcp, Arc::clone(&policy))
                    .expect("the registry starts");
            let registry = discovery.registry();
            let spec = Arc::new(ShellSpec {
                command_timeout: SHELL_COMMAND_TIMEOUT,
                request_timeout: SERVE_REQUEST_TIMEOUT,
                reach: Arc::new(
                    Reach::over(
                        &marker.path().canonicalize().expect("marker resolves"),
                        None,
                        None,
                    )
                    .expect("marker is reachable"),
                ),
                mcp,
                mcp_registry: Arc::clone(&registry),
                mcp_working_directory: marker.path().to_path_buf(),
                mcp_working_directory_handle: None,
                mcp_leaf_launcher: None,
                policy,
                governed: GovernedBox::assigned("codex"),
                spawn_credentials: Default::default(),
                egress: None,
                recorder: crate::run::telemetry::DecisionRecorder::discarding(),
                host_spawner: None,
            });
            let (_directory, socket) = serving_socket(spec);
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Mcp {
                        server: "/bin/sh".to_string(),
                    },
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(
                        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
                    ),
                },
            )
            .await;
            let initialize: serde_json::Value =
                serde_json::from_str(&next_out(&mut reader).await).expect("initialize response");
            assert_eq!(initialize["id"], 1);
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(
                        b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
                    ),
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(
                        b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n",
                    ),
                },
            )
            .await;
            let catalog: serde_json::Value =
                serde_json::from_str(&next_out(&mut reader).await).expect("tools/list response");
            assert_eq!(catalog["id"], 2);
            assert_eq!(catalog["result"]["tools"][0]["name"], "PrivateSearch");
            std::fs::write(&exit, b"exit").expect("release the MCP child");

            let closed =
                tokio::time::timeout(Duration::from_secs(2), read_frame::<Frame, _>(&mut reader))
                    .await
                    .expect("the completed exchange closes the transport")
                    .expect("read the completed transport");
            assert!(closed.is_none(), "the completed transport must close");
            assert!(
                registry.require_listed("test-mcp", "PrivateSearch").is_ok(),
                "exchange completion must preserve the accepted catalog"
            );
            drop(writer);
            drop(discovery);
        }));
    }

    #[cfg(unix)]
    #[test]
    fn broker_shutdown_joins_a_live_mcp_exchange_and_reaps_its_process_group() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let child_pid = marker.path().join("child-pid");
            let command = vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                r#"trap '' TERM; sleep 3600 & printf '%s %s' "$$" "$!" > "$1"; wait"#.to_string(),
                "fake-mcp".to_string(),
                child_pid.to_string_lossy().into_owned(),
            ];
            let spec = mcp_spec_with_server(marker.path(), command);
            let directory = tempfile::tempdir().expect("socket directory");
            let socket = directory.path().join("box.sock");
            let listener = UnixListener::bind(&socket).expect("bind test broker");
            let (stop, stopped) = oneshot::channel();
            let serving = tokio::task::spawn_local(async move {
                serve(listener, spec, async {
                    let _ = stopped.await;
                })
                .await
            });
            let (_reader, mut writer) = transport(&socket).await;
            put(
                &mut writer,
                7,
                Body::Open {
                    mode: Interpreter::Mcp {
                        server: "/bin/sh".to_string(),
                    },
                },
            )
            .await;
            let pids = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let pids = std::fs::read_to_string(&child_pid)
                        .unwrap_or_default()
                        .split_whitespace()
                        .filter_map(|pid| pid.parse::<libc::pid_t>().ok())
                        .collect::<Vec<_>>();
                    if pids.len() == 2 {
                        return pids;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the MCP child records its leader and its child");

            stop.send(()).expect("the broker is serving");
            tokio::time::timeout(Duration::from_secs(3), serving)
                .await
                .expect("broker shutdown joins its connection")
                .expect("serving task joins")
                .expect("broker shutdown succeeds");
            for pid in pids {
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        // SAFETY: signal zero only tests whether the recorded process still exists.
                        let result = unsafe { libc::kill(pid, 0) };
                        if result == -1
                            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("the MCP process is reaped");
            }
        }));
    }

    #[cfg(unix)]
    #[test]
    fn a_protocol_error_reaps_the_open_mcp_process_group() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let child_pid = marker.path().join("child-pid");
            let command = vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                r#"trap '' TERM; sleep 3600 & printf '%s %s' "$$" "$!" > "$1"; wait"#.to_string(),
                "fake-mcp".to_string(),
                child_pid.to_string_lossy().into_owned(),
            ];
            let (_directory, socket) = serving_socket(mcp_spec_with_server(marker.path(), command));
            let (mut reader, mut writer) = transport(&socket).await;
            put(
                &mut writer,
                7,
                Body::Open {
                    mode: Interpreter::Mcp {
                        server: "/bin/sh".to_string(),
                    },
                },
            )
            .await;
            let pids = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let pids = std::fs::read_to_string(&child_pid)
                        .unwrap_or_default()
                        .split_whitespace()
                        .filter_map(|pid| pid.parse::<libc::pid_t>().ok())
                        .collect::<Vec<_>>();
                    if pids.len() == 2 {
                        return pids;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the MCP child records its leader and its child");

            put(
                &mut writer,
                7,
                Body::Output {
                    stream: Stream::Stdout,
                    data: encode_payload(b"invalid client output"),
                },
            )
            .await;
            let closed =
                tokio::time::timeout(Duration::from_secs(3), read_frame::<Frame, _>(&mut reader))
                    .await
                    .expect("protocol cleanup closes the connection")
                    .expect("read the closed connection");
            assert!(
                closed.is_none(),
                "the protocol error must close the connection"
            );

            for pid in pids {
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        // SAFETY: signal zero only tests whether the recorded process still exists.
                        let result = unsafe { libc::kill(pid, 0) };
                        if result == -1
                            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("the MCP process is reaped");
            }
        }));
    }

    #[test]
    fn each_root_list_reaches_the_server_and_an_unchanged_one_keeps_the_catalog() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let list_calls = marker.path().join("list-calls");
            let script = format!(
                r#"while IFS= read -r frame; do
case "$frame" in
  *'"method":"initialize"'*)
    printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":"2024-11-05","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"test-mcp","version":"1"}}}}}}'
    ;;
  *'"method":"tools/list"'*)
    printf list >> '{}'
    id=$(printf '%s\n' "$frame" | sed -nE 's/.*"id":("[^"]*"|[0-9]+).*/\1/p')
    printf '{{"jsonrpc":"2.0","id":%s,"result":{{"tools":[{{"name":"PrivateSearch","inputSchema":{{"type":"object"}}}}]}}}}\n' "$id"
    ;;
esac
done"#,
                list_calls.display()
            );
            let mcp = Arc::new(vec![crate::record::config::mcp::McpServer {
                name: "test-mcp".to_string(),
                command: vec!["/bin/sh".to_string(), "-c".to_string(), script],
            }]);
            let database = tempfile::tempdir().expect("policy database");
            let policy = Arc::new(
                PolicyEngine::open_staged(&policy::Operator::unanchored(),
                    vec![Policy {
                        origin: PathBuf::from("lazy-mcp.dw"),
                        text: r#"
                            permit (
                                principal,
                                action == Box::Action::"mcp:call",
                                resource
                            );
                            permit (principal, action == Box::Action::"shell:spawn", resource);
                            permit (
                                principal,
                                action == test_mcp::Action::"PrivateSearch",
                                resource
                            );
                        "#
                        .to_string(),
                    }],
                    &database.path().join("dogwood.redb"),
                )
                .expect("the staged policy opens"),
            );
            let discovery =
                crate::run::broker::mcp::DiscoveryRegistryHost::start(&mcp, Arc::clone(&policy))
                    .expect("the registry starts");
            let spec = Arc::new(ShellSpec {
                command_timeout: SHELL_COMMAND_TIMEOUT,
                request_timeout: SERVE_REQUEST_TIMEOUT,
                reach: Arc::new(
                    Reach::over(
                        &marker.path().canonicalize().expect("marker resolves"),
                        None,
                        None,
                    )
                    .expect("marker is reachable"),
                ),
                mcp,
                mcp_registry: discovery.registry(),
                mcp_working_directory: marker.path().to_path_buf(),
                mcp_working_directory_handle: None,
                mcp_leaf_launcher: None,
                policy,
                governed: GovernedBox::assigned("codex"),
                spawn_credentials: Default::default(),
                egress: None,
                recorder: crate::run::telemetry::DecisionRecorder::discarding(),
                host_spawner: None,
            });
            let (_directory, socket) = serving_socket(spec);
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Mcp {
                        server: "/bin/sh".to_string(),
                    },
                },
            )
            .await;
            let initialize =
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n";
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(initialize),
                },
            )
            .await;
            let initialize_response: serde_json::Value =
                serde_json::from_str(&next_out(&mut reader).await).expect("initialize response");
            assert_eq!(initialize_response["id"], 1);

            let initialized =
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n";
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(initialized),
                },
            )
            .await;
            for id in [9, 10] {
                let list = format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/list\",\"params\":{{}}}}\n"
                );
                put(
                    &mut writer,
                    1,
                    Body::Input {
                        data: encode_payload(list.as_bytes()),
                    },
                )
                .await;
                let response: serde_json::Value =
                    serde_json::from_str(&next_out(&mut reader).await).expect("tools/list response");
                assert_eq!(response["id"], id);
                assert_eq!(response["result"]["tools"][0]["name"], "PrivateSearch");
            }
            assert_eq!(
                std::fs::read_to_string(&list_calls).expect("list marker"),
                "listlist",
                "each root list must reach the server"
            );
            let unknown_call = b"{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":\"UnknownTool\",\"arguments\":{}}}\n";
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(unknown_call),
                },
            )
            .await;
            let refusal: serde_json::Value =
                serde_json::from_str(&next_out(&mut reader).await).expect("catalog refusal");
            assert_eq!(refusal["id"], 11);
            assert_eq!(refusal["error"]["code"], -32003);
            put(&mut writer, 1, Body::Close).await;
            drop(discovery);
        }));
    }

    #[test]
    fn a_denied_mcp_tool_call_answers_and_keeps_the_server() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let script = r#"while IFS= read -r frame; do
case "$frame" in
  *'"method":"initialize"'*)
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"test-mcp","version":"1"}}}'
    ;;
  *'"method":"notifications/initialized"'*)
    ;;
  *'"method":"tools/list"'*)
    id=$(printf '%s\n' "$frame" | sed -nE 's/.*"id":("[^"]*"|[0-9]+).*/\1/p')
    printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"PrivateSearch","inputSchema":{"type":"object","properties":{"isDeep":{"type":"boolean"},"query":{"type":"string"}},"required":["query"]}},{"name":"PublicSearch","inputSchema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}]}}\n' "$id"
    ;;
  *)
    printf '%s\n' "$frame"
    ;;
esac
done"#;
            let mcp = Arc::new(vec![crate::record::config::mcp::McpServer {
                name: "test-mcp".to_string(),
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    script.to_string(),
                ],
            }]);
            let database = tempfile::tempdir().expect("policy database");
            let policy = Arc::new(
                PolicyEngine::open_staged(&policy::Operator::unanchored(),
                    vec![Policy {
                        origin: PathBuf::from("mcp-broker-test.dw"),
                        text: r#"
                            permit (principal, action == Box::Action::"mcp:call", resource);
                            permit (principal, action == Box::Action::"shell:spawn", resource);
                            @id("private-search")
                            @description("Use PublicSearch for this workload.")
                            forbid (principal, action == Box::Action::"mcp:call", resource)
                            when {
                                context.input has tool &&
                                context.input.tool == "PrivateSearch"
                            };
                        "#
                        .to_string(),
                    }],
                    &database.path().join("dogwood.redb"),
                )
                .expect("the staged policy opens"),
            );
            let discovery =
                crate::run::broker::mcp::DiscoveryRegistryHost::start(&mcp, Arc::clone(&policy))
                    .expect("the registry starts");
            let spec = Arc::new(ShellSpec {
                command_timeout: SHELL_COMMAND_TIMEOUT,
                request_timeout: SERVE_REQUEST_TIMEOUT,
                reach: Arc::new(
                    Reach::over(
                        &marker.path().canonicalize().expect("marker resolves"),
                        None,
                        None,
                    )
                    .expect("marker is reachable"),
                ),
                mcp,
                mcp_registry: discovery.registry(),
                mcp_working_directory: marker.path().to_path_buf(),
                mcp_working_directory_handle: None,
                mcp_leaf_launcher: None,
                policy,
                governed: GovernedBox::assigned("codex"),
                spawn_credentials: Default::default(),
                egress: None,
                recorder: crate::run::telemetry::DecisionRecorder::discarding(),
                host_spawner: None,
            });
            let (_directory, socket) = serving_socket(spec);
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Mcp {
                        server: "/bin/sh".to_string(),
                    },
                },
            )
            .await;

            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(
                        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
                    ),
                },
            )
            .await;
            let initialize: serde_json::Value =
                serde_json::from_str(&next_out(&mut reader).await).expect("initialize response");
            assert_eq!(initialize["id"], 1);
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(
                        b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
                    ),
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(
                        b"{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/list\",\"params\":{}}\n",
                    ),
                },
            )
            .await;
            let catalog: serde_json::Value =
                serde_json::from_str(&next_out(&mut reader).await).expect("tools/list response");
            assert_eq!(catalog["id"], 6);
            assert_eq!(catalog["result"]["tools"][0]["name"], "PrivateSearch");

            let denied = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"PrivateSearch","arguments":{"query":"widgets"}}}
"#;
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(denied.as_bytes()),
                },
            )
            .await;
            let response: serde_json::Value =
                serde_json::from_str(&next_out(&mut reader).await).expect("JSON-RPC error");
            assert_eq!(response["id"], 7);
            assert_eq!(response["error"]["code"], -32001);
            assert_eq!(
                response["error"]["message"],
                "policy denied this operation on 'test-mcp/PrivateSearch' [policy: private-search]: Use PublicSearch for this workload. (tools/call)"
            );

            let permitted = r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"PublicSearch","arguments":{"query":"widgets"}}}
"#;
            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(permitted.as_bytes()),
                },
            )
            .await;
            assert_eq!(
                next_out(&mut reader).await,
                permitted,
                "the permitted request must reach the still-running server"
            );
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    read_frame::<Frame, _>(&mut reader)
                )
                .await
                .is_err(),
                "the denied request must not reach the server"
            );
            drop(discovery);
        }));
    }

    #[test]
    fn a_call_on_one_program_does_not_block_another() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            for id in [1, 2] {
                put(
                    &mut writer,
                    id,
                    Body::Open {
                        mode: Interpreter::Shell,
                    },
                )
                .await;
            }
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf READY; read release; printf released".to_string(),
                },
            )
            .await;
            tokio::time::timeout(
                Duration::from_secs(10),
                await_output(&mut reader, 1, "READY"),
            )
            .await
            .expect("error: the first program reaches its input gate");
            put(
                &mut writer,
                2,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf quick".to_string(),
                },
            )
            .await;

            let (text, status) =
                tokio::time::timeout(Duration::from_secs(10), collect(&mut reader, 2))
                    .await
                    .expect("error: the second program completes while the first waits for input");
            assert_eq!(status, 0, "error: the second program's call must succeed");
            assert!(text.contains("quick"), "error: got {text:?}");

            put(
                &mut writer,
                1,
                Body::Input {
                    data: encode_payload(b"continue\n"),
                },
            )
            .await;
            let (text, status) =
                tokio::time::timeout(Duration::from_secs(10), collect(&mut reader, 1))
                    .await
                    .expect("error: the first program completes after input");
            assert_eq!(status, 0, "error: the first program's call must succeed");
            assert!(
                text.contains("released"),
                "error: the first program must resume after input: {text:?}"
            );
        }));
    }

    /// A second Call for a Program already running one is refused, not queued.
    #[test]
    fn a_concurrent_call_on_one_program_is_refused() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(short_connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "sleep 60".to_string(),
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf second".to_string(),
                },
            )
            .await;

            // The refusal arrives while the first Call is still running, and it is a transport
            // refusal — `Denied` — never a policy decision.
            let frame = read_frame::<Frame, _>(&mut reader)
                .await
                .expect("read")
                .expect("a frame");
            match frame.body {
                Body::Denied { kind, reason } => {
                    assert_eq!(
                        kind,
                        DeniedKind::FlowControl,
                        "a second Call on a busy Program is back-pressure (R20 flow_control)"
                    );
                    assert!(
                        reason.contains("already running"),
                        "the refusal must say why: {reason:?}"
                    );
                }
                other => panic!("expected a transport refusal, got {other:?}"),
            }

            // And the first Call was unaffected by the refusal — it runs on to its own end, which
            // here is the deadline rather than completion, so any status but a clean 0 is right.
            let (_, status) = collect(&mut reader, 1).await;
            assert_ne!(
                status, 0,
                "the running call must end on its own terms, not the refusal's"
            );
        }));
    }

    /// Closing a Program mid-Call is final: a later `Open` at the same id is not clobbered.
    #[test]
    fn closing_a_running_program_does_not_resurrect_it() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            // Print before sleeping, so the test can *observe* the Call running instead of guessing
            // at it.
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: "export CLOSED=leaked; printf running; sleep 30".to_string(),
                },
            )
            .await;
            await_output(&mut reader, 1, "running").await;
            put(&mut writer, 1, Body::Close).await;

            // A fresh Program at the same id, and it must be genuinely fresh.
            put(
                &mut writer,
                1,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            put(
                &mut writer,
                1,
                Body::Call {
                    correlation: Default::default(),
                    source: r#"printf "leaked=[%s]" "$CLOSED""#.to_string(),
                },
            )
            .await;

            let (text, status) = collect(&mut reader, 1).await;
            assert_eq!(status, 0, "the reopened program must serve: {text:?}");
            assert!(
                text.contains("leaked=[]"),
                "a closed Program's state must not reach its replacement: {text:?}"
            );
        }));
    }

    #[test]
    fn a_stale_mcp_completion_does_not_remove_a_reopened_program() {
        let mut programs = HashMap::from([(
            7,
            OpenMcpProgram {
                sequence: 0,
                program: "closed",
            },
        )]);
        programs.remove(&7).expect("close removes the old program");
        programs.insert(
            7,
            OpenMcpProgram {
                sequence: 1,
                program: "reopened",
            },
        );

        let stale = remove_completed_mcp(&mut programs, CompletedMcp { id: 7, sequence: 0 });

        assert!(stale.is_none(), "the old completion must be ignored");
        assert_eq!(
            programs.get(&7).map(|current| current.program),
            Some("reopened"),
            "the stale completion must leave the reopened program registered"
        );
    }

    /// A reused `ProgramId` is never answered with a closed Call's status.
    #[test]
    fn a_reused_program_id_never_reports_a_closed_calls_status() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            for cycle in 0..12 {
                put(
                    &mut writer,
                    1,
                    Body::Open {
                        mode: Interpreter::Shell,
                    },
                )
                .await;
                // Observed rather than timed, like the sibling: the Call must genuinely be
                // running before it is closed, or the cycle proves nothing.
                put(
                    &mut writer,
                    1,
                    Body::Call {
                        correlation: Default::default(),
                        source: "printf running; sleep 30".to_string(),
                    },
                )
                .await;
                await_output(&mut reader, 1, "running").await;
                put(&mut writer, 1, Body::Close).await;

                // The replacement, submitted without waiting for the abandoned Call to wind
                // down, which is the interleaving the defect needs.
                put(
                    &mut writer,
                    1,
                    Body::Open {
                        mode: Interpreter::Shell,
                    },
                )
                .await;
                put(
                    &mut writer,
                    1,
                    Body::Call {
                        correlation: Default::default(),
                        source: "printf replaced".to_string(),
                    },
                )
                .await;

                let (text, status) = collect(&mut reader, 1).await;
                assert_eq!(
                    status, 0,
                    "cycle {cycle}: the reply must carry the replacement's status, not the \
                     closed Call's: {text:?}"
                );
                assert!(
                    text.contains("replaced"),
                    "cycle {cycle}: the replacement must be the Program that answered: {text:?}"
                );
                put(&mut writer, 1, Body::Close).await;
            }
        }));
    }

    /// **A Python Program refuses `Input`, `InputEof` and `Signal` by name.**
    ///
    /// A Python Program lives in its own set and `control_for` consults only `programs` and
    /// `running`, so `Input` answered "transport program 3 is not open" for a Program that was open,
    /// and `InputEof` and `Signal` were dropped in silence — no way to interrupt a running script and
    /// no frame saying so. Nothing covered any of the three.
    #[test]
    fn a_python_program_refuses_input_and_signal_by_name() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                3,
                Body::Open {
                    mode: Interpreter::Python,
                },
            )
            .await;

            for body in [
                Body::Input {
                    data: encode_payload(b"ignored"),
                },
                Body::InputEof,
                Body::Signal {
                    kind: SignalKind::Interrupt,
                },
            ] {
                let named = format!("{body:?}");
                put(&mut writer, 3, body).await;
                let outcome = read_frame::<Frame, _>(&mut reader).await;
                let Ok(Some(frame)) = outcome else {
                    panic!("{named} must be answered, not dropped: {outcome:?}");
                };
                match frame.body {
                    Body::Denied { kind, reason } => {
                        assert_eq!(kind, DeniedKind::TransportError, "{named}");
                        assert!(
                            !reason.contains("not open"),
                            "{named}: the Program IS open; that message was the defect: {reason}"
                        );
                        assert!(
                            reason.contains("no input") || reason.contains("no signal"),
                            "{named}: the refusal must say what a Python program does not take: \
                             {reason}"
                        );
                    }
                    other => panic!("{named} must be refused by name, got {other:?}"),
                }
            }
        }));
    }

    /// **A frame naming an unopened Program is denied, and the connection keeps serving.**
    ///
    /// This asserted that the daemon *dropped the connection*. Dropping it is what broke a denied
    #[test]
    fn a_frame_for_an_unopened_program_is_refused() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(
                &mut writer,
                7,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf nope".to_string(),
                },
            )
            .await;

            // Fail-closed, and *answered*: the frame is refused by name and the connection lives.
            let outcome = read_frame::<Frame, _>(&mut reader).await;
            let Ok(Some(frame)) = outcome else {
                panic!("the daemon must answer rather than drop the connection: {outcome:?}");
            };
            match frame.body {
                Body::Denied { kind, reason } => {
                    assert_eq!(
                        kind,
                        DeniedKind::TransportError,
                        "a frame naming an unopened id is a transport error (R20)"
                    );
                    assert!(
                        reason.contains("not open"),
                        "the refusal must say the id was never opened: {reason}"
                    );
                }
                other => panic!("expected a refusal for an unopened id, got {other:?}"),
            }

            // **And the connection still serves**, which is the half that broke a denied MCP
            // server. A second frame on the same transport must be answered too.
            put(
                &mut writer,
                8,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf nope".to_string(),
                },
            )
            .await;
            let next = read_frame::<Frame, _>(&mut reader).await;
            assert!(
                matches!(next, Ok(Some(_))),
                "the transport must survive a per-program refusal: {next:?}"
            );
        }));
    }

    /// A second `Open` on a live Program drops the connection.
    #[test]
    fn reopening_a_live_program_is_refused() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            for _ in 0..2 {
                put(
                    &mut writer,
                    1,
                    Body::Open {
                        mode: Interpreter::Shell,
                    },
                )
                .await;
            }
            let outcome = read_frame::<Frame, _>(&mut reader).await;
            assert!(
                matches!(outcome, Ok(None) | Err(_)),
                "reopening a live program must not be served: {outcome:?}"
            );
        }));
    }

    /// A daemon-only body sent BY the client drops the connection.
    #[test]
    fn a_client_sending_a_daemon_body_is_refused() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            put(&mut writer, 1, Body::Exit { status: 0 }).await;
            let outcome = read_frame::<Frame, _>(&mut reader).await;
            assert!(
                matches!(outcome, Ok(None) | Err(_)),
                "a client may not send a daemon body: {outcome:?}"
            );
        }));
    }

    /// Past the per-connection cap, an `Open` is denied while open Programs keep serving.
    #[test]
    fn the_program_cap_denies_rather_than_dropping() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let (mut reader, mut writer) = transport(&socket).await;

            for id in 0..MAX_PROGRAMS_PER_CONNECTION {
                put(
                    &mut writer,
                    id as ProgramId,
                    Body::Open {
                        mode: Interpreter::Shell,
                    },
                )
                .await;
            }
            put(
                &mut writer,
                999,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;

            let frame = read_frame::<Frame, _>(&mut reader)
                .await
                .expect("read")
                .expect("a denial");
            assert_eq!(frame.program, 999);
            match frame.body {
                Body::Denied { kind, reason } => {
                    assert_eq!(
                        kind,
                        DeniedKind::OverBudget,
                        "the per-connection program cap is over_budget"
                    );
                    assert!(reason.contains("programs per connection"), "got {reason:?}")
                }
                other => panic!("expected a denial, got {other:?}"),
            }

            // An already-open program still serves.
            put(
                &mut writer,
                0,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf still_here".to_string(),
                },
            )
            .await;
            let (text, status) = collect(&mut reader, 0).await;
            assert_eq!(status, 0);
            assert!(text.contains("still_here"), "got {text:?}");
        }));
    }

    /// Dropping the connection reaps every Program on it.
    #[test]
    fn dropping_a_connection_reaps_its_programs() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));

            // Open several Programs, set state in one, then walk away without closing anything.
            {
                let (mut reader, mut writer) = transport(&socket).await;
                for id in 0..3 {
                    put(
                        &mut writer,
                        id,
                        Body::Open {
                            mode: Interpreter::Shell,
                        },
                    )
                    .await;
                }
                put(
                    &mut writer,
                    0,
                    Body::Call {
                        correlation: Default::default(),
                        source: "export ABANDONED=yes".to_string(),
                    },
                )
                .await;
                let (_, status) = collect(&mut reader, 0).await;
                assert_eq!(status, 0);
                // Both halves drop here, closing the socket.
            }

            // A fresh connection is served, and sees none of the abandoned state.
            let (mut reader, mut writer) = transport(&socket).await;
            put(
                &mut writer,
                0,
                Body::Open {
                    mode: Interpreter::Shell,
                },
            )
            .await;
            put(
                &mut writer,
                0,
                Body::Call {
                    correlation: Default::default(),
                    source: "printf \"abandoned=[%s]\" \"$ABANDONED\"".to_string(),
                },
            )
            .await;
            let (text, status) = collect(&mut reader, 0).await;
            assert_eq!(
                status, 0,
                "the boundary must keep serving after a peer vanishes"
            );
            assert!(
                text.contains("abandoned=[]"),
                "a reaped Program's state must not reach a later connection: {text:?}"
            );
        }));
    }

    /// The daemon reads the peer's pid, and it is the *test process* that connected.
    #[test]
    fn the_daemon_reads_the_connecting_peers_pid() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let directory = tempfile::tempdir().expect("socket directory");
            let socket = directory.path().join("peer.sock");
            let listener = UnixListener::bind(&socket).expect("bind");

            let accepted = tokio::task::spawn_local(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                peer_pid(&stream)
            });
            let _client = UnixStream::connect(&socket).await.expect("connect");

            let reported = accepted.await.expect("join").expect("a readable peer pid");
            assert_eq!(
                reported,
                std::process::id() as i32,
                "the kernel must report the connecting process, not a placeholder"
            );
        }));
    }

    /// Peer identity never reaches a policy request.
    #[test]
    fn peer_identity_never_reaches_a_policy_request() {
        // `Principal` is constructed from a *boundary*, taking no caller argument at all.
        let principal = Principal::agent();
        let rendered = format!("{principal:?}");
        assert!(
            !rendered.contains(&std::process::id().to_string()),
            "a principal must not carry the calling pid: {rendered}"
        );

        // And the audit path takes an `Outcome`, whose variants are effect facts. There is no
        // attribution field to fill in.
        let outcome = policy::Outcome::ShellRun {
            command: "printf audited",
            program: "printf",
            args: &["audited".to_string()],
            cwd: "/workspace",
            status: 0,
        };
        let rendered = format!("{outcome:?}");
        assert!(
            !rendered.contains(&std::process::id().to_string()),
            "an outcome must not carry the calling pid: {rendered}"
        );
    }

    /// Version 1 still works, so the alias is unaffected while clients migrate.
    #[test]
    fn the_previous_protocol_still_serves() {
        let (runtime, local) = runtime();
        runtime.block_on(local.run_until(async {
            let marker = tempfile::tempdir().expect("marker");
            let (_dir, socket) = serving_socket(connection_spec(marker.path()));
            let response = submit(&socket, "printf legacy_ok").await;
            assert_eq!(response.1, 0);
            assert!(
                response.0.contains("legacy_ok"),
                "version 1 must keep working: {response:?}"
            );
        }));
    }
}
