//! One client connection to one running MCP server, relayed frame by frame.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use egress_gateway::McpTarget;
use policy::{
    Decision, DiscoveryFailure, GovernedBox, ListPage, Outcome, PolicyEngine, Principal, Request,
    ServerDiscovery,
};
use serde_json::Value;

use super::admission::{McpRequestAdmission, admit_tool_call, policy_denial_response};
use super::discovery::{CompletionOutcome, DiscoveryRegistry, StagedList, failure_response};
use super::jsonrpc::{
    emit_request_error, emit_text, id_key, invalid_data, list_cursor, optional_request_id,
    require_request_id,
};
use super::server::{
    MCP_BROKER_IO_TIMEOUT, MCP_DISCOVERY_RESPONSE_TIMEOUT, RunningMcpServer, read_server_frame,
    validate_initialize_result,
};
use crate::run::telemetry::{DecisionRecorder, EffectiveDecision};

/// How long an MCP caller can wait to enter the exchange input queue.
pub(super) const MCP_INPUT_SEND_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(100);

/// The number of pending inputs one MCP exchange can retain.
pub(super) const MCP_INPUT_CHANNEL_CAPACITY: usize = 64;

/// The most server requests one connection can have awaiting the client's reply.
const MAXIMUM_PENDING_SERVER_REQUESTS: usize = 64;

/// The longest id or method a remembered server request can carry.
const MAXIMUM_SERVER_REQUEST_FIELD_BYTES: usize = 256;

/// How long a server has to answer a `tools/list` before its discovery fails.
const LIST_REPLY_TIMEOUT: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_secs(5)
} else {
    MCP_DISCOVERY_RESPONSE_TIMEOUT
};

/// Numbers each exchange, so its catalog pages accumulate apart from every other's.
static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

enum McpInput {
    Bytes(Vec<u8>),
    Eof,
    Stop,
}

struct LocalTask<T> {
    task: Option<tokio::task::JoinHandle<T>>,
}

impl<T> LocalTask<T> {
    fn new(task: tokio::task::JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    async fn abort_and_join(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl<T> Drop for LocalTask<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// One running exchange between a client and its MCP server.
pub(crate) struct McpProgram {
    input: tokio::sync::mpsc::Sender<McpInput>,
    cancellation: tokio::sync::watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<io::Result<()>>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum McpConnectionPhase {
    AwaitingInitialize,
    AwaitingInitialized,
    Active,
}

/// A decided client request awaiting its reply, so the reply can record `mcp:call::response`.
struct RecordedCall {
    method: String,
    tool: Option<String>,
    prompt: Option<String>,
    uri: Option<String>,
}

/// A client's `tools/list` awaiting the server's reply.
struct PendingList {
    id: Value,
    cursor: Option<String>,
    /// When a captured list fails, or `None` for a list that is relayed but not captured.
    deadline: Option<Instant>,
}

/// The final page's reply, held until its schema stages.
struct HeldReply {
    staged: std::pin::Pin<Box<dyn std::future::Future<Output = StagedList>>>,
    raw: Vec<u8>,
    id: Value,
    release: super::discovery::DiscoveryReleaseGuard,
}

struct McpConnection {
    key: String,
    phase: McpConnectionPhase,
    initialize_id: Option<String>,
    in_flight: std::collections::BTreeSet<String>,
    recorder: Arc<DecisionRecorder>,
    decided_calls: BTreeMap<String, RecordedCall>,
    lists: BTreeMap<String, PendingList>,
    /// Server requests forwarded to the client, by id, with the method each one asked.
    server_requests: BTreeMap<String, String>,
    /// Final-page replies waiting for their schema, in the order the server sent them.
    held: VecDeque<HeldReply>,
    policy: Arc<PolicyEngine>,
    governed: GovernedBox,
}

/// The frames, channels, and identity one exchange works with.
struct Exchange<'a> {
    running: &'a mut RunningMcpServer,
    registry: &'a Arc<DiscoveryRegistry>,
    frames: &'a tokio::sync::mpsc::Sender<super::super::host::OutboundFrame>,
    program: crate::run::broker::protocol::ProgramId,
    connection: &'a mut McpConnection,
}

impl McpProgram {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::run::broker) fn spawn(
        running: RunningMcpServer,
        stdout: tokio::process::ChildStdout,
        registry: Arc<DiscoveryRegistry>,
        frames: tokio::sync::mpsc::Sender<super::super::host::OutboundFrame>,
        program: crate::run::broker::protocol::ProgramId,
        policy: Arc<PolicyEngine>,
        governed: GovernedBox,
        recorder: Arc<DecisionRecorder>,
    ) -> (Self, tokio::sync::oneshot::Receiver<()>) {
        let (input, receiver) = tokio::sync::mpsc::channel(MCP_INPUT_CHANNEL_CAPACITY);
        let (cancellation, cancelled) = tokio::sync::watch::channel(false);
        let (completed, completion) = tokio::sync::oneshot::channel();
        let task = tokio::task::spawn_local(async move {
            let result = run_mcp_program(
                running, stdout, registry, frames, program, policy, governed, recorder, receiver,
                cancelled,
            )
            .await;
            let _ = completed.send(());
            result
        });
        (
            Self {
                input,
                cancellation,
                task: Some(task),
            },
            completion,
        )
    }

    pub(crate) async fn input(&self, bytes: Vec<u8>) -> io::Result<()> {
        self.send_input(McpInput::Bytes(bytes)).await
    }

    pub(crate) async fn eof(&self) -> io::Result<()> {
        self.send_input(McpInput::Eof).await
    }

    async fn send_input(&self, input: McpInput) -> io::Result<()> {
        tokio::time::timeout(MCP_INPUT_SEND_TIMEOUT, self.input.send(input))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the MCP exchange input queue did not accept input",
                )
            })?
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the MCP exchange stopped"))
    }

    pub(crate) async fn stop_and_wait(&mut self) -> io::Result<()> {
        self.cancellation.send_replace(true);
        let _ = tokio::time::timeout(MCP_INPUT_SEND_TIMEOUT, self.input.send(McpInput::Stop)).await;
        self.join().await
    }

    pub(crate) async fn join(&mut self) -> io::Result<()> {
        self.task
            .take()
            .ok_or_else(|| io::Error::other("the MCP exchange was already joined"))?
            .await
            .map_err(io::Error::other)?
    }

    #[cfg(test)]
    pub(super) fn input_capacity(&self) -> usize {
        self.input.capacity()
    }
}

impl Drop for McpProgram {
    fn drop(&mut self) {
        self.cancellation.send_replace(true);
    }
}

enum ProgramEvent {
    Input(Option<McpInput>),
    Output(Option<io::Result<Vec<u8>>>),
    ListDeadline,
    Staged(StagedList),
}

enum ProgramAction {
    Continue,
    Close,
}

#[allow(clippy::too_many_arguments)]
async fn run_mcp_program(
    mut running: RunningMcpServer,
    stdout: tokio::process::ChildStdout,
    registry: Arc<DiscoveryRegistry>,
    frames: tokio::sync::mpsc::Sender<super::super::host::OutboundFrame>,
    program: crate::run::broker::protocol::ProgramId,
    policy: Arc<PolicyEngine>,
    governed: GovernedBox,
    recorder: Arc<DecisionRecorder>,
    mut input: tokio::sync::mpsc::Receiver<McpInput>,
    mut cancellation: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let (server_frames, mut server_output) = tokio::sync::mpsc::channel(8);
    let mut reader = LocalTask::new(tokio::task::spawn_local(read_server_frames(
        stdout,
        server_frames,
    )));
    let mut completion = registry.completion();
    let mut registry_changes = registry.changes();
    let initial_admission = registry.admit_open(running.server());
    let mut connection = McpConnection {
        key: format!("stdio-{}", NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed)),
        phase: McpConnectionPhase::AwaitingInitialize,
        initialize_id: None,
        in_flight: std::collections::BTreeSet::new(),
        recorder,
        decided_calls: BTreeMap::new(),
        lists: BTreeMap::new(),
        server_requests: BTreeMap::new(),
        held: VecDeque::new(),
        policy: Arc::clone(&policy),
        governed: governed.clone(),
    };
    let mut client_frames = VecDeque::new();

    let result = if let Err(error) = initial_admission {
        Err(error)
    } else {
        let exchange = async {
            loop {
                let deadline = connection
                    .lists
                    .values()
                    .filter_map(|list| list.deadline)
                    .min();
                let event = if let Some(frame) = client_frames.pop_front() {
                    let mut exchange = Exchange {
                        running: &mut running,
                        registry: &registry,
                        frames: &frames,
                        program,
                        connection: &mut connection,
                    };
                    match handle_client_frame(frame, &mut exchange, &policy, &governed).await {
                        Ok(ProgramAction::Continue) => continue,
                        Ok(ProgramAction::Close) => break Ok(()),
                        Err(error) => break Err(error),
                    }
                } else {
                    tokio::select! {
                        input = input.recv() => ProgramEvent::Input(input),
                        output = server_output.recv() => ProgramEvent::Output(output),
                        () = sleep_until(deadline), if deadline.is_some() => ProgramEvent::ListDeadline,
                        staged = next_staged(&mut connection.held), if !connection.held.is_empty() => {
                            ProgramEvent::Staged(staged)
                        }
                        changed = completion.changed() => {
                            if changed.is_err()
                                || *completion.borrow_and_update() == CompletionOutcome::Closing
                            {
                                break Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "MCP discovery is closing",
                                ));
                            }
                            continue;
                        }
                        changed = registry_changes.changed() => {
                            // A held reply is answered first, even when its own staging failed the server.
                            if changed.is_err()
                                || (connection.held.is_empty()
                                    && registry.admit_open(running.server()).is_err())
                            {
                                break Err(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "the MCP server has a terminal discovery failure",
                                ));
                            }
                            continue;
                        }
                    }
                };
                let mut exchange = Exchange {
                    running: &mut running,
                    registry: &registry,
                    frames: &frames,
                    program,
                    connection: &mut connection,
                };
                let outcome = match event {
                    ProgramEvent::Input(Some(McpInput::Bytes(bytes))) => {
                        exchange.running.complete_frames(&bytes).map(|complete| {
                            client_frames.extend(complete);
                            ProgramAction::Continue
                        })
                    }
                    ProgramEvent::Input(Some(McpInput::Eof)) => {
                        if let Some(frame) = exchange.running.take_pending() {
                            client_frames.push_back(frame);
                        }
                        exchange
                            .running
                            .close_stdin()
                            .await
                            .map(|()| ProgramAction::Continue)
                    }
                    ProgramEvent::Input(Some(McpInput::Stop) | None) => Ok(ProgramAction::Close),
                    ProgramEvent::Output(Some(Ok(frame))) => {
                        forward_server_frame(&frame, &mut exchange).await
                    }
                    ProgramEvent::Output(Some(Err(error))) => Err(error),
                    ProgramEvent::Output(None) => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the MCP server closed stdout",
                    )),
                    ProgramEvent::ListDeadline => expire_lists(&mut exchange).await,
                    ProgramEvent::Staged(staged) => release_held_reply(staged, &mut exchange).await,
                };
                match outcome {
                    Ok(ProgramAction::Continue) => {}
                    Ok(ProgramAction::Close) => break Ok(()),
                    Err(error) => break Err(error),
                }
            }
        };
        tokio::pin!(exchange);
        tokio::select! {
            result = &mut exchange => result,
            () = wait_for_cancellation(&mut cancellation) => Ok(()),
        }
    };

    let result = match result {
        Err(error) => {
            let mut exchange = Exchange {
                running: &mut running,
                registry: &registry,
                frames: &frames,
                program,
                connection: &mut connection,
            };
            fail_pending_lists(&mut exchange).await;
            Err(error)
        }
        ok => ok,
    };
    registry.connection_closed(&connection.key);
    reader.abort_and_join().await;
    let cleanup = running.stop_and_wait().await;
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn next_staged(held: &mut VecDeque<HeldReply>) -> StagedList {
    match held.front_mut() {
        Some(reply) => reply.staged.as_mut().await,
        None => std::future::pending().await,
    }
}

/// Send the oldest held reply, or the failure that replaces it.
async fn release_held_reply(
    staged: StagedList,
    exchange: &mut Exchange<'_>,
) -> io::Result<ProgramAction> {
    let Some(reply) = exchange.connection.held.pop_front() else {
        return Ok(ProgramAction::Continue);
    };
    let server = exchange.running.server().to_string();
    match staged {
        StagedList::Released => {
            emit_text(
                exchange.frames,
                exchange.program,
                &reply.raw,
                Some(reply.release),
            )
            .await?;
            Ok(ProgramAction::Continue)
        }
        StagedList::Failed(failure) => {
            emit_list_failure(exchange, &server, failure, &reply.id, reply.release).await
        }
        StagedList::Closing => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "MCP discovery is closing",
        )),
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await,
        None => std::future::pending().await,
    }
}

async fn wait_for_cancellation(cancellation: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *cancellation.borrow_and_update() || cancellation.changed().await.is_err() {
            return;
        }
    }
}

async fn read_server_frames(
    stdout: tokio::process::ChildStdout,
    frames: tokio::sync::mpsc::Sender<io::Result<Vec<u8>>>,
) {
    let mut stdout = tokio::io::BufReader::new(stdout);
    loop {
        let frame = read_server_frame(&mut stdout).await;
        let stopped = frame.is_err();
        let sent = tokio::time::timeout(MCP_BROKER_IO_TIMEOUT, frames.send(frame)).await;
        if !matches!(sent, Ok(Ok(()))) || stopped {
            break;
        }
    }
}

/// Fail each captured list whose server has not replied in time.
async fn expire_lists(exchange: &mut Exchange<'_>) -> io::Result<ProgramAction> {
    let now = Instant::now();
    let expired: Vec<String> = exchange
        .connection
        .lists
        .iter()
        .filter(|(_, list)| list.deadline.is_some_and(|deadline| deadline <= now))
        .map(|(key, _)| key.clone())
        .collect();
    let server = exchange.running.server().to_string();
    for key in expired {
        let Some(list) = exchange.connection.lists.remove(&key) else {
            continue;
        };
        if matches!(
            exchange.registry.discovery(&server),
            Some(ServerDiscovery::Ready)
        ) {
            list_still_pending(exchange, key, list);
            continue;
        }
        exchange.connection.in_flight.remove(&key);
        exchange.registry.list_failed(
            &server,
            &exchange.connection.key,
            DiscoveryFailure::CaptureDeadline,
        );
        let release = exchange.registry.delivery();
        emit_text(
            exchange.frames,
            exchange.program,
            failure_response(&server, DiscoveryFailure::CaptureDeadline, &list.id).as_bytes(),
            Some(release),
        )
        .await?;
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "MCP discovery timed out",
        ));
    }
    Ok(ProgramAction::Continue)
}

/// Fail the lists a stopped exchange can no longer answer, unless the server is already ready.
async fn fail_pending_lists(exchange: &mut Exchange<'_>) {
    let server = exchange.running.server().to_string();
    if exchange.connection.lists.is_empty()
        || matches!(
            exchange.registry.discovery(&server),
            Some(ServerDiscovery::Ready)
        )
    {
        return;
    }
    exchange.registry.list_failed(
        &server,
        &exchange.connection.key,
        DiscoveryFailure::CatalogCapture,
    );
    for list in std::mem::take(&mut exchange.connection.lists)
        .into_values()
        .filter(|list| list.deadline.is_some())
    {
        let release = exchange.registry.delivery();
        let _ = emit_text(
            exchange.frames,
            exchange.program,
            failure_response(&server, DiscoveryFailure::CatalogCapture, &list.id).as_bytes(),
            Some(release),
        )
        .await;
    }
}

/// Keep waiting on a list whose server already has an accepted catalog.
fn list_still_pending(exchange: &mut Exchange<'_>, key: String, mut list: PendingList) {
    list.deadline = Some(Instant::now() + LIST_REPLY_TIMEOUT);
    exchange.connection.lists.insert(key, list);
}

fn parse_client_frame(frame: &str) -> io::Result<Value> {
    let request: Value = serde_json::from_str(frame.trim())
        .map_err(|error| invalid_data(format!("invalid MCP client frame: {error}")))?;
    let object = request
        .as_object()
        .ok_or_else(|| invalid_data("an MCP client frame must be an object"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(invalid_data(
            "an MCP client frame must declare JSON-RPC 2.0",
        ));
    }
    Ok(request)
}

async fn handle_client_frame(
    frame: String,
    exchange: &mut Exchange<'_>,
    policy: &PolicyEngine,
    governed: &GovernedBox,
) -> io::Result<ProgramAction> {
    let correlation = telemetry::Correlation::from_mcp(&frame);
    correlation
        .scope(async {
            // A `resources/read` is judged and forwarded with the one URI the server resolves.
            let text = egress_gateway::canonicalize_mcp_frame(frame.as_bytes())
                .map_or(frame, |canonical| {
                    String::from_utf8_lossy(&canonical).into_owned()
                });
            let request = parse_client_frame(&text)?;
            let Some(method) = request.get("method").and_then(Value::as_str) else {
                return handle_client_response(&text, &request, exchange, policy, governed).await;
            };
            let method = method.to_string();
            if method == "tools/list" {
                if exchange.connection.phase != McpConnectionPhase::Active {
                    emit_request_error(
                        exchange.frames,
                        exchange.program,
                        request.get("id"),
                        -32600,
                        "tools/list requires an initialized MCP connection",
                        None,
                    )
                    .await?;
                    return Ok(ProgramAction::Continue);
                }
                return handle_tools_list(&text, &request, exchange, policy, governed).await;
            }
            handle_request(&text, &request, &method, exchange, policy, governed).await
        })
        .await
}

/// Decide and forward the client's reply to a request the server sent.
async fn handle_client_response(
    frame: &str,
    request: &Value,
    exchange: &mut Exchange<'_>,
    policy: &PolicyEngine,
    governed: &GovernedBox,
) -> io::Result<ProgramAction> {
    let answers = request
        .get("id")
        .filter(|_| request.get("result").is_some() || request.get("error").is_some())
        .map(id_key)
        .transpose()?
        .and_then(|key| {
            exchange
                .connection
                .server_requests
                .remove(&key)
                .map(|method| (key, method))
        });
    let Some((_, method)) = answers else {
        return Err(invalid_data(
            "a client-sent JSON-RPC response that answers no request the server sent is refused",
        ));
    };
    if method == "ping" {
        // A ping reply carries nothing, so only an empty result or an error crosses undecided.
        let empty = request
            .get("result")
            .is_some_and(|result| result.as_object().is_some_and(serde_json::Map::is_empty));
        let reply = if empty || request.get("error").is_some() {
            frame.to_string()
        } else {
            serde_json::json!({"jsonrpc": "2.0", "id": request.get("id"), "result": {}}).to_string()
        };
        exchange.running.forward(&reply).await?;
        return Ok(ProgramAction::Continue);
    }
    let server = exchange.running.server().to_string();
    let decision = policy.decide(
        governed,
        &Principal::agent(),
        &Request::McpCall {
            server: &server,
            method: &method,
            tool: None,
            prompt: None,
            uri: None,
            arguments: None,
        },
    );
    let resource = format!("{server}/{method}");
    let effective =
        EffectiveDecision::from_policy(r#"Box::Action::"mcp:call""#, &resource, &decision);
    match &decision {
        Decision::Allow { .. } => {
            exchange.connection.recorder.record(effective);
            exchange.running.forward(frame).await?;
        }
        refused => {
            exchange.connection.recorder.record(effective);
            let refusal = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32001, "message": refused.to_string()},
            });
            exchange.running.forward(&refusal.to_string()).await?;
        }
    }
    Ok(ProgramAction::Continue)
}

enum ClientRequestAdmission {
    Undecided,
    Permit(Box<EffectiveDecision>),
    Refused,
}

async fn admit_client_request(
    frame: &str,
    exchange: &Exchange<'_>,
    policy: &PolicyEngine,
    governed: &GovernedBox,
    pending_is_bootstrap: bool,
) -> io::Result<ClientRequestAdmission> {
    let recorder = &exchange.connection.recorder;
    match admit_tool_call(
        policy,
        governed,
        &Principal::agent(),
        exchange.running.server(),
        frame,
    )? {
        McpRequestAdmission::Undecided => Ok(ClientRequestAdmission::Undecided),
        McpRequestAdmission::Allowed(decision) => {
            Ok(ClientRequestAdmission::Permit(Box::new(decision)))
        }
        McpRequestAdmission::PolicyPending(decision, _) if pending_is_bootstrap => {
            Ok(ClientRequestAdmission::Permit(Box::new(
                decision.into_enforcement_permit("policy-pending-bootstrap"),
            )))
        }
        McpRequestAdmission::PolicyPending(decision, refusal)
        | McpRequestAdmission::Denied {
            decision, refusal, ..
        } => {
            recorder.record(decision);
            match policy_denial_response(frame, &refusal.to_string()) {
                Some(response) => {
                    emit_text(exchange.frames, exchange.program, response.as_bytes(), None).await?;
                    Ok(ClientRequestAdmission::Refused)
                }
                None => Err(refusal),
            }
        }
    }
}

/// Reply to a request whose id is already in flight on this connection.
async fn refuse_reused_id(
    exchange: &Exchange<'_>,
    id: Option<&Value>,
) -> io::Result<ProgramAction> {
    emit_request_error(
        exchange.frames,
        exchange.program,
        id,
        -32600,
        "the MCP client reused an in-flight request id",
        None,
    )
    .await?;
    Ok(ProgramAction::Continue)
}

/// Decide a client's `tools/list`, and relay it to the server.
async fn handle_tools_list(
    frame: &str,
    request: &Value,
    exchange: &mut Exchange<'_>,
    policy: &PolicyEngine,
    governed: &GovernedBox,
) -> io::Result<ProgramAction> {
    let (key, id) = require_request_id(request)?;
    if exchange.connection.in_flight.contains(&key) {
        return refuse_reused_id(exchange, Some(&id)).await;
    }
    let cursor = match list_cursor(request) {
        Ok(cursor) => cursor,
        Err(error) => {
            emit_request_error(
                exchange.frames,
                exchange.program,
                Some(&id),
                -32602,
                &error.to_string(),
                None,
            )
            .await?;
            return Ok(ProgramAction::Continue);
        }
    };
    match admit_client_request(frame, exchange, policy, governed, true).await? {
        ClientRequestAdmission::Permit(decision) => exchange.connection.recorder.record(*decision),
        ClientRequestAdmission::Undecided => {}
        ClientRequestAdmission::Refused => {
            exchange.registry.list_denied(exchange.running.server());
            return Ok(ProgramAction::Continue);
        }
    }
    let captured = exchange.registry.captures(
        exchange.running.server(),
        &exchange.connection.key,
        cursor.as_deref(),
    );
    exchange.connection.in_flight.insert(key.clone());
    exchange.connection.lists.insert(
        key,
        PendingList {
            id,
            cursor,
            deadline: captured.then(|| Instant::now() + LIST_REPLY_TIMEOUT),
        },
    );
    exchange.running.forward(frame).await?;
    Ok(ProgramAction::Continue)
}

/// Decide and forward every client request other than `tools/list`.
async fn handle_request(
    frame: &str,
    request: &Value,
    method: &str,
    exchange: &mut Exchange<'_>,
    policy: &PolicyEngine,
    governed: &GovernedBox,
) -> io::Result<ProgramAction> {
    if method == "initialize" {
        if exchange.connection.phase != McpConnectionPhase::AwaitingInitialize {
            emit_request_error(
                exchange.frames,
                exchange.program,
                request.get("id"),
                -32600,
                "initialize is not valid in this connection phase",
                None,
            )
            .await?;
            return Ok(ProgramAction::Continue);
        }
        let (key, _) = require_request_id(request)?;
        if !exchange.connection.in_flight.insert(key.clone()) {
            return refuse_reused_id(exchange, request.get("id")).await;
        }
        exchange.connection.initialize_id = Some(key);
        exchange.running.forward(frame).await?;
        return Ok(ProgramAction::Continue);
    }

    if method == "notifications/initialized" && request.get("id").is_none() {
        if exchange.connection.phase != McpConnectionPhase::AwaitingInitialized {
            return Err(invalid_data(
                "notifications/initialized arrived before initialize completed",
            ));
        }
        exchange.running.forward(frame).await?;
        exchange.connection.phase = McpConnectionPhase::Active;
        return Ok(ProgramAction::Continue);
    }

    let request_id = optional_request_id(request)?;
    if let Some((key, id)) = &request_id
        && exchange.connection.in_flight.contains(key)
    {
        return refuse_reused_id(exchange, Some(id)).await;
    }
    let target = McpTarget::of_stdio_request(frame.as_bytes())?;
    if method == "tools/call" {
        let tool = target
            .as_ref()
            .and_then(McpTarget::tool)
            .ok_or_else(|| invalid_data("tools/call did not name a tool"))?;
        if let Err(refusal) = exchange
            .registry
            .require_listed(exchange.running.server(), tool)
        {
            let reason = match refusal {
                policy::CatalogRefusal::NotListed => refusal.to_string(),
                _ => policy::CatalogRefusal::NotAccepted.to_string(),
            };
            exchange
                .connection
                .recorder
                .record(EffectiveDecision::enforcement_deny(
                    r#"Box::Action::"mcp:call""#,
                    format!("{}/{}", exchange.running.server(), tool),
                    "mcp-catalog",
                    &reason,
                ));
            emit_request_error(
                exchange.frames,
                exchange.program,
                request.get("id"),
                -32003,
                &reason,
                None,
            )
            .await?;
            return Ok(ProgramAction::Continue);
        }
    }
    let forward = match admit_client_request(frame, exchange, policy, governed, false).await? {
        ClientRequestAdmission::Undecided => true,
        ClientRequestAdmission::Permit(decision) => {
            exchange.connection.recorder.record(*decision);
            true
        }
        ClientRequestAdmission::Refused => false,
    };
    if !forward {
        return Ok(ProgramAction::Continue);
    }
    if let Some((key, _)) = request_id {
        // Only a call that names an item records `mcp:call::response`, so listing does not count
        // toward a temporal cap.
        if let Some(target) = target
            && (target.tool().is_some() || target.prompt().is_some() || target.uri().is_some())
        {
            exchange.connection.decided_calls.insert(
                key.clone(),
                RecordedCall {
                    method: target.method().to_string(),
                    tool: target.tool().map(str::to_string),
                    prompt: target.prompt().map(str::to_string),
                    uri: target.uri().map(str::to_string),
                },
            );
        }
        exchange.connection.in_flight.insert(key);
    }
    exchange.running.forward(frame).await?;
    Ok(ProgramAction::Continue)
}

async fn forward_server_frame(
    raw: &[u8],
    exchange: &mut Exchange<'_>,
) -> io::Result<ProgramAction> {
    let response: Value = serde_json::from_slice(raw)
        .map_err(|error| invalid_data(format!("invalid MCP server frame: {error}")))?;
    let object = response
        .as_object()
        .ok_or_else(|| invalid_data("an MCP server frame must be an object"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(invalid_data(
            "an MCP server frame must declare JSON-RPC 2.0",
        ));
    }
    if let Some(method) = object.get("method") {
        if let Some(id) = object.get("id") {
            let method = method.as_str().unwrap_or_default();
            let key = id_key(id)?;
            if exchange.connection.server_requests.len() >= MAXIMUM_PENDING_SERVER_REQUESTS
                || method.len() > MAXIMUM_SERVER_REQUEST_FIELD_BYTES
                || key.len() > MAXIMUM_SERVER_REQUEST_FIELD_BYTES
            {
                let refusal = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32603, "message": "the MCP client has too many requests to answer"},
                });
                exchange.running.forward(&refusal.to_string()).await?;
                return Ok(ProgramAction::Continue);
            }
            exchange
                .connection
                .server_requests
                .insert(key, method.to_string());
        }
        emit_text(exchange.frames, exchange.program, raw, None).await?;
        return Ok(ProgramAction::Continue);
    }
    let id = object
        .get("id")
        .ok_or_else(|| invalid_data("an MCP server response has no id"))?;
    let key = id_key(id)?;
    if exchange.connection.initialize_id.as_deref() == Some(&key) {
        if object.get("error").is_some() {
            return Err(io::Error::other("MCP initialize returned an error"));
        }
        validate_initialize_result(&response)?;
        exchange.connection.phase = McpConnectionPhase::AwaitingInitialized;
        exchange.connection.initialize_id = None;
    }
    if !exchange.connection.in_flight.remove(&key) {
        return Err(invalid_data(
            "the MCP server returned an unknown response id",
        ));
    }
    if let Some(list) = exchange.connection.lists.remove(&key) {
        return forward_list_reply(raw, &response, list, exchange).await;
    }
    let response_leg = exchange.connection.decided_calls.remove(&key);
    // The reply reaches the client before its usage is recorded, so bookkeeping never drops it.
    emit_text(exchange.frames, exchange.program, raw, None).await?;
    if let Some(call) = response_leg
        && let Err(error) = exchange.connection.policy.record(
            &exchange.connection.governed,
            &Principal::agent(),
            &Outcome::Mcp {
                server: exchange.running.server(),
                method: &call.method,
                tool: call.tool.as_deref(),
                prompt: call.prompt.as_deref(),
                uri: call.uri.as_deref(),
            },
        )
    {
        eprintln!("[broker] failed to record mcp:call response leg: {error}");
    }
    Ok(ProgramAction::Continue)
}

/// Capture one `tools/list` reply, and hold the final page until its schema stages.
async fn forward_list_reply(
    raw: &[u8],
    response: &Value,
    list: PendingList,
    exchange: &mut Exchange<'_>,
) -> io::Result<ProgramAction> {
    let server = exchange.running.server().to_string();
    let page = exchange.registry.observe_page(
        &server,
        &exchange.connection.key,
        list.cursor.as_deref(),
        response,
        raw.len(),
    );
    let failure = match page {
        Ok(ListPage::More | ListPage::Ignored) => {
            emit_text(exchange.frames, exchange.program, raw, None).await?;
            return Ok(ProgramAction::Continue);
        }
        Ok(ListPage::Complete(catalog)) => {
            let release = exchange.registry.delivery();
            exchange.connection.held.push_back(HeldReply {
                staged: Box::pin(exchange.registry.stage(catalog)),
                raw: raw.to_vec(),
                id: list.id,
                release,
            });
            return Ok(ProgramAction::Continue);
        }
        Err(failure) => failure,
    };
    eprintln!("strands-box: warning: MCP server {server:?} catalog capture failed: {failure}");
    let release = exchange.registry.delivery();
    emit_list_failure(exchange, &server, failure, &list.id, release).await
}

async fn emit_list_failure(
    exchange: &mut Exchange<'_>,
    server: &str,
    failure: DiscoveryFailure,
    id: &Value,
    release: super::discovery::DiscoveryReleaseGuard,
) -> io::Result<ProgramAction> {
    emit_text(
        exchange.frames,
        exchange.program,
        failure_response(server, failure, id).as_bytes(),
        Some(release),
    )
    .await?;
    Ok(match exchange.registry.discovery(server) {
        Some(ServerDiscovery::Failed(_)) => ProgramAction::Close,
        _ => ProgramAction::Continue,
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use serde_json::json;

    use super::super::discovery::CompletionOutcome;
    use super::*;
    use crate::record::config::mcp::McpServer;
    use crate::test_support::open_policy;

    const TEST_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

    const INITIALIZE_REPLY: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"test","version":"1"}}}"#;

    struct Fixture {
        registry: Arc<DiscoveryRegistry>,
        policy: Arc<PolicyEngine>,
        _history: tempfile::TempDir,
    }

    fn fixture(text: &str) -> Fixture {
        let history = tempfile::tempdir().expect("history directory");
        let policy = Arc::new(
            PolicyEngine::open_staged(
                &policy::Operator::unanchored(),
                vec![policy::Policy {
                    origin: PathBuf::from("mcp.dw"),
                    text: text.to_string(),
                }],
                &history.path().join("dogwood.redb"),
            )
            .expect("the staged policy opens"),
        );
        let registry = DiscoveryRegistry::testing_with_policy(
            &[McpServer {
                name: "issues-mcp".to_string(),
                command: vec!["issues-mcp".to_string()],
            }],
            Arc::clone(&policy),
        );
        Fixture {
            registry,
            policy,
            _history: history,
        }
    }

    const PERMIT_ALL_MCP: &str =
        r#"permit (principal, action == Box::Action::"mcp:call", resource);"#;

    /// A server that answers `initialize`, answers each `tools/list` with `tools`, and logs every
    /// frame it reads to `$1`.
    fn listing_server(log: &Path, tools: &str, before_list: &str) -> Vec<String> {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                r#"while IFS= read -r frame; do
printf '%s\n' "$frame" >> "$1"
case "$frame" in
  *'"method":"initialize"'*)
    printf '%s\n' '{INITIALIZE_REPLY}'
    ;;
  *'"method":"tools/list"'*)
    {before_list}
    id=$(printf '%s\n' "$frame" | sed -nE 's/.*"id":("[^"]*"|[0-9]+).*/\1/p')
    printf '{{"jsonrpc":"2.0","id":%s,"result":{{"tools":{tools}}}}}\n' "$id"
    ;;
  *'"method":"notifications/initialized"'*)
    ;;
esac
done"#
            ),
            "test-mcp".to_string(),
            log.to_string_lossy().into_owned(),
        ]
    }

    const SEARCH_TOOLS: &str = r#"[{"name":"Search","inputSchema":{"type":"object","properties":{"value":{"type":"string"}}}}]"#;

    async fn exchange(
        command: Vec<String>,
        fixture: &Fixture,
    ) -> (
        McpProgram,
        tokio::sync::mpsc::Receiver<super::super::super::host::OutboundFrame>,
    ) {
        let admitted = McpServer {
            name: "issues-mcp".to_string(),
            command,
        };
        let (running, stdout) =
            RunningMcpServer::start(&admitted, Path::new("/tmp"), Path::new("/tmp"))
                .await
                .expect("the test MCP server starts");
        let (frames, output) = tokio::sync::mpsc::channel(16);
        let (program, _completion) = McpProgram::spawn(
            running,
            stdout,
            Arc::clone(&fixture.registry),
            frames,
            7,
            Arc::clone(&fixture.policy),
            GovernedBox::assigned("test-box"),
            DecisionRecorder::discarding(),
        );
        (program, output)
    }

    async fn next_output(
        output: &mut tokio::sync::mpsc::Receiver<super::super::super::host::OutboundFrame>,
    ) -> Value {
        let outbound = tokio::time::timeout(TEST_WAIT_TIMEOUT, output.recv())
            .await
            .expect("no MCP output within the test deadline")
            .expect("the MCP output channel closed");
        let crate::run::broker::protocol::Body::Output { data, .. } = outbound.frame.body else {
            panic!("non-output frame: {:?}", outbound.frame);
        };
        let bytes = crate::run::broker::protocol::decode_payload(&data).expect("output payload");
        serde_json::from_slice(&bytes).expect("the MCP output is JSON")
    }

    async fn send(program: &McpProgram, frame: Value) {
        program
            .input(format!("{frame}\n").into_bytes())
            .await
            .expect("send a client frame");
    }

    async fn initialize(
        program: &McpProgram,
        output: &mut tokio::sync::mpsc::Receiver<super::super::super::host::OutboundFrame>,
    ) {
        send(
            program,
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        )
        .await;
        assert_eq!(next_output(output).await["id"], 1);
        send(
            program,
            json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        )
        .await;
    }

    fn read_log(log: &Path) -> Vec<Value> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    fn local_runtime() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
        (
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime"),
            tokio::task::LocalSet::new(),
        )
    }

    #[test]
    fn the_final_list_reply_waits_for_its_schema_to_stage() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (gate_open, gate) = std::sync::mpsc::channel::<()>();
            let gate = std::sync::Mutex::new(gate);
            let (entered, staging) = std::sync::mpsc::channel();
            let held = std::sync::atomic::AtomicBool::new(false);
            fixture.registry.set_staging_hook(Arc::new(move |_| {
                if held.swap(true, Ordering::AcqRel) {
                    return;
                }
                let _ = entered.send(());
                let _ = gate.lock().expect("staging gate").recv();
            }));
            let (mut program, mut output) =
                exchange(listing_server(log.path(), SEARCH_TOOLS, ":"), &fixture).await;
            initialize(&program, &mut output).await;

            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            )
            .await;
            tokio::time::timeout(TEST_WAIT_TIMEOUT, async {
                while staging.try_recv().is_err() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the complete list reaches staging");
            assert!(
                tokio::time::timeout(Duration::from_millis(200), output.recv())
                    .await
                    .is_err(),
                "the final reply must wait for staging"
            );
            assert_eq!(
                fixture.registry.require_listed("issues-mcp", "Search"),
                Err(policy::CatalogRefusal::NotAccepted),
                "no tool is accepted before its schema commits"
            );
            gate_open.send(()).expect("open the staging gate");
            let reply = next_output(&mut output).await;
            assert_eq!(reply["id"], 2);
            assert_eq!(reply["result"]["tools"][0]["name"], "Search");
            assert_eq!(
                fixture.registry.require_listed("issues-mcp", "Search"),
                Ok(())
            );

            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}),
            )
            .await;
            assert_eq!(next_output(&mut output).await["id"], 3);
            let lists = read_log(log.path())
                .into_iter()
                .filter(|frame| frame["method"] == "tools/list")
                .count();
            assert_eq!(lists, 2, "each list reaches the server");
            program.stop_and_wait().await.expect("stop the exchange");
        }));
    }

    #[test]
    fn a_catalog_that_cannot_stage_replaces_the_held_reply_with_the_discovery_error() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut program, mut output) = exchange(
                listing_server(
                    log.path(),
                    r#"[{"name":"Search","inputSchema":"not a schema"}]"#,
                    ":",
                ),
                &fixture,
            )
            .await;
            initialize(&program, &mut output).await;
            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            )
            .await;
            let reply = next_output(&mut output).await;
            assert_eq!(reply["id"], 2);
            assert_eq!(reply["error"]["code"], -32002, "{reply}");
            assert!(
                reply["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("failed during schema generation")),
                "{reply}"
            );
            assert!(fixture.registry.admit_open("issues-mcp").is_err());
            let _ = program.join().await;
        }));
    }

    #[test]
    fn a_list_the_server_never_answers_fails_discovery_at_its_deadline() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut program, mut output) = exchange(
                listing_server(log.path(), SEARCH_TOOLS, "sleep 30"),
                &fixture,
            )
            .await;
            initialize(&program, &mut output).await;
            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            )
            .await;
            let reply = next_output(&mut output).await;
            assert_eq!(reply["error"]["code"], -32002);
            assert!(
                reply["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("capture deadline")),
                "{reply}"
            );
            let error = program.join().await.expect_err("the exchange times out");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(fixture.registry.admit_open("issues-mcp").is_err());
        }));
    }

    #[test]
    fn a_list_that_starts_mid_chain_is_relayed_but_not_captured() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut program, mut output) =
                exchange(listing_server(log.path(), SEARCH_TOOLS, ":"), &fixture).await;
            initialize(&program, &mut output).await;
            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": "crafted"}}),
            )
            .await;
            let reply = next_output(&mut output).await;
            assert_eq!(reply["result"]["tools"][0]["name"], "Search");
            assert_eq!(
                fixture.registry.discovery("issues-mcp"),
                Some(ServerDiscovery::Undiscovered),
                "a list that starts with a cursor is never captured"
            );
            program.stop_and_wait().await.expect("stop the exchange");
        }));
    }

    /// A server that sends one server request after `notifications/initialized` and logs every
    /// frame it reads to `$1`.
    fn requesting_server(log: &Path, request: &str) -> Vec<String> {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                r#"while IFS= read -r frame; do
printf '%s\n' "$frame" >> "$1"
case "$frame" in
  *'"method":"initialize"'*)
    printf '%s\n' '{INITIALIZE_REPLY}'
    ;;
  *'"method":"notifications/initialized"'*)
    printf '%s\n' '{request}'
    ;;
esac
done"#
            ),
            "test-mcp".to_string(),
            log.to_string_lossy().into_owned(),
        ]
    }

    async fn wait_for_logged(log: &Path, predicate: impl Fn(&Value) -> bool) -> Value {
        tokio::time::timeout(TEST_WAIT_TIMEOUT, async {
            loop {
                if let Some(frame) = read_log(log).into_iter().find(&predicate) {
                    return frame;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the server reads the expected frame")
    }

    #[test]
    fn a_server_request_reaches_the_client_and_a_permitted_reply_reaches_the_server() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut program, mut output) = exchange(
                requesting_server(
                    log.path(),
                    r#"{"jsonrpc":"2.0","id":"roots-1","method":"roots/list","params":{}}"#,
                ),
                &fixture,
            )
            .await;
            initialize(&program, &mut output).await;
            let request = next_output(&mut output).await;
            assert_eq!(request["method"], "roots/list");
            send(
                &program,
                json!({"jsonrpc": "2.0", "id": "roots-1", "result": {"roots": []}}),
            )
            .await;
            let reply = wait_for_logged(log.path(), |frame| frame["id"] == "roots-1").await;
            assert_eq!(reply["result"]["roots"], json!([]));
            program.stop_and_wait().await.expect("stop the exchange");
        }));
    }

    #[test]
    fn a_forbidden_reply_to_a_server_request_returns_an_error_to_the_server() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(&format!(
                r#"{PERMIT_ALL_MCP}
                forbid (principal, action == Box::Action::"mcp:call", resource)
                when {{ context.input.method == "elicitation/create" }};"#
            ));
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut program, mut output) = exchange(
                requesting_server(
                    log.path(),
                    r#"{"jsonrpc":"2.0","id":5,"method":"elicitation/create","params":{}}"#,
                ),
                &fixture,
            )
            .await;
            initialize(&program, &mut output).await;
            assert_eq!(next_output(&mut output).await["method"], "elicitation/create");
            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 5, "result": {"action": "accept", "content": {"secret": "x"}}}),
            )
            .await;
            let reply = wait_for_logged(log.path(), |frame| frame["id"] == 5).await;
            assert_eq!(reply["error"]["code"], -32001);
            assert!(
                reply.get("result").is_none(),
                "the client's answer must not reach the server"
            );
            program.stop_and_wait().await.expect("stop the exchange");
        }));
    }

    #[test]
    fn a_reply_to_a_server_ping_crosses_undecided() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(&format!(
                r#"{PERMIT_ALL_MCP}
                forbid (principal, action == Box::Action::"mcp:call", resource)
                when {{ context.input.method == "ping" }};"#
            ));
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut program, mut output) = exchange(
                requesting_server(log.path(), r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#),
                &fixture,
            )
            .await;
            initialize(&program, &mut output).await;
            assert_eq!(next_output(&mut output).await["method"], "ping");
            send(&program, json!({"jsonrpc": "2.0", "id": 9, "result": {}})).await;
            let reply = wait_for_logged(log.path(), |frame| frame["id"] == 9).await;
            assert_eq!(reply["result"], json!({}));
            program.stop_and_wait().await.expect("stop the exchange");
        }));
    }

    #[test]
    fn an_unsolicited_or_repeated_client_reply_is_refused() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            for (name, replies) in [
                (
                    "unsolicited",
                    vec![json!({"jsonrpc": "2.0", "id": "never-asked", "result": {}})],
                ),
                (
                    "repeated",
                    vec![
                        json!({"jsonrpc": "2.0", "id": "roots-1", "result": {"roots": []}}),
                        json!({"jsonrpc": "2.0", "id": "roots-1", "result": {"roots": []}}),
                    ],
                ),
            ] {
                let fixture = fixture(PERMIT_ALL_MCP);
                let log = tempfile::NamedTempFile::new().expect("frame log");
                let (mut program, mut output) = exchange(
                    requesting_server(
                        log.path(),
                        r#"{"jsonrpc":"2.0","id":"roots-1","method":"roots/list","params":{}}"#,
                    ),
                    &fixture,
                )
                .await;
                initialize(&program, &mut output).await;
                assert_eq!(next_output(&mut output).await["method"], "roots/list");
                for reply in replies {
                    let _ = program.input(format!("{reply}\n").into_bytes()).await;
                }
                let error = tokio::time::timeout(TEST_WAIT_TIMEOUT, program.join())
                    .await
                    .unwrap_or_else(|_| panic!("{name}: the exchange must stop"))
                    .expect_err("the stray reply must refuse the exchange");
                assert!(
                    error
                        .to_string()
                        .contains("answers no request the server sent"),
                    "{name}: {error}"
                );
                let delivered = read_log(log.path())
                    .into_iter()
                    .filter(|frame| frame.get("result").is_some())
                    .count();
                assert!(
                    delivered <= 1,
                    "{name}: at most one reply reaches the server"
                );
            }
        }));
    }

    #[test]
    fn two_connections_listing_at_once_accept_one_catalog() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let first_log = tempfile::NamedTempFile::new().expect("frame log");
            let second_log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut first, mut first_output) = exchange(
                listing_server(first_log.path(), SEARCH_TOOLS, ":"),
                &fixture,
            )
            .await;
            let (mut second, mut second_output) = exchange(
                listing_server(second_log.path(), SEARCH_TOOLS, ":"),
                &fixture,
            )
            .await;
            initialize(&first, &mut first_output).await;
            initialize(&second, &mut second_output).await;
            let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}});
            send(&first, list.clone()).await;
            send(&second, list).await;
            assert_eq!(next_output(&mut first_output).await["id"], 2);
            assert_eq!(next_output(&mut second_output).await["id"], 2);
            assert_eq!(
                fixture.registry.require_listed("issues-mcp", "Search"),
                Ok(())
            );
            first
                .stop_and_wait()
                .await
                .expect("stop the first exchange");
            second
                .stop_and_wait()
                .await
                .expect("stop the second exchange");
        }));
    }

    #[test]
    fn an_unsupported_protocol_version_refuses_the_exchange() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let reply = INITIALIZE_REPLY.replace("2024-11-05", "2099-01-01");
            let (mut program, _output) = exchange(
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    format!("IFS= read -r frame; printf '%s\\n' '{reply}'; sleep 30"),
                ],
                &fixture,
            )
            .await;
            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            )
            .await;
            let error = tokio::time::timeout(TEST_WAIT_TIMEOUT, program.join())
                .await
                .expect("the exchange stops")
                .expect_err("an unsupported revision refuses the exchange");
            assert!(
                error.to_string().contains("unsupported protocol version"),
                "{error}"
            );
        }));
    }

    async fn next_frame(
        output: &mut tokio::sync::mpsc::Receiver<super::super::super::host::OutboundFrame>,
    ) -> (Value, super::super::super::host::OutboundFrame) {
        let outbound = tokio::time::timeout(TEST_WAIT_TIMEOUT, output.recv())
            .await
            .expect("no MCP output within the test deadline")
            .expect("the MCP output channel closed");
        let crate::run::broker::protocol::Body::Output { data, .. } = &outbound.frame.body else {
            panic!("non-output frame: {:?}", outbound.frame);
        };
        let bytes = crate::run::broker::protocol::decode_payload(data).expect("output payload");
        (
            serde_json::from_slice(&bytes).expect("the MCP output is JSON"),
            outbound,
        )
    }

    #[test]
    fn discovery_completes_only_after_the_held_reply_reaches_the_client() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let mut completion = fixture.registry.completion();
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut program, mut output) =
                exchange(listing_server(log.path(), SEARCH_TOOLS, ":"), &fixture).await;
            initialize(&program, &mut output).await;
            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            )
            .await;
            let (reply, outbound) = next_frame(&mut output).await;
            assert_eq!(reply["id"], 2);
            assert!(
                outbound.release.is_some(),
                "the held reply carries the door open"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(
                *completion.borrow_and_update() == CompletionOutcome::Pending,
                "discovery must not complete before the reply is delivered"
            );
            drop(outbound);
            tokio::time::timeout(TEST_WAIT_TIMEOUT, async {
                while *completion.borrow_and_update() != CompletionOutcome::Finished {
                    completion
                        .changed()
                        .await
                        .expect("completion stays connected");
                }
            })
            .await
            .expect("discovery completes once the reply is delivered");
            program.stop_and_wait().await.expect("stop the exchange");
        }));
    }

    #[test]
    fn server_frames_keep_flowing_while_a_schema_stages() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let held = std::sync::atomic::AtomicBool::new(false);
            fixture.registry.set_staging_hook(Arc::new(move |_| {
                if !held.swap(true, Ordering::AcqRel) {
                    std::thread::sleep(MCP_BROKER_IO_TIMEOUT + Duration::from_secs(1));
                }
            }));
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let notifications = (0..12)
                .map(|index| {
                    format!(
                        r#"printf '%s\n' '{{"jsonrpc":"2.0","method":"notifications/message","params":{{"n":{index}}}}}'"#
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            let mut command = listing_server(log.path(), SEARCH_TOOLS, ":");
            command[2] = command[2].replace(
                "    ;;\n  *'\"method\":\"notifications/initialized\"'*)",
                &format!(
                    "    {notifications}\n    ;;\n  *'\"method\":\"notifications/initialized\"'*)"
                ),
            );
            assert!(command[2].contains("notifications/message"));
            let (mut program, mut output) = exchange(command, &fixture).await;
            initialize(&program, &mut output).await;
            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            )
            .await;
            let mut seen = 0;
            let mut reply = None;
            while reply.is_none() || seen < 12 {
                let frame = next_output(&mut output).await;
                if frame["method"] == "notifications/message" {
                    seen += 1;
                } else {
                    reply = Some(frame);
                }
            }
            assert_eq!(reply.expect("the list reply arrives")["id"], 2);
            send(&program, json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})).await;
            loop {
                let frame = next_output(&mut output).await;
                if frame["id"] == 3 {
                    break;
                }
            }
            program.stop_and_wait().await.expect("the exchange survived the staging delay");
        }));
    }

    #[test]
    fn a_ping_reply_carries_no_payload_to_the_server() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut program, mut output) = exchange(
                requesting_server(log.path(), r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#),
                &fixture,
            )
            .await;
            initialize(&program, &mut output).await;
            assert_eq!(next_output(&mut output).await["method"], "ping");
            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 9, "result": {"secret": "workspace contents"}}),
            )
            .await;
            let reply = wait_for_logged(log.path(), |frame| frame["id"] == 9).await;
            assert_eq!(reply["result"], json!({}));
            program.stop_and_wait().await.expect("stop the exchange");
        }));
    }

    #[test]
    fn an_oversized_server_request_is_refused_and_not_forwarded() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let method = "x".repeat(MAXIMUM_SERVER_REQUEST_FIELD_BYTES + 1);
            let (mut program, mut output) = exchange(
                requesting_server(
                    log.path(),
                    &format!(r#"{{"jsonrpc":"2.0","id":4,"method":"{method}"}}"#),
                ),
                &fixture,
            )
            .await;
            initialize(&program, &mut output).await;
            let refusal = wait_for_logged(log.path(), |frame| frame["id"] == 4).await;
            assert_eq!(refusal["error"]["code"], -32603);
            assert!(
                tokio::time::timeout(Duration::from_millis(200), output.recv())
                    .await
                    .is_err(),
                "the refused request must not reach the client"
            );
            program.stop_and_wait().await.expect("stop the exchange");
        }));
    }

    #[test]
    fn a_list_that_is_not_captured_cannot_fail_discovery() {
        let (runtime, local) = local_runtime();
        runtime.block_on(local.run_until(async {
            let fixture = fixture(PERMIT_ALL_MCP);
            let log = tempfile::NamedTempFile::new().expect("frame log");
            let (mut program, mut output) =
                exchange(listing_server(log.path(), SEARCH_TOOLS, "sleep 30"), &fixture).await;
            initialize(&program, &mut output).await;
            send(
                &program,
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": "crafted"}}),
            )
            .await;
            tokio::time::sleep(LIST_REPLY_TIMEOUT + Duration::from_secs(1)).await;
            assert_eq!(
                fixture.registry.discovery("issues-mcp"),
                Some(ServerDiscovery::Undiscovered)
            );
            assert!(fixture.registry.admit_open("issues-mcp").is_ok());
            program.stop_and_wait().await.expect("stop the exchange");
        }));
    }

    #[test]
    fn a_registry_with_no_stdio_server_reports_done_once() {
        let fixture_policy = Arc::new(crate::test_support::open_policy(Vec::new()));
        let registry = DiscoveryRegistry::testing_with_policy(&[], fixture_policy);
        registry.request_completion_check();
        registry.request_completion_check();
        assert_eq!(registry.completion_claims(), 1);
    }

    fn policy(text: &str) -> PolicyEngine {
        open_policy(vec![policy::Policy {
            origin: PathBuf::from("mcp.dw"),
            text: text.to_string(),
        }])
    }

    fn registry() -> Arc<DiscoveryRegistry> {
        DiscoveryRegistry::testing(&[McpServer {
            name: "issues-mcp".to_string(),
            command: vec!["issues-mcp".to_string()],
        }])
    }

    async fn test_exchange(
        command: Vec<String>,
        registry: Arc<DiscoveryRegistry>,
        policy: Arc<PolicyEngine>,
    ) -> (
        McpProgram,
        tokio::sync::mpsc::Receiver<super::super::super::host::OutboundFrame>,
    ) {
        let (program, output, _recorder) =
            test_exchange_with_recorder(command, registry, policy).await;
        (program, output)
    }

    async fn test_exchange_with_recorder(
        command: Vec<String>,
        registry: Arc<DiscoveryRegistry>,
        policy: Arc<PolicyEngine>,
    ) -> (
        McpProgram,
        tokio::sync::mpsc::Receiver<super::super::super::host::OutboundFrame>,
        Arc<DecisionRecorder>,
    ) {
        let admitted = McpServer {
            name: "issues-mcp".to_string(),
            command,
        };
        let (running, stdout) =
            RunningMcpServer::start(&admitted, Path::new("/tmp"), Path::new("/tmp"))
                .await
                .expect("the test MCP server starts");
        let (frames, output) = tokio::sync::mpsc::channel(16);
        let recorder = DecisionRecorder::discarding();
        let (program, _completion) = McpProgram::spawn(
            running,
            stdout,
            registry,
            frames,
            7,
            policy,
            GovernedBox::assigned("test-box"),
            Arc::clone(&recorder),
        );
        (program, output, recorder)
    }

    async fn next_exchange_output(
        output: &mut tokio::sync::mpsc::Receiver<super::super::super::host::OutboundFrame>,
    ) -> (
        Value,
        Option<super::super::discovery::DiscoveryReleaseGuard>,
    ) {
        let outbound = tokio::time::timeout(TEST_WAIT_TIMEOUT, output.recv())
            .await
            .expect("MCP exchange wait error: no output within the test deadline")
            .expect("MCP exchange error: the output channel closed");
        let crate::run::broker::protocol::Body::Output { data, .. } = outbound.frame.body else {
            panic!("MCP exchange error: non-output frame: {:?}", outbound.frame);
        };
        let bytes = crate::run::broker::protocol::decode_payload(&data).expect("output payload");
        (
            serde_json::from_slice(&bytes).expect("the MCP output is JSON"),
            outbound.release,
        )
    }

    async fn initialize_exchange(
        program: &McpProgram,
        output: &mut tokio::sync::mpsc::Receiver<super::super::super::host::OutboundFrame>,
    ) {
        program
            .input(
                br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
"#
                .to_vec(),
            )
            .await
            .expect("send initialize");
        let (response, release) = next_exchange_output(output).await;
        assert_eq!(response["id"], 1);
        assert!(release.is_none());
        program
            .input(
                br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
"#
                .to_vec(),
            )
            .await
            .expect("send initialized");
    }

    fn responsive_server_script(list_marker: Option<&Path>) -> Vec<String> {
        let marker = list_marker
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            r#"while IFS= read -r frame; do
case "$frame" in
  *'"method":"initialize"'*)
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"test","version":"1"}}}'
    ;;
  *'"method":"tools/list"'*)
    test -z "$1" || printf list >> "$1"
    id=$(printf '%s\n' "$frame" | sed -nE 's/.*"id":("[^"]*"|[0-9]+).*/\1/p')
    sleep 0.05
    printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"Search","inputSchema":{"type":"object"}}]}}\n' "$id"
    ;;
  *'"method":"ping"'*)
    printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{}}'
    ;;
esac
done"#
                .to_string(),
            "test-mcp".to_string(),
            marker,
        ]
    }

    #[test]
    fn a_root_list_before_initialize_leaves_discovery_undiscovered() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let local = tokio::task::LocalSet::new();
        runtime.block_on(local.run_until(async {
            let registry = registry();
            let (mut program, mut output) = test_exchange(
                responsive_server_script(None),
                Arc::clone(&registry),
                Arc::new(policy("")),
            )
            .await;

            program
                .input(
                    br#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
"#
                    .to_vec(),
                )
                .await
                .expect("send root list before initialize");
            let (refusal, release) = next_exchange_output(&mut output).await;
            assert_eq!(refusal["id"], 2);
            assert_eq!(refusal["error"]["code"], -32600);
            assert!(release.is_none());
            assert_eq!(
                registry.discovery("issues-mcp"),
                Some(ServerDiscovery::Undiscovered)
            );

            program.stop_and_wait().await.expect("stop exchange");
        }));
    }

    #[test]
    fn invalid_server_frames_stop_and_refuse_the_exchange() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let local = tokio::task::LocalSet::new();
        runtime.block_on(local.run_until(async {
            for (name, frame, expected) in [
                (
                    "unknown-response",
                    r#"{"jsonrpc":"2.0","id":99,"result":{}}"#,
                    "unknown response id",
                ),
                ("batch", r#"[{"jsonrpc":"2.0"}]"#, "must be an object"),
                ("bare-value", "17", "must be an object"),
                ("malformed-json", "{not-json", "invalid MCP server frame"),
            ] {
                let admitted = McpServer {
                    name: name.to_string(),
                    command: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "printf '%s\n' \"$1\"; sleep 30".to_string(),
                        "invalid-server".to_string(),
                        frame.to_string(),
                    ],
                };
                let (running, stdout) =
                    RunningMcpServer::start(&admitted, Path::new("/tmp"), Path::new("/tmp"))
                        .await
                        .expect("the invalid-frame server starts");
                let (frames, mut output) = tokio::sync::mpsc::channel(1);
                let (mut program, completion) = McpProgram::spawn(
                    running,
                    stdout,
                    DiscoveryRegistry::testing(std::slice::from_ref(&admitted)),
                    frames,
                    7,
                    Arc::new(policy("")),
                    GovernedBox::assigned("test-box"),
                    DecisionRecorder::discarding(),
                );

                tokio::time::timeout(Duration::from_secs(3), completion)
                    .await
                    .unwrap_or_else(|_| panic!("{name} did not stop the exchange"))
                    .expect("the completion signal remains connected");
                let error = program
                    .join()
                    .await
                    .expect_err("the invalid server frame must refuse the exchange");
                assert!(
                    error.to_string().contains(expected),
                    "{name} returned the wrong refusal: {error}"
                );
                assert!(
                    output.recv().await.is_none(),
                    "{name} must not forward the invalid frame"
                );
            }
        }));
    }

    #[test]
    fn an_existing_terminal_failure_stops_and_reaps_a_new_exchange() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let local = tokio::task::LocalSet::new();
        runtime.block_on(local.run_until(async {
            let registry = registry();
            registry.list_failed("issues-mcp", "earlier", DiscoveryFailure::CatalogCapture);

            let admitted = McpServer {
                name: "issues-mcp".to_string(),
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "while :; do sleep 30; done".to_string(),
                ],
            };
            let (mut running, stdout) =
                RunningMcpServer::start(&admitted, Path::new("/tmp"), Path::new("/tmp"))
                    .await
                    .expect("the test MCP server starts");
            let reaped = running.observe_stop_and_wait_completion();
            let (frames, _output) = tokio::sync::mpsc::channel(1);
            let (mut program, completion) = McpProgram::spawn(
                running,
                stdout,
                registry,
                frames,
                7,
                Arc::new(policy("")),
                GovernedBox::assigned("test-box"),
                DecisionRecorder::discarding(),
            );

            tokio::time::timeout(Duration::from_secs(3), completion)
                .await
                .expect("the terminal failure stops the exchange")
                .expect("the completion signal remains connected");
            let error = program
                .join()
                .await
                .expect_err("the terminal failure must refuse the exchange");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains("failed during catalog capture"));
            reaped
                .await
                .expect("the failed exchange reports only after child reap");
        }));
    }

    #[test]
    fn a_tool_call_before_list_returns_an_error_and_the_exchange_remains_usable() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let local = tokio::task::LocalSet::new();
        runtime.block_on(local.run_until(async {
            let registry = registry();
            let (mut program, mut output) = test_exchange(
                responsive_server_script(None),
                Arc::clone(&registry),
                Arc::new(policy("")),
            )
            .await;
            initialize_exchange(&program, &mut output).await;

            program
                .input(
                    br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"Search","arguments":{}}}
"#
                    .to_vec(),
                )
                .await
                .expect("send premature tool call");
            let (refusal, release) = next_exchange_output(&mut output).await;
            assert_eq!(refusal["id"], 2);
            assert_eq!(refusal["error"]["code"], -32003);
            assert!(release.is_none());
            assert_eq!(
                registry.discovery("issues-mcp"),
                Some(ServerDiscovery::Undiscovered)
            );

            program
                .input(
                    br#"{"jsonrpc":"2.0","id":3,"method":"ping","params":{}}
"#
                    .to_vec(),
                )
                .await
                .expect("send ping after refusal");
            let (ping, release) = next_exchange_output(&mut output).await;
            assert_eq!(ping["id"], 3);
            assert!(ping.get("result").is_some());
            assert!(release.is_none());
            program.stop_and_wait().await.expect("stop exchange");
        }));
    }

    #[test]
    fn saturated_input_cannot_hide_stop_or_prevent_reap() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let local = tokio::task::LocalSet::new();
        runtime.block_on(local.run_until(async {
            let (mut running, stdout) = non_reading_server().await;
            let reaped = running.observe_stop_and_wait_completion();
            let (frames, _output) = tokio::sync::mpsc::channel(1);
            let registry = DiscoveryRegistry::testing(&[McpServer {
                name: "non-reading-server".to_string(),
                command: vec!["unused".to_string()],
            }]);
            let (mut program, _completion) = McpProgram::spawn(
                running,
                stdout,
                registry,
                frames,
                7,
                Arc::new(policy("")),
                GovernedBox::assigned("test-box"),
                DecisionRecorder::discarding(),
            );
            let padding = "x".repeat(crate::run::broker::protocol::MAX_FRAME_BYTES / 2);
            program
                .input(
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"padding\":\"{padding}\"}}}}\n"
                    )
                    .into_bytes(),
                )
                .await
                .expect("queue the blocking child write");
            tokio::time::timeout(Duration::from_secs(1), async {
                while program.input_capacity() != MCP_INPUT_CHANNEL_CAPACITY {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the exchange starts the child write");
            for _ in 0..MCP_INPUT_CHANNEL_CAPACITY {
                program
                    .input(b" ".to_vec())
                    .await
                    .expect("fill the input queue");
            }
            let error = program
                .input(b" ".to_vec())
                .await
                .expect_err("a saturated input queue must time out");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);

            let started = Instant::now();
            program.stop_and_wait().await.expect("stop and join exchange");
            assert!(
                started.elapsed() < MCP_BROKER_IO_TIMEOUT,
                "out-of-band cancellation must bypass the saturated queue"
            );
            reaped
                .await
                .expect("normal stop reports only after child reap");
        }));
    }

    #[test]
    fn dropping_a_program_cancels_its_exchange_and_reaps_its_child() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let local = tokio::task::LocalSet::new();
        runtime.block_on(local.run_until(async {
            let (mut running, stdout) = non_reading_server().await;
            let reaped = running.observe_stop_and_wait_completion();
            let (frames, _output) = tokio::sync::mpsc::channel(1);
            let (program, _completion) = McpProgram::spawn(
                running,
                stdout,
                registry(),
                frames,
                7,
                Arc::new(policy("")),
                GovernedBox::assigned("test-box"),
                DecisionRecorder::discarding(),
            );

            drop(program);
            tokio::time::timeout(Duration::from_secs(3), reaped)
                .await
                .expect("drop cancellation reaches cleanup")
                .expect("drop cleanup reaps the child");
        }));
    }

    async fn non_reading_server() -> (RunningMcpServer, tokio::process::ChildStdout) {
        let admitted = McpServer {
            name: "non-reading-server".to_string(),
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "while :; do sleep 30; done".to_string(),
            ],
        };
        RunningMcpServer::start(&admitted, Path::new("/tmp"), Path::new("/tmp"))
            .await
            .expect("the non-reading server starts")
    }
}
