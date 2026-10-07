//! One MCP server process: its start, its framing, and the offline `tools/list` client.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::AsyncBufReadExt as _;

use crate::record::config::mcp::McpServer;

/// The MCP protocol version the offline `tools/list` client requests.
const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// The MCP protocol revisions approved for this broker.
pub(super) const SUPPORTED_MCP_PROTOCOL_VERSIONS: [&str; 4] = [
    MCP_PROTOCOL_VERSION,
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
];

/// How long one `tools/list` may take before discovery fails.
pub(super) const MCP_DISCOVERY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long general MCP broker I/O can wait.
pub(super) const MCP_BROKER_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// The most raw response text the offline client accepts for one catalog.
const MAXIMUM_DISCOVERY_RESPONSE_BYTES: usize = policy::MAXIMUM_LIST_BYTES;

/// One running MCP server: the child, and the stdin it is fed.
pub(crate) struct RunningMcpServer {
    /// The server name, for the decisions each later frame raises.
    server: String,
    /// The child's standard input.
    stdin: Option<tokio::process::ChildStdin>,
    /// The child itself, kept so dropping this handle kills it.
    child: tokio::process::Child,
    /// The process group remains addressable after the leader exits.
    #[cfg(unix)]
    process_group: libc::pid_t,

    /// The task streaming this child's stdout back to the client.
    #[cfg(test)]
    output: Option<tokio::task::JoinHandle<()>>,
    /// Received BYTES that do not yet complete a line.
    pending: Vec<u8>,
    #[cfg(test)]
    stop_and_wait_completion: Option<tokio::sync::oneshot::Sender<()>>,

    /// What a contained server must keep alive for its lifetime: the leaf's boundary (open
    /// containment-config descriptor) and its netns relays (Linux). `child` and `process_group`
    /// are the leaf's own child and leader, so every kill, wait, and drop path is identical to the
    /// uncontained case; this retention just rides along. `None` for an uncontained server.
    #[cfg(unix)]
    _leaf_retention: Option<crate::run::contain::supervise::StreamingLeafRetention>,
}

/// The most unterminated frame text one server may accumulate.
const MAXIMUM_PENDING_FRAME_BYTES: usize = crate::run::broker::protocol::MAX_FRAME_BYTES;

pub(crate) enum McpToolDiscoveryError {
    Cancelled,
    Discovery(io::Error),
    Cleanup(io::Error),
}

/// Start one declared MCP server, initialize it, and return its `tools/list` response.
pub(crate) async fn list_tools(admitted: &McpServer, home: &Path, cwd: &Path) -> io::Result<Value> {
    match list_tools_until_cancelled(
        admitted,
        home,
        cwd,
        std::future::pending(),
        MAXIMUM_DISCOVERY_RESPONSE_BYTES,
    )
    .await
    {
        Ok(tools) => Ok(tools),
        Err(McpToolDiscoveryError::Cancelled) => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "MCP discovery was cancelled",
        )),
        Err(McpToolDiscoveryError::Discovery(error) | McpToolDiscoveryError::Cleanup(error)) => {
            Err(error)
        }
    }
}

async fn list_tools_until_cancelled(
    admitted: &McpServer,
    home: &Path,
    cwd: &Path,
    cancellation: impl std::future::Future<Output = ()>,
    maximum_response_bytes: usize,
) -> Result<Value, McpToolDiscoveryError> {
    let (running, stdout) = RunningMcpServer::start(admitted, home, cwd)
        .await
        .map_err(McpToolDiscoveryError::Discovery)?;
    list_tools_from_running_server_until_cancelled(
        running,
        stdout,
        cancellation,
        maximum_response_bytes,
        MCP_DISCOVERY_RESPONSE_TIMEOUT,
    )
    .await
}

async fn list_tools_from_running_server_until_cancelled(
    mut running: RunningMcpServer,
    stdout: tokio::process::ChildStdout,
    cancellation: impl std::future::Future<Output = ()>,
    maximum_response_bytes: usize,
    response_timeout: Duration,
) -> Result<Value, McpToolDiscoveryError> {
    let result = {
        let mut stdout = tokio::io::BufReader::new(stdout);
        tokio::select! {
            biased;
            () = cancellation => Err(McpToolDiscoveryError::Cancelled),
            result = tokio::time::timeout(
                response_timeout,
                list_tools_before_deadline(&mut running, &mut stdout, maximum_response_bytes),
            ) => result.map_err(|_| McpToolDiscoveryError::Discovery(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "MCP discovery did not complete within {} seconds",
                        response_timeout.as_secs()
                    ),
                )))
                .and_then(|result| result.map_err(McpToolDiscoveryError::Discovery)),
        }
    };
    running
        .stop_and_wait()
        .await
        .map_err(McpToolDiscoveryError::Cleanup)?;
    result
}

async fn list_tools_before_deadline(
    running: &mut RunningMcpServer,
    stdout: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
    maximum_response_bytes: usize,
) -> io::Result<Value> {
    send_json(
        running,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "strands-box",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }),
    )
    .await?;
    let (initialized, _) = read_response(running, stdout, 1).await?;
    validate_initialize_result(&initialized)?;

    send_json(
        running,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
    )
    .await?;

    let mut tools = Vec::new();
    let mut tool_names = BTreeSet::new();
    let mut type_definitions = serde_json::Map::new();
    let mut cursor = None;
    let mut seen_cursors = BTreeSet::new();
    let mut request_id = 2_u64;
    let mut response_bytes = 0;
    loop {
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |cursor| json!({ "cursor": cursor }));
        send_json(
            running,
            &json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/list",
                "params": params
            }),
        )
        .await?;
        let (response, page_bytes) = read_response(running, stdout, request_id).await?;
        admit_discovery_response_bytes(&mut response_bytes, page_bytes, maximum_response_bytes)?;
        let result = response
            .get("result")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_data("MCP tools/list result is not an object"))?;
        let page = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_data("MCP tools/list result has no tools array"))?;
        for tool in page {
            let name = tool.get("name").and_then(Value::as_str).ok_or_else(|| {
                invalid_data("MCP tools/list contains a tool with no string name")
            })?;
            if !tool_names.insert(name.to_string()) {
                return Err(invalid_data(format!(
                    "MCP tools/list repeated the tool name {name:?}"
                )));
            }
            tools.push(tool.clone());
        }
        if let Some(definitions) = result.get("$defs") {
            let definitions = definitions
                .as_object()
                .ok_or_else(|| invalid_data("MCP tools/list $defs is not an object"))?;
            for (name, definition) in definitions {
                match type_definitions.get(name) {
                    Some(previous) if previous != definition => {
                        return Err(invalid_data(format!(
                            "MCP tools/list changed the $defs entry {name:?} between pages"
                        )));
                    }
                    Some(_) => {}
                    None => {
                        type_definitions.insert(name.clone(), definition.clone());
                    }
                }
            }
        }

        cursor = match result.get("nextCursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(next)) => Some(next.clone()),
            Some(_) => {
                return Err(invalid_data(
                    "MCP tools/list nextCursor is not a string or null",
                ));
            }
        };
        let Some(next) = cursor.as_ref() else {
            break;
        };
        if !seen_cursors.insert(next.clone()) {
            return Err(invalid_data("MCP tools/list repeated its nextCursor"));
        }
        request_id = request_id
            .checked_add(1)
            .ok_or_else(|| invalid_data("MCP tools/list used too many pages"))?;
    }

    let mut result = serde_json::Map::new();
    result.insert("tools".to_string(), Value::Array(tools));
    if !type_definitions.is_empty() {
        result.insert("$defs".to_string(), Value::Object(type_definitions));
    }
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": result
    }))
}

fn admit_discovery_response_bytes(
    total: &mut usize,
    page: usize,
    maximum: usize,
) -> io::Result<()> {
    let next = total.saturating_add(page);
    if next > maximum {
        return Err(invalid_data(format!(
            "MCP tools/list responses exceeded the {maximum}-byte aggregate maximum"
        )));
    }
    *total = next;
    Ok(())
}

async fn send_json(running: &mut RunningMcpServer, value: &Value) -> io::Result<()> {
    let frame = serde_json::to_string(value)
        .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))?;
    running.forward(&frame).await
}

async fn read_response(
    running: &mut RunningMcpServer,
    stdout: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
    expected_id: u64,
) -> io::Result<(Value, usize)> {
    loop {
        let frame = read_server_frame(stdout).await?;
        let frame_bytes = frame.len();
        let response: Value = serde_json::from_slice(&frame).map_err(|source| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("MCP server wrote an invalid JSON-RPC frame: {source}"),
            )
        })?;
        if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(invalid_data(
                "MCP server response does not declare JSON-RPC 2.0",
            ));
        }
        if response.get("method").is_some() {
            answer_server_request(running, &response).await?;
            continue;
        }
        let Some(id) = response.get("id") else {
            return Err(invalid_data("MCP server response has no id"));
        };
        if id.as_u64() != Some(expected_id) {
            return Err(invalid_data(format!(
                "MCP server answered request {id}, expected request {expected_id}"
            )));
        }
        if response.get("error").is_some() {
            return Err(io::Error::other(format!(
                "MCP server returned an error for request {expected_id}"
            )));
        }
        if response.get("result").is_none() {
            return Err(invalid_data(format!(
                "MCP server response {expected_id} has no result"
            )));
        }
        return Ok((response, frame_bytes));
    }
}

async fn answer_server_request(running: &mut RunningMcpServer, request: &Value) -> io::Result<()> {
    let Some(id) = request.get("id").filter(|id| !id.is_null()) else {
        return Ok(());
    };
    let response = if request.get("method").and_then(Value::as_str) == Some("ping") {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        })
    } else {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        })
    };
    send_json(running, &response).await
}

pub(super) fn validate_initialize_result(response: &Value) -> io::Result<()> {
    let result = response
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_data("MCP initialize result is not an object"))?;
    match result.get("protocolVersion").and_then(Value::as_str) {
        Some(version) if SUPPORTED_MCP_PROTOCOL_VERSIONS.contains(&version) => {}
        Some(version) => {
            return Err(invalid_data(format!(
                "MCP server selected unsupported protocol version {version:?}"
            )));
        }
        None => return Err(invalid_data("MCP initialize result has no protocolVersion")),
    }
    let capabilities = result
        .get("capabilities")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_data("MCP initialize result has no capabilities object"))?;
    if !capabilities.get("tools").is_some_and(Value::is_object) {
        return Err(invalid_data(
            "MCP initialize result does not advertise the tools capability",
        ));
    }
    let server = result
        .get("serverInfo")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_data("MCP initialize result has no serverInfo object"))?;
    if !server.get("name").is_some_and(Value::is_string)
        || !server.get("version").is_some_and(Value::is_string)
    {
        return Err(invalid_data(
            "MCP initialize serverInfo must contain string name and version fields",
        ));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub(super) async fn read_server_frame(
    stdout: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
) -> io::Result<Vec<u8>> {
    let mut frame = Vec::new();
    loop {
        let available = stdout.fill_buf().await?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "MCP server closed stdout before it sent a complete response",
            ));
        }
        let length = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if frame.len() + length > crate::run::broker::protocol::MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "MCP server response exceeded {} bytes",
                    crate::run::broker::protocol::MAX_FRAME_BYTES
                ),
            ));
        }
        frame.extend_from_slice(&available[..length]);
        stdout.consume(length);
        if frame.last() == Some(&b'\n') {
            if frame.iter().all(u8::is_ascii_whitespace) {
                frame.clear();
                continue;
            }
            return Ok(frame);
        }
    }
}

impl RunningMcpServer {
    /// Start an admitted server, with its output streaming back through `emit`.
    pub(crate) async fn start(
        admitted: &McpServer,
        home: &Path,
        cwd: &Path,
    ) -> io::Result<(Self, tokio::process::ChildStdout)> {
        Self::start_with(admitted, home, Some(cwd), None).await
    }

    /// Start an admitted server in an already-open working directory.
    pub(crate) async fn start_in_opened_directory(
        admitted: &McpServer,
        home: &Path,
        cwd: &std::fs::File,
    ) -> io::Result<(Self, tokio::process::ChildStdout)> {
        Self::start_with(admitted, home, None, Some(cwd)).await
    }

    async fn start_with(
        admitted: &McpServer,
        home: &Path,
        cwd: Option<&Path>,
        cwd_handle: Option<&std::fs::File>,
    ) -> io::Result<(Self, tokio::process::ChildStdout)> {
        let mut command = tokio::process::Command::new(admitted.program());
        command
            .args(admitted.arguments())
            .env_clear()
            .env("HOME", home)
            .env(
                "PATH",
                std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
            )
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            use std::os::unix::process::CommandExt as _;
            command.as_std_mut().process_group(0);
            if let Some(cwd_handle) = cwd_handle {
                let cwd = cwd_handle.as_raw_fd();
                // SAFETY: the closure calls only async-signal-safe `fchdir` before `exec`.
                unsafe {
                    command.as_std_mut().pre_exec(move || {
                        if libc::fchdir(cwd) == 0 {
                            Ok(())
                        } else {
                            Err(io::Error::last_os_error())
                        }
                    });
                }
            }
        }

        let mut child = command.spawn().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "start MCP server {:?} ({}): {error}",
                    admitted.name,
                    admitted.program()
                ),
            )
        })?;
        #[cfg(unix)]
        let process_group = child
            .id()
            .ok_or_else(|| io::Error::other("the MCP server has no process id"))?
            as libc::pid_t;
        let Some(stdin) = child.stdin.take() else {
            #[cfg(unix)]
            signal_process_group(process_group, libc::SIGKILL);
            let _ = child.start_kill();
            child.wait().await?;
            return Err(io::Error::other("the MCP server's stdin was not piped"));
        };
        let Some(stdout) = child.stdout.take() else {
            #[cfg(unix)]
            signal_process_group(process_group, libc::SIGKILL);
            let _ = child.start_kill();
            child.wait().await?;
            return Err(io::Error::other("the MCP server's stdout was not piped"));
        };
        Ok((
            Self {
                server: admitted.name.clone(),
                stdin: Some(stdin),
                child,
                #[cfg(unix)]
                process_group,
                #[cfg(test)]
                output: None,
                pending: Vec::new(),
                #[cfg(test)]
                stop_and_wait_completion: None,
                // An uncontained server retains nothing beyond its own child.
                #[cfg(unix)]
                _leaf_retention: None,
            },
            stdout,
        ))
    }

    /// Adopt an already-contained streaming leaf as a running MCP server. The leaf's child and its
    /// process group become this handle's, so every forward, stop, and drop path is the uncontained
    /// one; the leaf's retention (its boundary and — on Linux — its netns relays) rides along so the
    /// containment outlives the server exactly as long as the child does.
    #[cfg(unix)]
    pub(crate) fn from_leaf(
        admitted: &McpServer,
        leaf: crate::run::contain::supervise::StreamingLeaf,
    ) -> io::Result<(Self, tokio::process::ChildStdout)> {
        let parts = leaf
            .into_parts()
            .ok_or_else(|| io::Error::other("the contained MCP server exposed no live streams"))?;
        Ok((
            Self {
                server: admitted.name.clone(),
                stdin: Some(parts.stdin),
                child: parts.child,
                process_group: parts.leader as libc::pid_t,
                #[cfg(test)]
                output: None,
                pending: Vec::new(),
                #[cfg(test)]
                stop_and_wait_completion: None,
                _leaf_retention: Some(parts.retention),
            },
            parts.stdout,
        ))
    }

    /// The server this handle runs, for the decision each frame raises.
    pub(crate) fn server(&self) -> &str {
        &self.server
    }

    /// Split newly arrived text into complete frames, holding any unterminated tail.
    pub(crate) fn complete_frames(&mut self, chunk: &[u8]) -> io::Result<Vec<String>> {
        if self.pending.len() + chunk.len() > MAXIMUM_PENDING_FRAME_BYTES {
            self.pending.clear();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "an unterminated MCP frame exceeded {MAXIMUM_PENDING_FRAME_BYTES} bytes and \
                     was discarded; a frame must be newline-terminated"
                ),
            ));
        }
        self.pending.extend_from_slice(chunk);

        // **One drain for the whole complete prefix, not one per frame.** Draining per frame shifts
        // every remaining byte down each time, which is quadratic in the frame count: a 1 MiB payload
        let Some(last) = self.pending.iter().rposition(|byte| *byte == b'\n') else {
            return Ok(Vec::new());
        };
        let complete: Vec<u8> = self.pending.drain(..=last).collect();
        // Converted once per complete frame, so a character split across two chunks is whole by the
        // time it is decoded.
        Ok(complete
            .split_inclusive(|byte| *byte == b'\n')
            .map(|frame| String::from_utf8_lossy(frame).into_owned())
            .collect())
    }

    /// The unterminated tail, taken as a final frame.
    pub(crate) fn take_pending(&mut self) -> Option<String> {
        let tail = std::mem::take(&mut self.pending);
        let tail = String::from_utf8_lossy(&tail).into_owned();
        (!tail.trim().is_empty()).then_some(tail)
    }

    /// Forward one decided frame to the server.
    pub(crate) async fn forward(&mut self, frame: &str) -> io::Result<()> {
        self.forward_before(frame, Instant::now() + MCP_BROKER_IO_TIMEOUT)
            .await
    }

    async fn forward_before(&mut self, frame: &str, deadline: Instant) -> io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "MCP stdin is closed"))?;
        let deadline = deadline.min(Instant::now() + MCP_BROKER_IO_TIMEOUT);
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            stdin.write_all(frame.trim_end().as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MCP server input timed out"))?
    }

    /// Close the server's stdin, which is how a client says it is done.
    pub(crate) async fn close_stdin(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let Some(mut stdin) = self.stdin.take() else {
            return Ok(());
        };
        tokio::time::timeout(MCP_BROKER_IO_TIMEOUT, stdin.shutdown())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MCP stdin close timed out"))?
    }

    /// Adopt the task streaming this child's stdout.
    #[cfg(test)]
    pub(crate) fn adopt_output(&mut self, output: tokio::task::JoinHandle<()>) {
        self.output = Some(output);
    }

    /// Stop the server and reap its child.
    pub(crate) async fn stop_and_wait(&mut self) -> io::Result<()> {
        #[cfg(test)]
        let output = {
            let output = self.output.take();
            if let Some(output) = &output {
                output.abort();
            }
            output
        };
        self.stdin.take();
        self.signal_process_group(libc::SIGTERM);
        let wait = tokio::time::timeout(Duration::from_secs(1), self.child.wait()).await;
        let wait = match wait {
            Ok(wait) => wait,
            Err(_) => {
                self.signal_process_group(libc::SIGKILL);
                self.child.wait().await
            }
        };
        self.signal_process_group(libc::SIGKILL);
        #[cfg(test)]
        {
            if let Some(output) = output {
                let _ = output.await;
            }
        }
        wait?;
        #[cfg(test)]
        if let Some(completion) = self.stop_and_wait_completion.take() {
            let _ = completion.send(());
        }
        Ok(())
    }

    #[cfg(unix)]
    fn signal_process_group(&self, signal: libc::c_int) {
        // SAFETY: the child starts as leader of a process group whose id is its pid.
        signal_process_group(self.process_group, signal);
    }

    #[cfg(not(unix))]
    fn signal_process_group(&mut self, _signal: libc::c_int) {
        let _ = self.child.start_kill();
    }

    #[cfg(test)]
    pub(super) fn observe_stop_and_wait_completion(
        &mut self,
    ) -> tokio::sync::oneshot::Receiver<()> {
        let (completion, observed) = tokio::sync::oneshot::channel();
        self.stop_and_wait_completion = Some(completion);
        observed
    }

    #[cfg(test)]
    async fn wait_for_output(&mut self) -> io::Result<()> {
        let result = match self.output.as_mut() {
            Some(output) => output.await.map_err(io::Error::other),
            None => Ok(()),
        };
        self.output.take();
        result
    }

    /// Close stdin, then reap the server or stop it after `timeout`.
    #[cfg(test)]
    pub(crate) async fn finish_after_disconnect(&mut self, timeout: Duration) -> io::Result<()> {
        let close = self.close_stdin().await;
        let graceful = async {
            self.child.wait().await?;
            self.wait_for_output().await
        };
        let waited = tokio::time::timeout(timeout, graceful).await;
        let reaped = match waited {
            Ok(result) => result,
            Err(_) => self.stop_and_wait().await,
        };
        close?;
        reaped
    }
}

#[cfg(unix)]
fn signal_process_group(process_group: libc::pid_t, signal: libc::c_int) {
    // SAFETY: the negative pid addresses the process group created for this child.
    unsafe {
        libc::kill(-process_group, signal);
    }
}

impl Drop for RunningMcpServer {
    fn drop(&mut self) {
        self.stdin.take();
        self.signal_process_group(libc::SIGKILL);
        let _ = self.child.start_kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_mcp_protocol_revisions_are_accepted_and_other_revisions_are_refused() {
        for protocol_version in SUPPORTED_MCP_PROTOCOL_VERSIONS {
            validate_initialize_result(&json!({
                "result": {
                    "protocolVersion": protocol_version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "test", "version": "1"}
                }
            }))
            .expect("the approved MCP protocol revision is supported");
        }

        let error = validate_initialize_result(&json!({
            "result": {
                "protocolVersion": "2099-01-01",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "test", "version": "1"}
            }
        }))
        .expect_err("an unapproved MCP protocol revision must be refused");
        assert!(error.to_string().contains("unsupported protocol version"));
    }

    #[test]
    fn paginated_discovery_accepts_responses_within_the_aggregate_maximum() {
        let pages = [
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "tools": [{"name": "first", "inputSchema": {"type": "object"}}],
                    "nextCursor": "page-2"
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": {
                    "tools": [{"name": "second", "inputSchema": {"type": "object"}}]
                }
            }),
        ];
        let mut total = 0;
        for page in pages {
            let page_bytes = serde_json::to_vec(&page)
                .expect("the page serializes")
                .len()
                + 1;
            admit_discovery_response_bytes(
                &mut total,
                page_bytes,
                MAXIMUM_DISCOVERY_RESPONSE_BYTES,
            )
            .expect("the paginated response is within the maximum");
        }

        assert!(total < MAXIMUM_DISCOVERY_RESPONSE_BYTES);
    }

    #[tokio::test]
    async fn discovery_timeout_stops_and_reaps_the_server_before_returning() {
        let admitted = McpServer {
            name: "silent-server".to_string(),
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "while IFS= read -r request; do :; done".to_string(),
            ],
        };
        let (mut running, stdout) =
            RunningMcpServer::start(&admitted, Path::new("/tmp"), Path::new("/tmp"))
                .await
                .expect("the silent server starts");
        let reaped = running.observe_stop_and_wait_completion();

        let error = list_tools_from_running_server_until_cancelled(
            running,
            stdout,
            std::future::pending(),
            MAXIMUM_DISCOVERY_RESPONSE_BYTES,
            Duration::from_millis(10),
        )
        .await
        .expect_err("silent discovery must time out");

        match error {
            McpToolDiscoveryError::Discovery(error) => {
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            }
            McpToolDiscoveryError::Cancelled => panic!("discovery was not cancelled"),
            McpToolDiscoveryError::Cleanup(error) => {
                panic!("discovery cleanup failed instead: {error}")
            }
        }
        reaped
            .await
            .expect("stop_and_wait must signal after it reaps the server");
    }

    #[tokio::test]
    async fn paginated_discovery_refuses_responses_over_the_aggregate_maximum() {
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "1"}
            }
        });
        let pages = [
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "tools": [{"name": "first", "inputSchema": {"type": "object"}}],
                    "nextCursor": "page-2"
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": {
                    "tools": [{"name": "second", "inputSchema": {"type": "object"}}]
                }
            }),
        ];
        let script = r#"
IFS= read -r request
printf '%s\n' "$1"
IFS= read -r notification
shift
for response in "$@"; do
    IFS= read -r request
    printf '%s\n' "$response"
done
"#;
        let mut command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            script.to_string(),
            "fake-mcp".to_string(),
            serde_json::to_string(&initialize).expect("the initialize response serializes"),
        ];
        command.extend(
            pages
                .iter()
                .map(|page| serde_json::to_string(page).expect("the page serializes")),
        );
        let admitted = McpServer {
            name: "fake".to_string(),
            command,
        };
        let page_bytes = pages
            .iter()
            .map(|page| serde_json::to_vec(page).expect("the page serializes").len() + 1)
            .sum::<usize>();
        let error = list_tools_until_cancelled(
            &admitted,
            Path::new("/tmp"),
            Path::new("/tmp"),
            std::future::pending(),
            page_bytes - 1,
        )
        .await
        .expect_err("the aggregate response bytes must be bounded");
        let refusal = match error {
            McpToolDiscoveryError::Discovery(error) => error,
            McpToolDiscoveryError::Cancelled => panic!("discovery was not cancelled"),
            McpToolDiscoveryError::Cleanup(error) => {
                panic!("discovery cleanup failed instead: {error}")
            }
        };

        assert_eq!(refusal.kind(), io::ErrorKind::InvalidData);
        assert!(
            refusal.to_string().contains("aggregate maximum"),
            "the refusal must name the aggregate maximum: {refusal}"
        );
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

    #[tokio::test]
    async fn an_internal_write_deadline_reaps_a_non_reading_child() {
        let (mut running, _stdout) = non_reading_server().await;
        let reaped = running.observe_stop_and_wait_completion();
        let payload = "x".repeat(MAXIMUM_PENDING_FRAME_BYTES);
        let started = Instant::now();
        let error = running
            .forward_before(&payload, Instant::now() + Duration::from_millis(20))
            .await
            .expect_err("the internal write must meet its absolute deadline");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < MCP_BROKER_IO_TIMEOUT);
        running.stop_and_wait().await.expect("reap child");
        reaped
            .await
            .expect("stop_and_wait reports only after child reap");
    }

    /// One frame on ONE line.
    const ONE_LINE_SEARCH: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"SearchIssues","arguments":{"query":"x"}}}"#;
    const ONE_LINE_COMMENT: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"AddComment","arguments":{}}}"#;

    /// A running server over `cat`, which echoes and so needs no MCP implementation.
    async fn running_over_cat() -> RunningMcpServer {
        let admitted = McpServer {
            name: "echo-server".to_string(),
            command: vec!["cat".to_string()],
        };
        let (running, _stdout) =
            RunningMcpServer::start(&admitted, Path::new("/tmp"), Path::new("/tmp"))
                .await
                .expect("cat starts");
        running
    }

    #[tokio::test]
    async fn server_output_frames_enforce_the_one_mebibyte_boundary() {
        for (payload_bytes, accepted) in [
            (crate::run::broker::protocol::MAX_FRAME_BYTES - 1, true),
            (crate::run::broker::protocol::MAX_FRAME_BYTES, false),
        ] {
            let admitted = McpServer {
                name: "frame-boundary".to_string(),
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "head -c \"$1\" /dev/zero | tr '\\000' x; printf '\\n'; sleep 30".to_string(),
                    "frame-boundary".to_string(),
                    payload_bytes.to_string(),
                ],
            };
            let (mut running, stdout) =
                RunningMcpServer::start(&admitted, Path::new("/tmp"), Path::new("/tmp"))
                    .await
                    .expect("the frame-boundary server starts");
            let mut stdout = tokio::io::BufReader::new(stdout);
            let result = read_server_frame(&mut stdout).await;
            if accepted {
                assert_eq!(
                    result.expect("the exact boundary is accepted").len(),
                    crate::run::broker::protocol::MAX_FRAME_BYTES
                );
            } else {
                let error = result.expect_err("one byte above the boundary is refused");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(error.to_string().contains("exceeded"));
            }
            running.stop_and_wait().await.expect("reap frame server");
        }
    }

    #[tokio::test]
    async fn graceful_disconnect_waits_for_buffered_output() {
        use tokio::io::AsyncReadExt as _;

        let admitted = McpServer {
            name: "buffered-server".to_string(),
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf buffered-output".to_string(),
            ],
        };
        let (mut running, mut stdout) =
            RunningMcpServer::start(&admitted, Path::new("/tmp"), Path::new("/tmp"))
                .await
                .expect("the buffered server starts");
        let (observed, output) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        running.adopt_output(tokio::spawn(async move {
            let mut bytes = Vec::new();
            stdout
                .read_to_end(&mut bytes)
                .await
                .expect("read the buffered output");
            let _ = observed.send(bytes);
            let _ = released.await;
        }));
        running
            .close_stdin()
            .await
            .expect("graceful cleanup closes stdin");
        running
            .child
            .wait()
            .await
            .expect("the child exits before output cleanup");

        let finish = running.finish_after_disconnect(Duration::from_secs(1));
        tokio::pin!(finish);
        let bytes = tokio::select! {
            biased;
            result = &mut finish => {
                panic!("disconnect cleanup finished before output was released: {result:?}")
            }
            result = output => result.expect("output task was not aborted before observation"),
        };

        assert_eq!(bytes, b"buffered-output");
        release.send(()).expect("output task is still pending");
        finish
            .await
            .expect("graceful disconnect drains output after release");
    }

    /// **A frame split across two `Input` frames is reassembled, not refused twice.**
    ///
    /// The alias reads the agent's stdin in 8192-byte chunks, so a `tools/call` with large
    #[tokio::test]
    async fn a_frame_split_across_two_input_frames_is_reassembled() {
        let mut running = running_over_cat().await;
        let (first, second) = ONE_LINE_SEARCH.split_at(ONE_LINE_SEARCH.len() / 2);

        assert!(
            running
                .complete_frames(first.as_bytes())
                .expect("buffered")
                .is_empty(),
            "an unterminated half must yield no frame, and must not be parsed as one"
        );
        let complete = running
            .complete_frames(format!("{second}\n").as_bytes())
            .expect("the second half completes it");
        assert_eq!(complete.len(), 1, "the two halves are one frame");
        assert_eq!(
            complete[0].trim(),
            ONE_LINE_SEARCH,
            "the reassembled frame must be the original text"
        );
    }

    /// Several frames in one `Input` are each returned, and a trailing partial is held.
    #[tokio::test]
    async fn many_frames_in_one_input_are_split_and_a_partial_tail_is_held() {
        let mut running = running_over_cat().await;
        let arriving =
            format!("{ONE_LINE_SEARCH}\n{ONE_LINE_COMMENT}\n{{\"jsonrpc\":\"2.0\",\"id\":3");

        let complete = running
            .complete_frames(arriving.as_bytes())
            .expect("buffered");
        assert_eq!(complete.len(), 2, "both terminated frames are complete");
        assert_eq!(complete[0].trim(), ONE_LINE_SEARCH);
        assert_eq!(complete[1].trim(), ONE_LINE_COMMENT);

        // The tail is legal as a final frame, so `StdinEof` takes it rather than dropping it.
        assert_eq!(
            running.take_pending().as_deref(),
            Some("{\"jsonrpc\":\"2.0\",\"id\":3"),
            "an unterminated tail must survive to be decided at EOF"
        );
        assert!(
            running.take_pending().is_none(),
            "taking it twice must not repeat it"
        );
    }

    /// **An unterminated frame cannot grow without limit.**
    ///
    /// The tail is held rather than forwarded, so a client that never sends a newline would
    #[tokio::test]
    async fn an_unterminated_frame_is_bounded() {
        let mut running = running_over_cat().await;
        let refusal = running
            .complete_frames(&vec![b'x'; MAXIMUM_PENDING_FRAME_BYTES + 1])
            .expect_err("an unbounded frame must be refused")
            .to_string();
        assert!(
            refusal.contains("newline-terminated"),
            "the refusal must say what a frame needs: {refusal}"
        );
        assert!(
            running.take_pending().is_none(),
            "the discarded text must not stay buffered"
        );
    }

    #[tokio::test]
    async fn a_character_split_across_two_chunks_survives_reassembly() {
        let mut running = running_over_cat().await;
        let frame = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"Say","arguments":{{"text":"{}"}}}}}}"#,
            "café–naïve"
        );
        let bytes = frame.as_bytes();

        // Split inside the `é`, which is two bytes in UTF-8.
        let boundary = frame.find('é').expect("the fixture holds it") + 1;
        assert!(
            std::str::from_utf8(&bytes[..boundary]).is_err(),
            "the split must land mid-character, or this test measures nothing"
        );

        assert!(
            running
                .complete_frames(&bytes[..boundary])
                .expect("buffered")
                .is_empty()
        );
        let mut second = bytes[boundary..].to_vec();
        second.push(b'\n');
        let complete = running.complete_frames(&second).expect("completed");

        assert_eq!(complete.len(), 1, "the two halves are one frame");
        assert_eq!(
            complete[0].trim(),
            frame,
            "the reassembled frame must be byte-for-byte the original, with no replacement character"
        );
        assert!(
            !complete[0].contains('\u{FFFD}'),
            "no replacement character may appear: {}",
            complete[0]
        );
    }
}
