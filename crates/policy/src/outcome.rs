//! What actually happened after an admitted effect.

use std::net::SocketAddr;
use std::path::Path;

use crate::request::FsOperation;

/// How much of a message actually left, and whether that count can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The whole prepared message was accepted and flushed.
    Completed {
        /// Bytes delivered.
        bytes: usize,
    },
    /// A non-zero prefix was accepted before the write failed.
    Partial {
        /// Bytes accepted before the failure.
        accepted_bytes: usize,
    },
    /// The write failed before any bytes were accepted.
    Failed,
    /// Delivery became uncertain after this many bytes were accepted.
    Indeterminate {
        /// Bytes accepted before certainty was lost.
        accepted_bytes: usize,
    },
}

impl Delivery {
    /// Bytes that reached the operating system, whether or not delivery was certain.
    #[must_use]
    pub fn accepted_bytes(self) -> usize {
        match self {
            Delivery::Completed { bytes } => bytes,
            Delivery::Partial { accepted_bytes } | Delivery::Indeterminate { accepted_bytes } => {
                accepted_bytes
            }
            Delivery::Failed => 0,
        }
    }

    /// Whether the whole message is known to have been delivered.
    #[must_use]
    pub fn is_complete(self) -> bool {
        matches!(self, Delivery::Completed { .. })
    }
}

/// How a filesystem operation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsResult {
    /// The operation completed and its whole effect has happened.
    Completed,
    /// A descriptor was issued; the transfer it enables has not happened yet.
    DescriptorIssued,
    /// The operation was attempted and its effect did not happen.
    Failed,
    /// The operation was admitted and ended with no terminal outcome recorded.
    Indeterminate,
}

impl FsResult {
    /// The `FsResponseResult` eid a response event carries on `output.result`, or
    /// `None` for a failure, which selects the `error` event kind and reaches no
    /// field. The schema declares no `"failed"` eid, and this signature is what
    /// keeps one out of history.
    pub(crate) fn response_result(self) -> Option<&'static str> {
        match self {
            FsResult::Completed => Some("completed"),
            FsResult::DescriptorIssued => Some("descriptor_issued"),
            FsResult::Indeterminate => Some("indeterminate"),
            FsResult::Failed => None,
        }
    }
}

/// One completed effect, submitted to policy as history.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Outcome<'a> {
    /// An upstream socket attempt resolved.
    Connect {
        /// The logical destination host.
        host: &'a str,
        /// The logical destination port.
        port: u16,
        /// The pinned address the attempt used.
        address: SocketAddr,
        /// Whether the socket opened or may have opened. False only for a connect
        /// that definitely failed, because only a definite failure records an
        /// `error` event.
        connected: bool,
    },
    /// One HTTP exchange ended (`http:request::response`), at reply time or when no reply came.
    Http {
        /// The logical destination host.
        host: &'a str,
        /// The logical destination port.
        port: u16,
        /// The request method.
        method: &'a str,
        /// The request path, without its query.
        path: &'a str,
        /// How much of the request left.
        delivery: Delivery,
        /// The upstream's reply status, or `None` when no reply arrived.
        status: Option<u16>,
        /// Whether the gateway decrypted a TLS exchange. `false` for plain HTTP.
        intercepted: bool,
    },
    /// A resolved command line finished (`shell:exec::response`).
    ///
    /// The response names the same action whose request was authorized, so a rule can
    /// join a `shell:exec::request` to its own response and to no other.
    ShellRun {
        /// The command that ran.
        command: &'a str,
        /// The program that ran, as resolved.
        program: &'a str,
        /// The arguments it ran with, without the program.
        args: &'a [String],
        /// The working directory it ran in.
        cwd: &'a str,
        /// Its reported exit status.
        status: i32,
    },
    /// A host binary finished (`shell:spawn::response`).
    ShellSpawn {
        /// The command that ran.
        command: &'a str,
        /// The program that ran, as resolved.
        program: &'a str,
        /// The absolute path of the binary that executed.
        program_path: &'a str,
        /// Exact credential path spellings this leaf received.
        credential_reads: &'a [String],
        /// The arguments it ran with, without the program.
        args: &'a [String],
        /// The working directory it ran in.
        cwd: &'a str,
        /// Its reported exit status.
        status: i32,
    },
    /// A filesystem effect finished.
    Fs {
        /// The canonicalized target path.
        path: &'a Path,
        /// The exact operation performed. It selects the same granular action whose
        /// `request` was authorized, so a rule can correlate the two.
        operation: FsOperation,
        /// How the operation ended.
        result: FsResult,
    },
    /// One terminal or indeterminate MCP call (`mcp:call::response`).
    Mcp {
        /// The MCP server name, from the operator's file.
        server: &'a str,
        /// The JSON-RPC method — an act method only (`tools/call`, `resources/read`, `prompts/get`).
        /// Enumeration (`*/list`) and description-only methods raise no response leg, so they never
        /// reach here.
        method: &'a str,
        /// The tool a `tools/call` named, if any.
        tool: Option<&'a str>,
        /// The prompt a `prompts/get` named, if any.
        prompt: Option<&'a str>,
        /// The resource uri a `resources/read` named, if any.
        uri: Option<&'a str>,
    },
}

/// The per-tool `::response` an allowed `tools/call` owes, from `refine_tool_call` to `record_tool_response`.
#[must_use = "a dropped pending tool response is a `::response` that history never sees"]
pub struct PendingToolResponse {
    pub(crate) request_id: crate::RequestId,
    pub(crate) identity: crate::schema::ActionIdentity,
    pub(crate) input: dogwood_language::Value,
}

impl std::fmt::Debug for PendingToolResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingToolResponse")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// How one MCP tool call ended, recorded on its own `::response` as `output.reply`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpReply {
    /// The server answered with a result that does not report an error.
    Result,
    /// The server answered with a result that sets `isError`.
    ToolError,
    /// The server answered with a JSON-RPC error.
    ProtocolError,
    /// The client cancelled the call.
    Cancelled,
    /// The call's end is uncertain: its connection ended, the reply was not read, or the reply only
    /// accepted an MCP task.
    Indeterminate,
}

impl McpReply {
    /// The value a JSON-RPC reply to a `tools/call` reports.
    ///
    /// Only a `result` that is an object, with an `isError` that is absent or a boolean, is a
    /// `Result` or a `ToolError`. A result that only accepts an MCP task, and any other shape, is
    /// `Indeterminate`, so it cannot satisfy a precondition that requires `result`.
    #[must_use]
    pub fn of_reply(reply: &serde_json::Value) -> Self {
        if reply.get("error").is_some() {
            return Self::ProtocolError;
        }
        let Some(serde_json::Value::Object(result)) = reply.get("result") else {
            return Self::Indeterminate;
        };
        // The task's own result arrives later, through `tasks/result`, which Box does not record.
        if result.contains_key("task") {
            return Self::Indeterminate;
        }
        match result.get("isError") {
            None | Some(serde_json::Value::Bool(false)) => Self::Result,
            Some(serde_json::Value::Bool(true)) => Self::ToolError,
            Some(_) => Self::Indeterminate,
        }
    }

    /// Every value, as a rule spells it on `output.reply`.
    pub(crate) const VALUES: [&'static str; 5] = [
        "result",
        "tool_error",
        "protocol_error",
        "cancelled",
        "indeterminate",
    ];

    /// The value as `output.reply` records it.
    pub(crate) fn eid(self) -> &'static str {
        match self {
            Self::Result => "result",
            Self::ToolError => "tool_error",
            Self::ProtocolError => "protocol_error",
            Self::Cancelled => "cancelled",
            Self::Indeterminate => "indeterminate",
        }
    }
}
