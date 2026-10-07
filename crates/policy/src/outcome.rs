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
    /// One completed MCP call (`mcp:call::response`).
    ///
    /// A call that COMPLETED is a `response`, whatever the server then said — a JSON-RPC error reply
    /// is still `::response`, exactly as an HTTP 500 is a `Http` `::response` and a non-zero exit is a
    /// `ShellRun` `::response`. `::error` across this codebase means the box's effect did not occur,
    /// not that the counterparty was unhappy; a call that never completes simply records nothing.
    ///
    /// The response names the same `mcp:call` action whose request was authorized, so a temporal rule
    /// can `count`/`formerly` over `mcp:call::response`. The per-item identity — `tool` for a
    /// `tools/call`, `prompt` for a `prompts/get`, `uri` for a `resources/read` — rides the same
    /// `McpCallInput` fields the request carried, so a rule keyed on any of them joins the two legs
    /// on identity (mirroring the request leg, which emits all three together).
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
