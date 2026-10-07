//! JSON-RPC ids, `tools/list` cursors, and the frames the broker writes to a client.

use std::io;

use serde_json::{Value, json};

use super::discovery::DiscoveryReleaseGuard;
use super::server::MCP_BROKER_IO_TIMEOUT;

pub(super) fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// The `params.cursor` a `tools/list` names, or `None` for the first page.
pub(super) fn list_cursor(request: &Value) -> io::Result<Option<String>> {
    let params = match request.get("params") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(params)) => params,
        Some(_) => return Err(invalid_data("tools/list params must be an object")),
    };
    match params.get("cursor") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(cursor)) => Ok(Some(cursor.clone())),
        Some(_) => Err(invalid_data("tools/list cursor must be a string or null")),
    }
}

pub(super) fn require_request_id(request: &Value) -> io::Result<(String, Value)> {
    optional_request_id(request)?.ok_or_else(|| invalid_data("the MCP request has no id"))
}

pub(super) fn optional_request_id(request: &Value) -> io::Result<Option<(String, Value)>> {
    request
        .get("id")
        .map(|id| Ok((id_key(id)?, id.clone())))
        .transpose()
}

pub(super) fn id_key(id: &Value) -> io::Result<String> {
    if !id.is_string() && !id.is_number() {
        return Err(invalid_data("an MCP request id must be a string or number"));
    }
    serde_json::to_string(id).map_err(|error| invalid_data(error.to_string()))
}

pub(super) async fn emit_request_error(
    frames: &tokio::sync::mpsc::Sender<super::super::host::OutboundFrame>,
    program: crate::run::broker::protocol::ProgramId,
    id: Option<&Value>,
    code: i32,
    message: &str,
    release: Option<DiscoveryReleaseGuard>,
) -> io::Result<()> {
    let response = json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": {"code": code, "message": message}
    });
    let mut rendered =
        serde_json::to_vec(&response).map_err(|error| invalid_data(error.to_string()))?;
    rendered.push(b'\n');
    emit_text(frames, program, &rendered, release).await
}

pub(super) async fn emit_text(
    frames: &tokio::sync::mpsc::Sender<super::super::host::OutboundFrame>,
    program: crate::run::broker::protocol::ProgramId,
    bytes: &[u8],
    mut release: Option<DiscoveryReleaseGuard>,
) -> io::Result<()> {
    let mut chunks = bytes
        .chunks(crate::run::broker::protocol::MAX_CHUNK_BYTES)
        .peekable();
    while let Some(chunk) = chunks.next() {
        let final_release = chunks.peek().is_none().then(|| release.take()).flatten();
        tokio::time::timeout(
            MCP_BROKER_IO_TIMEOUT,
            frames.send(super::super::host::OutboundFrame {
                frame: crate::run::broker::protocol::Frame {
                    version: crate::run::broker::protocol::PROTOCOL_VERSION,
                    program,
                    body: crate::run::broker::protocol::Body::Output {
                        stream: crate::run::broker::protocol::Stream::Stdout,
                        data: crate::run::broker::protocol::encode_payload(chunk),
                    },
                },
                release: final_release,
            }),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the MCP client output timed out",
            )
        })?
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the MCP client output stopped",
            )
        })?;
    }
    Ok(())
}
