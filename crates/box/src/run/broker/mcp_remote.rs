//! Discovery-only MCP client over Streamable HTTP, for `policy generate-schema`.
//!
//! | Step | Frame |
//! |---|---|
//! | open the session | `initialize`, capturing the `Mcp-Session-Id` response header |
//! | confirm the handshake | `notifications/initialized` |
//! | enumerate | `tools/list`, following `nextCursor` |
//!
//! **Not the agent, and no gateway in the path.** This runs before any box, so it reaches the
//! server directly and attaches the resolved credential itself. Its `tools/list` output has the
//! same shape the stdio door returns, so `generate_mcp_schema` consumes either unchanged.

use std::io;
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderName, HeaderValue};
use serde_json::{Value, json};

/// The MCP protocol version offered at `initialize` — the latest this client understands. The
/// server may answer with its own; the negotiated version is then carried on `MCP-Protocol-Version`.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// The session header a Streamable-HTTP server returns at `initialize` and expects on every later
/// request. Matched case-insensitively by `reqwest`'s header map.
const SESSION_HEADER: &str = "mcp-session-id";

/// How long the whole discovery exchange may take.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// A pagination bound, so a server that always returns a cursor cannot loop forever.
const MAX_PAGES: usize = 100;

/// List a remote MCP server's tools over Streamable HTTP.
///
/// `auth` is an optional `(header, value)` attached to every request — resolved by the caller from
/// the server's `[egress.<name>].secret`. Returns the aggregated response shaped as
/// `{"result":{"tools":[...]}}`.
pub(crate) async fn list_tools(url: &str, auth: Option<(String, String)>) -> io::Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(DISCOVERY_TIMEOUT)
        .build()
        .map_err(other)?;
    let auth = auth.as_ref();

    let init = post(
        &client,
        url,
        PROTOCOL_VERSION,
        auth,
        None,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "strands-box-generate-mcp-schemas",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }),
    )
    .await?;
    let session = init
        .headers()
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    // Adopt the version the server answered with, matching how a full MCP client negotiates. Absent
    // one, keep what was offered.
    let negotiated = reply(init)
        .await?
        .get("result")
        .and_then(|result| result.get("protocolVersion"))
        .and_then(Value::as_str)
        .map_or_else(|| PROTOCOL_VERSION.to_string(), str::to_string);

    post(
        &client,
        url,
        &negotiated,
        auth,
        session.as_deref(),
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
    )
    .await?;

    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    for id in 0..MAX_PAGES {
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |cursor| json!({"cursor": cursor}));
        let response = post(
            &client,
            url,
            &negotiated,
            auth,
            session.as_deref(),
            &json!({"jsonrpc": "2.0", "id": id + 2, "method": "tools/list", "params": params}),
        )
        .await?;
        let message = reply(response).await?;
        let result = message
            .get("result")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("MCP tools/list result is not an object"))?;
        let page = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("MCP tools/list result has no tools array"))?;
        tools.extend(page.iter().cloned());
        match result.get("nextCursor").and_then(Value::as_str) {
            Some(next) => cursor = Some(next.to_string()),
            None => return Ok(json!({"result": {"tools": tools}})),
        }
    }
    Err(invalid(format!(
        "MCP tools/list did not terminate within {MAX_PAGES} pages"
    )))
}

/// POST one JSON-RPC frame, carrying the negotiated protocol version, the session, and optional
/// credential.
async fn post(
    client: &reqwest::Client,
    url: &str,
    version: &str,
    auth: Option<&(String, String)>,
    session: Option<&str>,
    body: &Value,
) -> io::Result<reqwest::Response> {
    let mut request = client
        .post(url)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", version)
        .json(body);
    if let Some(session) = session {
        request = request.header(SESSION_HEADER, session);
    }
    if let Some((name, value)) = auth {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(other)?;
        let value = HeaderValue::from_str(value).map_err(other)?;
        request = request.header(name, value);
    }
    request.send().await.map_err(other)
}

/// Read one JSON-RPC message from a response that is either `application/json` or an SSE stream.
async fn reply(response: reqwest::Response) -> io::Result<Value> {
    let status = response.status();
    let event_stream = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|content_type| content_type.contains("text/event-stream"));
    let body = response.text().await.map_err(other)?;
    if !status.is_success() {
        return Err(invalid(format!(
            "MCP server returned HTTP {status}: {}",
            body.trim()
        )));
    }
    if event_stream {
        // Streamable HTTP carries the JSON-RPC message in an SSE `data:` line. Return the first
        // one that is a response (a `result` or an `error`), skipping any keep-alive or progress.
        for line in body.lines() {
            let Some(data) = line.trim_start().strip_prefix("data:") else {
                continue;
            };
            if let Ok(message) = serde_json::from_str::<Value>(data.trim())
                && (message.get("result").is_some() || message.get("error").is_some())
            {
                return Ok(message);
            }
        }
        return Err(invalid("no JSON-RPC response found in the MCP SSE stream"));
    }
    if body.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&body).map_err(other)
}

fn other<E: std::fmt::Display>(error: E) -> io::Error {
    io::Error::other(error.to_string())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
