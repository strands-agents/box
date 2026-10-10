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
    if event_stream && status.is_success() {
        let mut response = response;
        let mut parser = SseReply::default();
        while let Some(chunk) = response.chunk().await.map_err(other)? {
            for byte in chunk {
                if let Some(message) = parser.push(byte) {
                    return Ok(message);
                }
            }
        }
        return Err(invalid("no JSON-RPC response found in the MCP SSE stream"));
    }
    let body = response.text().await.map_err(other)?;
    if !status.is_success() {
        return Err(invalid(format!(
            "MCP server returned HTTP {status}: {}",
            body.trim()
        )));
    }
    if body.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&body).map_err(other)
}

#[derive(Default)]
struct SseReply {
    line: Vec<u8>,
    data: Vec<u8>,
    skip_lf: bool,
}

impl SseReply {
    fn push(&mut self, byte: u8) -> Option<Value> {
        if std::mem::take(&mut self.skip_lf) && byte == b'\n' {
            return None;
        }
        if byte != b'\r' && byte != b'\n' {
            self.line.push(byte);
            return None;
        }
        self.skip_lf = byte == b'\r';
        let line = std::mem::take(&mut self.line);
        if line.is_empty() {
            let data = std::mem::take(&mut self.data);
            let message: Value = serde_json::from_slice(&data).ok()?;
            return (message.get("result").is_some() || message.get("error").is_some())
                .then_some(message);
        }
        if let Some(data) = line.strip_prefix(b"data:") {
            if !self.data.is_empty() {
                self.data.push(b'\n');
            }
            self.data
                .extend_from_slice(data.strip_prefix(b" ").unwrap_or(data));
        }
        None
    }
}

fn other<E: std::fmt::Display>(error: E) -> io::Error {
    io::Error::other(error.to_string())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod remote_sse_events_tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[tokio::test]
    async fn multiline_sse_data_is_one_json_message() {
        for ending in ["\n", "\r\n", "\r"] {
            let event = format!(
                "event: message{ending}data: {{\"jsonrpc\":\"2.0\",{ending}data: \"id\":1, \"result\":{{\"tools\":[]}}}}{ending}{ending}"
            );
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{event}", event.len()).unwrap();
            });
            let response = reqwest::Client::new()
                .get(format!("http://{address}/"))
                .send()
                .await
                .unwrap();
            let message = reply(response)
                .await
                .expect("data fields belong to one event");
            server.join().unwrap();
            assert_eq!(message["id"], 1);
        }
    }

    #[tokio::test]
    async fn sse_reply_returns_before_the_http_stream_closes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release, released) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
            let event = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n";
            write!(stream, "{:x}\r\n", event.len()).unwrap();
            stream.write_all(event).unwrap();
            stream.write_all(b"\r\n").unwrap();
            stream.flush().unwrap();
            let _ = released.recv_timeout(Duration::from_secs(2));
        });
        let response = reqwest::Client::new()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_millis(500), reply(response)).await;
        let _ = release.send(());
        server.join().unwrap();
        let message = result
            .expect("an event response must not wait for HTTP EOF")
            .unwrap();
        assert_eq!(message["result"]["tools"], json!([]));
    }
}
