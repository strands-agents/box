//! `box-mcp-call-probe` — a minimal MCP client over the box's broker transport.
//!
//! The deterministic containment harness has no MCP client of its own (the real client is the agent,
//! or `strands-box-sock-alias` in `Interpreter::Mcp` mode). This probe is that client, reduced to one
//! scripted exchange: connect to a broker socket, open one declared MCP server, run
//! `initialize → notifications/initialized → tools/list → tools/call`, and print the tool result's
//! text to stdout. It exists so a black-box test can drive one tool call as a single command and
//! assert on the result — for example, that a `contain_egress = false` server reached a host endpoint.
//!
//! The transport protocol is included by path (the crate is `[[bin]]`-only, with no `lib.rs`), exactly
//! as `strands-box-sock-alias` includes it.
//!
//! Usage: `box-mcp-call-probe <broker-socket> <server> <tool> [arguments-json]`
//!   - `<broker-socket>`  path to the box's broker socket (`.../run/box.sock`).
//!   - `<server>`         the declared MCP server name (the `[mcp.<name>]` key).
//!   - `<tool>`           the tool to call.
//!   - `[arguments-json]` the `tools/call` arguments object; defaults to `{}`.
//!
//! Exit 0 and print the result text on a `result`; exit 1 and print the error on a JSON-RPC error, a
//! policy `Denied`, or a transport failure.

#[path = "../../src/run/broker/protocol.rs"]
mod shell_protocol;

use std::process::ExitCode;
use std::time::Duration;

use shell_protocol::{
    Body, Frame, Interpreter, PROTOCOL_VERSION, decode_payload, encode_payload, read_frame,
    write_frame,
};
use tokio::net::UnixStream;

/// The one program this client opens on its connection.
const PROGRAM: u32 = 1;
/// A whole exchange is bounded so a hung server fails the test rather than hanging it.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let (socket, server, tool) = match (arguments.next(), arguments.next(), arguments.next()) {
        (Some(socket), Some(server), Some(tool)) => (socket, server, tool),
        _ => {
            eprintln!("usage: box-mcp-call-probe <broker-socket> <server> <tool> [arguments-json]");
            return ExitCode::from(2);
        }
    };
    let call_arguments = arguments.next().unwrap_or_else(|| "{}".to_string());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a current-thread runtime");

    match runtime.block_on(run(&socket, &server, &tool, &call_arguments)) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("box-mcp-call-probe: {reason}");
            ExitCode::FAILURE
        }
    }
}

/// Drive one tool call and return the result's text, or a reason to fail.
async fn run(
    socket: &str,
    server: &str,
    tool: &str,
    call_arguments: &str,
) -> Result<String, String> {
    let arguments: serde_json::Value = serde_json::from_str(call_arguments)
        .map_err(|error| format!("arguments are not valid JSON: {error}"))?;

    let mut stream = tokio::time::timeout(EXCHANGE_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| "connect to the broker socket timed out".to_string())?
        .map_err(|error| format!("connect to the broker socket {socket}: {error}"))?;

    send(
        &mut stream,
        Body::Open {
            mode: Interpreter::Mcp {
                server: server.to_string(),
            },
        },
    )
    .await?;

    let mut reader = Reader::default();

    // initialize → its response, then the initialized notification.
    send_line(
        &mut stream,
        &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
    )
    .await?;
    reader.await_id(&mut stream, 1).await?;
    send_line(
        &mut stream,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
    )
    .await?;

    // tools/list first: the broker stages a server's policy on discovery, so a call before a list is
    // refused. The response is not asserted here — the tool call is what proves egress.
    send_line(
        &mut stream,
        &serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    )
    .await?;
    reader.await_id(&mut stream, 2).await?;

    // tools/call → the result.
    send_line(
        &mut stream,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}
        }),
    )
    .await?;
    let response = reader.await_id(&mut stream, 3).await?;

    if let Some(error) = response.get("error") {
        return Err(format!("tools/call returned an error: {error}"));
    }
    // The MCP result text is `result.content[<n>].text`, joined so a multi-part result is not lost.
    let text = response
        .get("result")
        .and_then(|result| result.get("content"))
        .and_then(|content| content.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|part| part.get("text").and_then(|text| text.as_str()))
                .collect::<Vec<_>>()
                .join("")
        })
        .ok_or_else(|| format!("the tool result carried no text content: {response}"))?;
    Ok(text)
}

/// Write one transport frame for [`PROGRAM`].
async fn send(stream: &mut UnixStream, body: Body) -> Result<(), String> {
    tokio::time::timeout(
        EXCHANGE_TIMEOUT,
        write_frame(
            stream,
            &Frame {
                version: PROTOCOL_VERSION,
                program: PROGRAM,
                body,
            },
        ),
    )
    .await
    .map_err(|_| "write a transport frame timed out".to_string())?
    .map_err(|error| format!("write a transport frame: {error}"))
}

/// Write one newline-terminated JSON-RPC message as an `Input` frame.
async fn send_line(stream: &mut UnixStream, message: &serde_json::Value) -> Result<(), String> {
    let mut line =
        serde_json::to_vec(message).map_err(|error| format!("encode a frame: {error}"))?;
    line.push(b'\n');
    send(
        stream,
        Body::Input {
            data: encode_payload(&line),
        },
    )
    .await
}

/// Accumulates decoded `Output` bytes and yields the JSON-RPC message carrying a given id.
#[derive(Default)]
struct Reader {
    buffer: String,
}

impl Reader {
    /// Read frames until a JSON-RPC message with `id` arrives, returning it.
    async fn await_id(
        &mut self,
        stream: &mut UnixStream,
        id: i64,
    ) -> Result<serde_json::Value, String> {
        loop {
            // A complete line already buffered from an earlier frame?
            if let Some(message) = self.take_id(id) {
                return Ok(message);
            }
            let frame = tokio::time::timeout(EXCHANGE_TIMEOUT, read_frame::<Frame, _>(stream))
                .await
                .map_err(|_| format!("waiting for the response to id {id} timed out"))?
                .map_err(|error| format!("read a transport frame: {error}"))?
                .ok_or_else(|| {
                    format!("the broker closed the connection before answering id {id}")
                })?;
            match frame.body {
                Body::Output { data, .. } => {
                    let bytes = decode_payload(&data)
                        .map_err(|error| format!("decode an output frame: {error}"))?;
                    self.buffer.push_str(&String::from_utf8_lossy(&bytes));
                }
                Body::Denied { reason, .. } => {
                    return Err(format!("policy denied the exchange: {reason}"));
                }
                Body::Exit { status } => {
                    return Err(format!(
                        "the server exited (status {status}) before answering id {id}"
                    ));
                }
                _ => {}
            }
        }
    }

    /// Pull the first complete buffered line whose `id` matches, if any.
    fn take_id(&mut self, id: i64) -> Option<serde_json::Value> {
        while let Some(newline) = self.buffer.find('\n') {
            let line = self.buffer[..newline].trim().to_string();
            self.buffer.drain(..=newline);
            if line.is_empty() {
                continue;
            }
            if let Ok(message) = serde_json::from_str::<serde_json::Value>(&line)
                && message.get("id").and_then(|value| value.as_i64()) == Some(id)
            {
                return Some(message);
            }
            // A notification or a different id: not what this call awaits, so drop it.
        }
        None
    }
}
