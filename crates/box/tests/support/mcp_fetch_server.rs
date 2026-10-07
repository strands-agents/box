//! `box-mcp-fetch-server` — a single-binary stdio MCP server whose one tool makes an outbound TCP
//! fetch from a *contained* leaf. On a `tools/call` it fetches `FIXTURE_FETCH_TARGET` and returns
//! the body. It has two client models, selected by `FIXTURE_FETCH_PROXY` (see `fetch_text`):
//!
//! - **Proxy-unaware (default):** a raw direct connect. Proves native egress
//!   (`[mcp.<name>.network] contain_egress = false`) — a gateway-routed leaf has no route to the
//!   un-proxied target so the fetch fails, while a native-egress leaf shares the host network and it
//!   succeeds (the CN-NE case).
//! - **Proxy-aware (`FIXTURE_FETCH_PROXY` set):** honors `$HTTPS_PROXY` with an absolute-URI request,
//!   so a contained *gateway* leaf's egress is mediated by the box gateway and policy-gated
//!   (`net:connect` / `http:request`) — a permitted target answers, a denied one gets the gateway's
//!   `403` refusal.
//!
//! It is deliberately one self-contained executable that needs no other program, so a contained leaf on
//! Linux runs it with only the one exec grant every profile carries — no broad exec (a
//! currently-missing Linux-leaf feature), and no interpreter/toolchain to grant.
//!
//! Protocol: newline-delimited JSON-RPC on stdin/stdout — `initialize`, `notifications/initialized`,
//! `tools/list`, `tools/call`. Seven tools: `reach` fetches the target from the environment, `add`
//! returns `sum:<a+b>` for its typed integer arguments `a` and `b`, `echo` returns `echo:<text>`
//! for its string argument `text`, `read` returns `read:<content>` or `read-failed:errno=<n>` for
//! the file at its `path` argument, `env` returns `env:<value>` or `env-unset` for the variable
//! its `name` argument names, `unix-connect` returns `connect-ok` or `connect-failed:errno=<n>`
//! for a pathname socket at its `path` argument, and `exec` runs the program at its `path` argument
//! with its `args` and returns `exec-ok:<stdout>`, `exec-failed:status=<n>:<stdout>`, or
//! `exec-failed:errno=<n>`. `FIXTURE_FETCH_METHOD` sets the proxy-aware request method.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{Value, json};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    // A startup marker on stderr (inherited by the box), so a black-box run can tell a launch
    // failure (this line absent) from a communication failure (present, but no response).
    eprintln!("box-mcp-fetch-server: started pid={}", std::process::id());
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(frame) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let method = frame.get("method").and_then(Value::as_str).unwrap_or("");
        let id = frame.get("id").cloned();
        let response = match method {
            "initialize" => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "box-mcp-fetch-server", "version": "1"}
                }
            })),
            "notifications/initialized" => None,
            "tools/list" => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "reach",
                            "description": "Fetch FIXTURE_FETCH_TARGET and return its body",
                            "inputSchema": {"type": "object"}
                        },
                        {
                            "name": "echo",
                            "description": "Return the text argument",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"text": {"type": "string"}},
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "read",
                            "description": "Return the content of the file at path",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "env",
                            "description": "Return the value of the environment variable name",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"name": {"type": "string"}},
                                "required": ["name"]
                            }
                        },
                        {
                            "name": "unix-connect",
                            "description": "Connect to the pathname socket at path",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "exec",
                            "description": "Run the program at path with args",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                    "args": {"type": "array", "items": {"type": "string"}}
                                },
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "add",
                            "description": "Return the sum of two integers",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "a": {"type": "integer"},
                                    "b": {"type": "integer"}
                                },
                                "required": ["a", "b"]
                            }
                        }
                    ]
                }
            })),
            "tools/call" => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{"type": "text", "text": call_text(&frame)}],
                    "isError": false
                }
            })),
            // Any other request with an id gets a "method not found"; notifications are ignored.
            _ if id.is_some() => Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": "method not found"}
            })),
            _ => None,
        };
        if let Some(response) = response
            && (serde_json::to_writer(&mut stdout, &response).is_err()
                || stdout.write_all(b"\n").is_err()
                || stdout.flush().is_err())
        {
            break;
        }
    }
}

/// The result text for one `tools/call`, chosen by `params.name`.
fn call_text(frame: &Value) -> String {
    let params = frame.get("params");
    match params
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
    {
        Some("add") => {
            let argument = |name: &str| {
                params
                    .and_then(|params| params.get("arguments"))
                    .and_then(|arguments| arguments.get(name))
                    .and_then(Value::as_i64)
            };
            match (argument("a"), argument("b")) {
                (Some(a), Some(b)) => format!("sum:{}", a.saturating_add(b)),
                _ => "add-failed:a and b must be integers".to_string(),
            }
        }
        Some("echo") => match params
            .and_then(|params| params.get("arguments"))
            .and_then(|arguments| arguments.get("text"))
            .and_then(Value::as_str)
        {
            Some(text) => format!("echo:{text}"),
            None => "echo-failed:text must be a string".to_string(),
        },
        Some("read") => match string_argument(params, "path") {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(content) => format!("read:{content}"),
                Err(error) => format!("read-failed:errno={}", error.raw_os_error().unwrap_or(-1)),
            },
            None => "read-failed:path must be a string".to_string(),
        },
        Some("env") => match string_argument(params, "name") {
            Some(name) => match std::env::var(name) {
                Ok(value) => format!("env:{value}"),
                Err(_) => "env-unset".to_string(),
            },
            None => "env-failed:name must be a string".to_string(),
        },
        Some("unix-connect") => match string_argument(params, "path") {
            Some(path) => match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => "connect-ok".to_string(),
                Err(error) => format!(
                    "connect-failed:errno={}",
                    error.raw_os_error().unwrap_or(-1)
                ),
            },
            None => "connect-failed:path must be a string".to_string(),
        },
        Some("exec") => match string_argument(params, "path") {
            Some(path) => exec_text(path, &string_list(params, "args")),
            None => "exec-failed:path must be a string".to_string(),
        },
        _ => fetch_text(),
    }
}

/// Run `path` with `arguments` and stdin closed, and describe how it ended.
fn exec_text(path: &str, arguments: &[String]) -> String {
    match std::process::Command::new(path)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => format!(
            "exec-ok:{}",
            String::from_utf8_lossy(&output.stdout).trim_end()
        ),
        Ok(output) => format!(
            "exec-failed:status={}:{}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).trim_end()
        ),
        Err(error) => format!("exec-failed:errno={}", error.raw_os_error().unwrap_or(-1)),
    }
}

/// The string items of the array `tools/call` argument `name`.
fn string_list(params: Option<&Value>, name: &str) -> Vec<String> {
    params
        .and_then(|params| params.get("arguments"))
        .and_then(|arguments| arguments.get(name))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The string `tools/call` argument `name`.
fn string_argument<'a>(params: Option<&'a Value>, name: &str) -> Option<&'a str> {
    params
        .and_then(|params| params.get("arguments"))
        .and_then(|arguments| arguments.get(name))
        .and_then(Value::as_str)
}

/// Reach `FIXTURE_FETCH_TARGET` and return `fetched:<body>`, or `fetch-failed:<reason>`.
///
/// Two client models, selected by `FIXTURE_FETCH_PROXY`, so one binary exercises both egress
/// postures from a *contained* leaf:
/// - **unset (default): proxy-UNAWARE.** A raw direct TCP connect to the target. Models the
///   native-egress client (an SSO/raw client that cannot honor `HTTPS_PROXY`); this is the CN-NE
///   case — reaches an un-proxied host endpoint only when the leaf shares the host network.
/// - **set: proxy-AWARE.** Route through the proxy in `$HTTPS_PROXY` with an absolute-URI request,
///   so a contained *gateway* leaf's egress is mediated and policy-gated. `NO_PROXY` is deliberately
///   ignored (the box sets it to loopback; a real gateway test targets a loopback recorder), so the
///   request still traverses the gateway rather than short-circuiting to a direct connect.
fn fetch_text() -> String {
    let target = match std::env::var("FIXTURE_FETCH_TARGET") {
        Ok(target) => target,
        Err(_) => return "fetch-failed:FIXTURE_FETCH_TARGET is unset".to_string(),
    };
    let result = if std::env::var_os("FIXTURE_FETCH_PROXY").is_some() {
        match std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")) {
            Ok(proxy) => fetch_via_proxy(&proxy, &target),
            Err(_) => Err("HTTPS_PROXY unset while FIXTURE_FETCH_PROXY is set".to_string()),
        }
    } else {
        fetch_direct(&target)
    };
    match result {
        Ok(body) => format!("fetched:{body}"),
        Err(reason) => format!("fetch-failed:{reason}"),
    }
}

/// Split a target into its `authority` and `path`. Accepts `http://host:port/path` or bare
/// `host:port`.
fn split_target(target: &str) -> (&str, &str) {
    let without_scheme = target.strip_prefix("http://").unwrap_or(target);
    match without_scheme.find('/') {
        Some(slash) => (&without_scheme[..slash], &without_scheme[slash..]),
        None => (without_scheme, "/"),
    }
}

/// A minimal HTTP/1.0 GET over a raw TCP socket straight to the target — no sub-process, no
/// dependency, so the leaf needs only its own exec grant and a route.
fn fetch_direct(target: &str) -> Result<String, String> {
    let (authority, path) = split_target(target);
    let mut stream =
        TcpStream::connect(authority).map_err(|error| format!("connect {authority}: {error}"))?;
    stream
        .set_read_timeout(Some(CONNECT_TIMEOUT))
        .map_err(|error| format!("set read timeout: {error}"))?;
    let request = format!("GET {path} HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("write request: {error}"))?;
    read_body(stream)
}

/// Route the GET through an HTTP proxy: connect to the proxy from `$HTTPS_PROXY` and send an
/// absolute-URI request line (`GET http://host:port/path HTTP/1.1`), the form a forward proxy
/// expects. On a 2xx, return the body. On any other status, return the proxy/gateway's full raw
/// response as the failure reason — so a gateway policy refusal (`403 Forbidden`, the
/// `x-strands-box-egress: refused` marker, the named target) survives into the tool result for a
/// test to judge.
fn fetch_via_proxy(proxy: &str, target: &str) -> Result<String, String> {
    let proxy_authority = proxy
        .strip_prefix("http://")
        .unwrap_or(proxy)
        .trim_end_matches('/');
    let (authority, path) = split_target(target);
    let mut stream = TcpStream::connect(proxy_authority)
        .map_err(|error| format!("connect proxy {proxy_authority}: {error}"))?;
    stream
        .set_read_timeout(Some(CONNECT_TIMEOUT))
        .map_err(|error| format!("set read timeout: {error}"))?;
    let method = std::env::var("FIXTURE_FETCH_METHOD").unwrap_or_else(|_| "GET".to_string());
    let request = format!(
        "{method} http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("write request: {error}"))?;

    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .map_err(|error| format!("read response: {error}"))?;
    // Status line: `HTTP/1.1 <code> <reason>`.
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    if (200..300).contains(&status) {
        let body = raw
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or(&raw);
        Ok(body.trim().to_string())
    } else {
        // Carry the whole response so the gateway's refusal shape is visible to the caller.
        Err(raw.trim().to_string())
    }
}

/// Read a connection to EOF and return the body (everything after the header terminator).
fn read_body(mut stream: TcpStream) -> Result<String, String> {
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .map_err(|error| format!("read response: {error}"))?;
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&raw);
    Ok(body.trim().to_string())
}
