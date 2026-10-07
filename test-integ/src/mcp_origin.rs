//! A loopback HTTP MCP origin that serves a two-tool catalog and records each request it answers.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};

/// The tools the origin lists. Each takes one string argument, `text`.
pub const TOOLS: [&str; 2] = ["echo", "blocked"];

/// One JSON-RPC request the origin answered.
#[derive(Clone, Debug)]
pub struct Received {
    pub method: String,
    pub tool: Option<String>,
    pub text: Option<String>,
}

pub struct McpOrigin {
    /// `127.0.0.1:<port>`.
    pub authority: String,
    received: Arc<Mutex<Vec<Received>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl McpOrigin {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("DET_ERROR: bind the MCP origin");
        let authority = listener
            .local_addr()
            .expect("DET_ERROR: MCP origin address")
            .to_string();
        listener
            .set_nonblocking(true)
            .expect("DET_ERROR: MCP origin nonblocking");
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, stopping) = (Arc::clone(&received), Arc::clone(&stop));
        let worker = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => match serve(stream) {
                        Ok(Some(request)) => log.lock().unwrap().push(request),
                        Ok(None) => {}
                        Err(error) => eprintln!("MCP origin: {error}"),
                    },
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => {
                        eprintln!("MCP origin accept: {error}");
                        return;
                    }
                }
            }
        });
        Self {
            authority,
            received,
            stop,
            worker: Some(worker),
        }
    }

    /// The loopback port the origin answers on.
    pub fn port(&self) -> u16 {
        self.authority
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .expect("a port")
    }

    /// Every request answered so far, in order.
    pub fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    /// The `tools/call` requests answered so far, as `(tool, text)`.
    pub fn calls(&self) -> Vec<(String, String)> {
        self.received()
            .into_iter()
            .filter(|request| request.method == "tools/call")
            .map(|request| {
                (
                    request.tool.unwrap_or_default(),
                    request.text.unwrap_or_default(),
                )
            })
            .collect()
    }

    /// Forget every recorded request.
    pub fn clear(&self) {
        self.received.lock().unwrap().clear();
    }
}

impl Drop for McpOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve(mut stream: TcpStream) -> io::Result<Option<Received>> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            return if head.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::other("incomplete request head"))
            };
        }
        head.push(byte[0]);
        if head.len() > 16 * 1024 {
            return Err(io::Error::other("request head exceeds the origin limit"));
        }
    }
    let head = String::from_utf8(head).map_err(io::Error::other)?;
    if !head.starts_with("POST /mcp ") {
        return Err(io::Error::other(format!(
            "unexpected request: {}",
            head.lines().next().unwrap_or("")
        )));
    }
    let length: usize = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .ok_or_else(|| io::Error::other("missing content-length"))?
        .1
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    if length > 64 * 1024 {
        return Err(io::Error::other("request body exceeds the origin limit"));
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    let body: Value = serde_json::from_slice(&body)?;
    let method = body["method"].as_str().unwrap_or_default().to_string();
    let result = match method.as_str() {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "det-mcp-origin", "version": "1"}
        }),
        "tools/list" => json!({
            "tools": TOOLS.map(|name| json!({
                "name": name,
                "inputSchema": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"]
                }
            }))
        }),
        "tools/call" => json!({
            "content": [{"type": "text", "text": format!("origin:{}", body["params"]["arguments"]["text"].as_str().unwrap_or(""))}]
        }),
        other => return Err(io::Error::other(format!("unexpected MCP method {other:?}"))),
    };
    let reply = json!({"jsonrpc": "2.0", "id": body["id"], "result": result}).to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    )?;
    stream.flush()?;
    Ok(Some(Received {
        tool: body["params"]["name"].as_str().map(str::to_string),
        text: body["params"]["arguments"]["text"]
            .as_str()
            .map(str::to_string),
        method,
    }))
}
