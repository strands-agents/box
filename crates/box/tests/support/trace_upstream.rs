//! An HTTP MCP origin that records requests and serves a two-tool catalog.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};

#[derive(Debug)]
pub(super) struct ReceivedRequest {
    pub(super) headers: BTreeMap<String, String>,
    pub(super) body: Value,
}

pub(super) struct TraceUpstream {
    pub(super) authority: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<Vec<ReceivedRequest>>>>,
}

impl TraceUpstream {
    pub(super) fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind MCP origin");
        let authority = listener.local_addr().unwrap().to_string();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let mut requests = Vec::new();
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Some(request) = serve(stream).inspect_err(|error| {
                            eprintln!("trace fixture origin failed: {error}");
                        })? {
                            requests.push(request);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if stopping.load(Ordering::Acquire) {
                            return Ok(requests);
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
        });
        Self {
            authority,
            stop,
            worker: Some(worker),
        }
    }

    pub(super) fn finish(mut self) -> Vec<ReceivedRequest> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("MCP origin thread")
            .expect("MCP origin exchange")
    }
}

impl Drop for TraceUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve(mut stream: TcpStream) -> io::Result<Option<ReceivedRequest>> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            if head.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::other("incomplete request headers"));
        }
        head.push(byte[0]);
        if head.len() > 16 * 1024 {
            return Err(io::Error::other("request headers exceed fixture limit"));
        }
    }
    let head = String::from_utf8(head).map_err(io::Error::other)?;
    if head.lines().next() != Some("POST /mcp HTTP/1.1") {
        return Err(io::Error::other(format!("unexpected request: {head}")));
    }
    let headers: BTreeMap<_, _> = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let length: usize = headers
        .get("content-length")
        .ok_or_else(|| io::Error::other("missing request content-length"))?
        .parse()
        .map_err(io::Error::other)?;
    if length > 64 * 1024 {
        return Err(io::Error::other("request body exceeds fixture limit"));
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    let body: Value = serde_json::from_slice(&body)?;
    let result = match body["method"].as_str() {
        Some("tools/list") => json!({
            "tools": (["echo", "blocked"].map(|name| json!({
                "name": name,
                "inputSchema": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"]
                }
            })))
        }),
        Some("tools/call") => json!({
            "content": [{"type": "text", "text": body["params"]["arguments"]["text"]}]
        }),
        _ => return Err(io::Error::other("unexpected MCP method")),
    };
    let reply = json!({"jsonrpc": "2.0", "id": body["id"], "result": result}).to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    )?;
    stream.flush()?;
    Ok(Some(ReceivedRequest { headers, body }))
}
