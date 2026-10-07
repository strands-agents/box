//! Egress evidence helpers: a host-side recorder that stands where a delivery would land, and the
//! native TCP probe that speaks to the box's egress gateway from inside the cage.
//!
//! A recorder is a test-owned loopback listener on the HOST. The gateway runs in the host's network
//! namespace, so a request the gateway forwards to `127.0.0.1:<port>` lands here, and a request it
//! refuses does not. Every count is measured: a case first proves the recorder live with a direct
//! host connection ([`HostRecorder::self_test`]), then trusts its zero. A connection the recorder
//! could not read to completion is an [`Observation`] with `complete == false` and a named error,
//! never a silent zero. Each connection has a total deadline; `stop` shuts every owned stream.
//!
//! The probe is a small binary the case compiles with [`crate::BoxFixture::compile_probe`] and runs
//! from the native contained bash under the agent's own `exec` grant on the fixture's `out/` tree
//! ([`crate::BoxFixture::with_exec_tree`]), the route CN-X-02 and CN-N-03 use. Its sockets are the
//! agent's own syscalls; nothing passes the broker. It connects to the port in `$HTTP_PROXY` (on
//! Linux the trampoline's relay inside the workload's network namespace, on macOS the gateway's
//! loopback port), writes the request bytes, reads the response to EOF or a total deadline, and
//! prints records the case parses. Response bytes travel only as hex inside `DATA` records, so no
//! response byte can look like a control record, and NUL, CR and binary bytes survive exactly.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The body the recorder answers with, so a case can tell a recorder answer from any other 200.
pub const RECORDER_BODY: &str = "DET_RECORDER_OK";

/// The header the gateway puts on every response it originates at L7 and on no relayed response.
pub const GATEWAY_ORIGIN_HEADER: &str = "x-strands-box-egress";

/// The most head bytes the recorder reads before it records the connection as incomplete.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// The most body bytes the recorder reads before it records the connection as incomplete.
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// The default total time one recorder connection has to deliver its request, from accept.
pub const DEFAULT_CONNECTION_DEADLINE: Duration = Duration::from_secs(5);
/// How long a snapshot waits for the accept loop's acknowledgement and for in-flight connections.
const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(10);

// ============================================================================================
// The host recorder
// ============================================================================================

/// One connection the recorder accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The request line, when a head arrived.
    pub request_line: Option<String>,
    /// Every byte read, head and body, as text.
    pub raw: String,
    /// Whether the head and the declared body were read in full within the limits and deadline.
    pub complete: bool,
    /// Why the read stopped short, when it did.
    pub error: Option<String>,
}

/// What the recorder saw, taken after a drain barrier: the accept loop has swept its backlog after
/// the caller asked, and every accepted connection has finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Every connection accepted, complete or not, in arrival order.
    pub observations: Vec<Observation>,
    /// Errors the accept loop met other than "nothing pending".
    pub accept_errors: Vec<String>,
}

impl Snapshot {
    /// The request lines of the requests read to completion, in arrival order.
    pub fn request_lines(&self) -> Vec<String> {
        self.observations
            .iter()
            .filter(|o| o.complete)
            .filter_map(|o| o.request_line.clone())
            .collect()
    }

    /// The raw requests read to completion, head and body.
    pub fn requests(&self) -> Vec<String> {
        self.observations
            .iter()
            .filter(|o| o.complete)
            .map(|o| o.raw.clone())
            .collect()
    }

    /// The connections that did not deliver a complete request.
    pub fn incomplete(&self) -> Vec<Observation> {
        self.observations
            .iter()
            .filter(|o| !o.complete)
            .cloned()
            .collect()
    }

    /// Bytes received over every connection.
    pub fn bytes(&self) -> usize {
        self.observations.iter().map(|o| o.raw.len()).sum()
    }
}

/// The test hook run between the accept loop's stop check and its `accept`, given the stop flag.
type BeforeAccept = Arc<dyn Fn(&AtomicBool) + Send + Sync>;

struct Shared {
    observations: Mutex<Vec<Observation>>,
    accept_errors: Mutex<Vec<String>>,
    /// Streams of connections still being read, so `stop` can shut them down.
    active: Mutex<Vec<(u64, TcpStream)>>,
    in_flight: AtomicUsize,
    stop: AtomicBool,
    /// Drain barrier: the caller bumps `drain_requested`; the accept loop sweeps its backlog and
    /// copies the value into `drain_acknowledged`.
    drain_requested: AtomicU64,
    drain_acknowledged: AtomicU64,
    deadline: Duration,
    /// A pause the tests insert between a sweep and its acknowledgement, to schedule the race the
    /// ticket ordering closes. `None` in every case.
    after_sweep: Option<Arc<dyn Fn() + Send + Sync>>,
    /// A test hook run after the accept loop's stop check and before its `accept`, given the stop
    /// flag: the one place a stream can still be accepted once `stop` has asked. `None` in every
    /// case.
    before_accept: Option<BeforeAccept>,
}

/// A loopback listener on the host recording every connection it accepts.
pub struct HostRecorder {
    addr: SocketAddr,
    shared: Arc<Shared>,
    accept_thread: Option<JoinHandle<()>>,
    handlers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl HostRecorder {
    /// Bind an ephemeral loopback port and answer every complete HTTP request with `200` and
    /// [`RECORDER_BODY`], with the default per-connection deadline.
    pub fn start() -> Self {
        Self::start_with_deadline(DEFAULT_CONNECTION_DEADLINE)
    }

    /// [`HostRecorder::start`] with a total per-connection deadline of `deadline`.
    pub fn start_with_deadline(deadline: Duration) -> Self {
        Self::start_with(deadline, None)
    }

    fn start_with(deadline: Duration, after_sweep: Option<Arc<dyn Fn() + Send + Sync>>) -> Self {
        Self::start_with_hooks(deadline, after_sweep, None)
    }

    fn start_with_hooks(
        deadline: Duration,
        after_sweep: Option<Arc<dyn Fn() + Send + Sync>>,
        before_accept: Option<BeforeAccept>,
    ) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("DET_ERROR: bind a loopback recorder on the host");
        listener
            .set_nonblocking(true)
            .expect("DET_ERROR: make the recorder's listener pollable");
        let addr = listener
            .local_addr()
            .expect("DET_ERROR: read the recorder's address");
        let shared = Arc::new(Shared {
            observations: Mutex::new(Vec::new()),
            accept_errors: Mutex::new(Vec::new()),
            active: Mutex::new(Vec::new()),
            in_flight: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
            drain_requested: AtomicU64::new(0),
            drain_acknowledged: AtomicU64::new(0),
            deadline,
            after_sweep,
            before_accept,
        });
        let handlers: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let (s, h) = (shared.clone(), handlers.clone());
        let accept_thread = std::thread::spawn(move || {
            let mut next_id = 0u64;
            loop {
                // Take the drain ticket BEFORE the sweep, and acknowledge only that ticket after a
                // sweep that ended in "nothing pending". A request made after this load waits for
                // the next sweep, so a connection queued before it can never be missed by the
                // snapshot that asked for it.
                let ticket = s.drain_requested.load(Ordering::SeqCst);
                loop {
                    if s.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Some(hook) = &s.before_accept {
                        hook(&s.stop);
                    }
                    match listener.accept() {
                        Ok((tcp, _)) => {
                            // BSD and macOS hand an accepted socket the listener's O_NONBLOCK;
                            // Linux does not. The handler reads under timeouts, so the stream
                            // must block, or every read fails at once with WouldBlock.
                            if let Err(error) = tcp.set_nonblocking(false) {
                                s.accept_errors
                                    .lock()
                                    .unwrap()
                                    .push(format!("set accepted stream blocking: {error}"));
                                break;
                            }
                            let id = next_id;
                            next_id += 1;
                            s.in_flight.fetch_add(1, Ordering::SeqCst);
                            if let Ok(handle) = tcp.try_clone() {
                                s.active.lock().unwrap().push((id, handle));
                            }
                            let s = s.clone();
                            let handle = std::thread::spawn(move || {
                                let observation = observe(tcp, s.deadline);
                                s.observations.lock().unwrap().push(observation);
                                s.active.lock().unwrap().retain(|(i, _)| *i != id);
                                s.in_flight.fetch_sub(1, Ordering::SeqCst);
                            });
                            h.lock().unwrap().push(handle);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => {
                            s.accept_errors.lock().unwrap().push(error.to_string());
                            break;
                        }
                    }
                }
                if let Some(pause) = &s.after_sweep {
                    pause();
                }
                if s.drain_acknowledged.load(Ordering::SeqCst) < ticket {
                    s.drain_acknowledged.store(ticket, Ordering::SeqCst);
                }
                if s.stop.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        Self {
            addr,
            shared,
            accept_thread: Some(accept_thread),
            handlers,
        }
    }

    /// The recorder's port on `127.0.0.1`.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Take a snapshot behind a drain barrier: ask the accept loop to sweep its backlog and
    /// acknowledge, then wait for every accepted connection to finish. Panics as `DET_ERROR` if the
    /// loop does not acknowledge or a connection is still being read after [`SNAPSHOT_DEADLINE`],
    /// so a hung delivery or a dead loop can never read as a clean count.
    pub fn snapshot(&self) -> Snapshot {
        let stopped = self.shared.stop.load(Ordering::SeqCst);
        if !stopped {
            let wanted = self.shared.drain_requested.fetch_add(1, Ordering::SeqCst) + 1;
            let deadline = Instant::now() + SNAPSHOT_DEADLINE;
            while self.shared.drain_acknowledged.load(Ordering::SeqCst) < wanted {
                assert!(
                    Instant::now() < deadline,
                    "DET_ERROR: the recorder's accept loop did not acknowledge a drain within {SNAPSHOT_DEADLINE:?}"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let deadline = Instant::now() + SNAPSHOT_DEADLINE;
        while self.shared.in_flight.load(Ordering::SeqCst) > 0 {
            assert!(
                Instant::now() < deadline,
                "DET_ERROR: a recorder connection is still being read after {SNAPSHOT_DEADLINE:?}"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        Snapshot {
            observations: self.shared.observations.lock().unwrap().clone(),
            accept_errors: self.shared.accept_errors.lock().unwrap().clone(),
        }
    }

    /// Every connection accepted so far, complete or not, in arrival order.
    pub fn observations(&self) -> Vec<Observation> {
        self.snapshot().observations
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.snapshot().observations.len()
    }

    /// Bytes received so far, over every connection.
    pub fn bytes(&self) -> usize {
        self.snapshot().bytes()
    }

    /// The request lines of the requests read to completion, in arrival order.
    pub fn request_lines(&self) -> Vec<String> {
        self.snapshot().request_lines()
    }

    /// The raw requests read to completion, head and body.
    pub fn requests(&self) -> Vec<String> {
        self.snapshot().requests()
    }

    /// The connections that did not deliver a complete request: a bare connect, a truncated body,
    /// an oversized head or body, a deadline, or a read error. A case that claims "nothing arrived"
    /// asserts this is empty as well as `connections() == 0`.
    pub fn incomplete(&self) -> Vec<Observation> {
        self.snapshot().incomplete()
    }

    /// Errors the accept loop met. A case asserts this is empty before it trusts a count.
    pub fn accept_errors(&self) -> Vec<String> {
        self.snapshot().accept_errors
    }

    /// Prove the recorder is live from the host, then reset it so the case's own measurement starts
    /// at zero. Panics as `DET_ERROR` when the observer itself is broken.
    pub fn self_test(&self) {
        let mut tcp = TcpStream::connect_timeout(&self.addr, DEFAULT_CONNECTION_DEADLINE)
            .expect("DET_ERROR: the host cannot reach its own recorder");
        tcp.set_read_timeout(Some(DEFAULT_CONNECTION_DEADLINE))
            .expect("DET_ERROR: bound the self-test read");
        tcp.write_all(b"GET /det-self-test HTTP/1.1\r\nHost: recorder\r\n\r\n")
            .expect("DET_ERROR: write the self-test request");
        let reply = read_head_and_body(
            &mut tcp,
            MAX_HEAD_BYTES,
            MAX_BODY_BYTES,
            Instant::now() + DEFAULT_CONNECTION_DEADLINE,
        );
        assert!(
            reply.complete
                && reply.raw.starts_with("HTTP/1.1 200")
                && reply.raw.contains(RECORDER_BODY),
            "DET_ERROR: the recorder did not answer its own self-test: {reply:?}"
        );
        let seen = self.snapshot();
        assert!(
            seen.accept_errors.is_empty(),
            "DET_ERROR: the recorder's accept loop reported errors: {:?}",
            seen.accept_errors
        );
        assert_eq!(
            seen.observations.len(),
            1,
            "DET_ERROR: the recorder did not count the self-test: {seen:?}"
        );
        assert!(
            seen.observations[0].complete
                && seen.observations[0].request_line.as_deref()
                    == Some("GET /det-self-test HTTP/1.1"),
            "DET_ERROR: the recorder did not record the self-test whole: {seen:?}"
        );
        self.shared.observations.lock().unwrap().clear();
    }

    /// Stop accepting, shut down every connection still being read, join the accept loop and every
    /// handler. Bounded by the handlers noticing the shutdown, not by a peer's pace. Called on drop.
    pub fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // Join the accept loop first, so the active set below includes every stream it accepted;
        // a stream accepted after the set was taken could otherwise miss its shutdown.
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
        for (_, stream) in self.shared.active.lock().unwrap().iter() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let handlers: Vec<JoinHandle<()>> = std::mem::take(&mut *self.handlers.lock().unwrap());
        for handle in handlers {
            let _ = handle.join();
        }
    }
}

impl Drop for HostRecorder {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Read one connection's request within the limits and `deadline`, answer a complete one, and
/// describe what happened.
fn observe(mut tcp: TcpStream, deadline: Duration) -> Observation {
    let read = read_head_and_body(
        &mut tcp,
        MAX_HEAD_BYTES,
        MAX_BODY_BYTES,
        Instant::now() + deadline,
    );
    let request_line = read
        .raw
        .lines()
        .next()
        .filter(|line| line.contains("HTTP/"))
        .map(str::to_string);
    let complete = read.complete && request_line.is_some();
    if complete {
        let body = format!("{RECORDER_BODY}\n");
        let _ = tcp.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
        let _ = tcp.flush();
    }
    let error = match (read.error, request_line.is_some()) {
        (Some(error), _) => Some(error),
        (None, false) => Some("no request line".to_string()),
        (None, true) => None,
    };
    Observation {
        request_line,
        raw: read.raw,
        complete,
        error,
    }
}

/// The outcome of one bounded head-and-body read.
#[derive(Debug)]
struct BoundedRead {
    raw: String,
    complete: bool,
    error: Option<String>,
}

/// Whether a read error is the armed deadline firing.
fn is_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Arm the stream's read timeout with the time left to `deadline`, or say the deadline passed.
fn arm_deadline(stream: &TcpStream, deadline: Instant) -> Result<(), String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("deadline exceeded".to_string());
    }
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|error| format!("set read timeout: {error}"))
}

/// Read an HTTP head plus a `Content-Length` body from a stream, within `max_head` and `max_body`
/// bytes and a total `deadline`, naming why the read stopped short when it did.
fn read_head_and_body(
    stream: &mut TcpStream,
    max_head: usize,
    max_body: usize,
    deadline: Instant,
) -> BoundedRead {
    let stop = |buf: &[u8], error: String| BoundedRead {
        raw: String::from_utf8_lossy(buf).into_owned(),
        complete: false,
        error: Some(error),
    };
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    let head_end = loop {
        if buf.len() >= max_head {
            return stop(&buf, format!("head exceeds {max_head} bytes"));
        }
        if let Err(error) = arm_deadline(stream, deadline) {
            return stop(&buf, format!("{error} after {} head bytes", buf.len()));
        }
        match stream.read(&mut byte) {
            Ok(1) => buf.push(byte[0]),
            Ok(_) => return stop(&buf, "closed before the end of the head".to_string()),
            Err(error) if is_timeout(&error) => {
                return stop(
                    &buf,
                    format!("deadline exceeded after {} head bytes", buf.len()),
                );
            }
            Err(error) => {
                return stop(
                    &buf,
                    format!("reading the head after {} bytes: {error}", buf.len()),
                );
            }
        }
        if buf.ends_with(b"\r\n\r\n") {
            break buf.len();
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let Some(len) = content_length(&head) else {
        return BoundedRead {
            raw: head,
            complete: false,
            error: Some("malformed Content-Length".to_string()),
        };
    };
    if len > max_body {
        return BoundedRead {
            raw: head,
            complete: false,
            error: Some(format!("declared body {len} exceeds {max_body} bytes")),
        };
    }
    let mut body = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        if let Err(error) = arm_deadline(stream, deadline) {
            body.truncate(filled);
            return BoundedRead {
                raw: format!("{head}{}", String::from_utf8_lossy(&body)),
                complete: false,
                error: Some(format!("{error} after {filled} of {len} body bytes")),
            };
        }
        match stream.read(&mut body[filled..]) {
            Ok(0) => {
                body.truncate(filled);
                return BoundedRead {
                    raw: format!("{head}{}", String::from_utf8_lossy(&body)),
                    complete: false,
                    error: Some(format!("closed after {filled} of {len} body bytes")),
                };
            }
            Ok(n) => filled += n,
            Err(error) => {
                body.truncate(filled);
                let why = if is_timeout(&error) {
                    format!("deadline exceeded after {filled} of {len} body bytes")
                } else {
                    format!("reading the body after {filled} of {len} bytes: {error}")
                };
                return BoundedRead {
                    raw: format!("{head}{}", String::from_utf8_lossy(&body)),
                    complete: false,
                    error: Some(why),
                };
            }
        }
    }
    BoundedRead {
        raw: format!("{head}{}", String::from_utf8_lossy(&body)),
        complete: true,
        error: None,
    }
}

/// The one `Content-Length` a head declares, `Some(0)` when it declares none, `None` when it is
/// repeated, empty or not a number.
fn content_length(head: &str) -> Option<usize> {
    let values: Vec<&str> = head
        .split("\r\n")
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim())
        })
        .collect();
    match values.as_slice() {
        [] => Some(0),
        [one] => one.parse().ok(),
        _ => None,
    }
}

// ============================================================================================
// The native probe
// ============================================================================================

/// The prefix of every record the probe prints. Response bytes never appear outside a `DATA`
/// record's hex field, so no response byte can spell a record.
pub const PROBE_RECORD: &str = "DET_PROBE";

/// The probe's source: `egress-probe TAG PORT REQUEST [TIMEOUT_SECS] [abort]`, where `REQUEST` is
/// the request bytes as hex, or `@path` naming a file holding them. It connects to
/// `127.0.0.1:PORT`, writes the decoded request, then either closes at once (`abort`) or reads to
/// EOF or the total deadline. Records, one per line on stdout:
///
/// | record | meaning |
/// |---|---|
/// | `DET_PROBE TAG CONNECT_FAILED <error>` | no connection to the proxy port |
/// | `DET_PROBE TAG WRITE_FAILED <error>` | the request did not go out whole |
/// | `DET_PROBE TAG DATA <hex>` | response bytes, in order, possibly several records |
/// | `DET_PROBE TAG END EOF` | the peer closed after the data |
/// | `DET_PROBE TAG END TIMEOUT` | the deadline passed with the connection open |
/// | `DET_PROBE TAG END RESET` | the peer reset the connection after the data |
///
/// Every read is bounded by the total deadline: by `SO_RCVTIMEO` while the kernel accepts it, and
/// by non-blocking polling to the same deadline once it does not. `DET_PROBE_FAULT=rearm-einval`
/// makes the first option call fail, for the harness's own regression.
/// | `DET_PROBE TAG END ERROR <error>` | a read error |
/// | `DET_PROBE TAG END TRUNCATED` | the 1 MiB capture bound was reached |
/// | `DET_PROBE TAG END ABORTED` | `abort` mode: written and closed without reading |
pub const PROBE_SOURCE: &str = r#"
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

const MAX_CAPTURE: usize = 1024 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: egress-probe TAG PORT REQUEST_HEX|@FILE [TIMEOUT_SECS] [abort]");
        std::process::exit(2);
    }
    let tag = &args[1];
    let port: u16 = args[2].parse().expect("PORT is a number");
    let request = match args[3].strip_prefix('@') {
        Some(path) => std::fs::read(path).expect("REQUEST file is readable"),
        None => unhex(&args[3]).expect("REQUEST_HEX is hex"),
    };
    let timeout: u64 = args.get(4).and_then(|t| t.parse().ok()).unwrap_or(15);
    let abort = args.get(5).map(String::as_str) == Some("abort");
    let mut out = std::io::stdout();
    let record = |out: &mut std::io::Stdout, text: String| {
        let _ = writeln!(out, "DET_PROBE {tag} {text}");
        let _ = out.flush();
    };

    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut tcp = match TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(timeout),
    ) {
        Ok(tcp) => tcp,
        Err(error) => {
            record(&mut out, format!("CONNECT_FAILED {error}"));
            return;
        }
    };
    // The write phase shares the total deadline: a peer that never drains the request cannot hold
    // the probe past it. One absolute deadline across partial writes: the time left is recomputed
    // before every write, a zero-length write is a failure, and nothing continues past the deadline.
    let total = request.len();
    let mut written = 0usize;
    while written < total {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            record(&mut out, format!("WRITE_FAILED deadline exceeded after {written} of {total} bytes"));
            return;
        }
        if let Err(error) = tcp.set_write_timeout(Some(remaining)) {
            record(&mut out, format!("WRITE_FAILED set write timeout: {error}"));
            return;
        }
        match tcp.write(&request[written..]) {
            Ok(0) => {
                record(&mut out, format!("WRITE_FAILED zero-length write after {written} of {total} bytes"));
                return;
            }
            Ok(n) => written += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                record(&mut out, format!("WRITE_FAILED deadline exceeded after {written} of {total} bytes"));
                return;
            }
            Err(error) => {
                record(&mut out, format!("WRITE_FAILED after {written} of {total} bytes: {error}"));
                return;
            }
        }
    }
    if let Err(error) = tcp.flush() {
        record(&mut out, format!("WRITE_FAILED flush: {error}"));
        return;
    }
    if abort {
        let _ = tcp.shutdown(Shutdown::Both);
        record(&mut out, "END ABORTED".to_string());
        return;
    }
    // Every read is bounded by the absolute deadline. While the kernel accepts SO_RCVTIMEO, each
    // read blocks for at most the time left. Once the kernel refuses it (macOS answers EINVAL for a
    // socket the peer has reset or closed), the socket is switched to non-blocking and polled: a
    // read then returns at once with data, EOF, a reset or WouldBlock, and WouldBlock at the
    // deadline is a TIMEOUT. No read may block without a bound, so a peer that holds the
    // connection open after a refused option ends the transcript at the deadline, not later.
    // `DET_PROBE_FAULT=rearm-einval` makes the first option call fail, for the regression only.
    let mut fault_first_rearm = std::env::var_os("DET_PROBE_FAULT")
        .is_some_and(|value| value == "rearm-einval");
    let mut polling = false;
    let mut captured = 0usize;
    let mut buf = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            record(&mut out, "END TIMEOUT".to_string());
            return;
        }
        if !polling {
            let armed = if fault_first_rearm {
                fault_first_rearm = false;
                Err(std::io::Error::from_raw_os_error(22))
            } else {
                tcp.set_read_timeout(Some(remaining))
            };
            if armed.is_err() {
                if let Err(error) = tcp.set_nonblocking(true) {
                    record(&mut out, format!("END ERROR set non-blocking after a refused read timeout: {error}"));
                    return;
                }
                polling = true;
            }
        }
        match tcp.read(&mut buf) {
            Ok(0) => {
                record(&mut out, "END EOF".to_string());
                return;
            }
            Ok(n) => {
                let take = n.min(MAX_CAPTURE - captured);
                record(&mut out, format!("DATA {}", hex(&buf[..take])));
                captured += take;
                if captured >= MAX_CAPTURE {
                    record(&mut out, "END TRUNCATED".to_string());
                    return;
                }
            }
            Err(error)
                if polling
                    && (error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut) =>
            {
                std::thread::sleep(Duration::from_millis(10).min(remaining));
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                record(&mut out, "END TIMEOUT".to_string());
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                record(&mut out, "END RESET".to_string());
                return;
            }
            Err(error) => {
                record(&mut out, format!("END ERROR {error}"));
                return;
            }
        }
    }
}
"#;

/// Hex-encode bytes for a probe argument.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// A plain-HTTP absolute-form request for `method` `http://authority/path`, as request bytes.
pub fn absolute_request(method: &str, authority: &str, path: &str) -> Vec<u8> {
    format!(
        "{method} http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// How a probe should treat the connection after writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    /// Read the response to EOF or the deadline.
    Read,
    /// Close without reading, as a killed client does.
    Abort,
}

/// The bash line that runs the compiled probe at `probe` for `tag` against the proxy port in
/// `$HTTP_PROXY`, sending `request`. `timeout_secs` is the probe's total deadline.
pub fn probe_command(
    probe: &std::path::Path,
    tag: &str,
    request: &[u8],
    timeout_secs: u64,
    mode: ProbeMode,
) -> String {
    let mode = match mode {
        ProbeMode::Read => "",
        ProbeMode::Abort => " abort",
    };
    format!(
        "'{}' {tag} \"${{HTTP_PROXY##*:}}\" {} {timeout_secs}{mode}",
        probe.display(),
        hex(request)
    )
}

/// How a probe's transcript ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The probe could not connect to the proxy port.
    ConnectFailed,
    /// The request was not written whole.
    WriteFailed,
    /// The peer closed after the data.
    Eof,
    /// The deadline passed with the connection open.
    TimedOut,
    /// The peer reset the connection after the data (a close with unread request bytes).
    Reset,
    /// A read error.
    Error,
    /// The capture bound was reached.
    Truncated,
    /// `abort` mode: written and closed without reading.
    Aborted,
    /// No `END` record: the probe never finished (or never ran).
    Missing,
    /// More than one `END` record, or records after an `END`: the transcript is not trustworthy.
    Invalid,
}

/// One probe's transcript: the raw response bytes and the strictly parsed HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    /// The response bytes exactly as received.
    pub bytes: Vec<u8>,
    /// The status line, when the bytes start with a well-formed one.
    pub status_line: Option<String>,
    /// The headers, in order, names lowercased; duplicates kept.
    pub headers: Vec<(String, String)>,
    /// The first head line that is not `token: value`, if any.
    pub malformed: Option<String>,
    /// Whether the blank line that ends the head arrived.
    pub head_complete: bool,
    /// The body bytes after the head.
    pub body: Vec<u8>,
    pub ending: Ending,
    /// The connect/write/read error text, when the ending carries one.
    pub detail: Option<String>,
}

impl Transcript {
    /// Parse the records of probe `tag` out of `out`.
    pub fn of(out: &str, tag: &str) -> Self {
        let prefix = format!("{PROBE_RECORD} {tag} ");
        let mut bytes = Vec::new();
        let mut ending = Ending::Missing;
        let mut detail = None;
        let mut ended = false;
        let mut invalid = false;
        for record in out.lines().filter_map(|line| line.strip_prefix(&prefix)) {
            if ended {
                invalid = true;
                break;
            }
            let (kind, rest) = record.split_once(' ').unwrap_or((record, ""));
            match kind {
                "DATA" => match unhex(rest) {
                    Some(mut chunk) => bytes.append(&mut chunk),
                    None => {
                        invalid = true;
                        break;
                    }
                },
                "END" => {
                    ended = true;
                    let (how, text) = rest.split_once(' ').unwrap_or((rest, ""));
                    ending = match how {
                        "EOF" => Ending::Eof,
                        "TIMEOUT" => Ending::TimedOut,
                        "RESET" => Ending::Reset,
                        "ERROR" => Ending::Error,
                        "TRUNCATED" => Ending::Truncated,
                        "ABORTED" => Ending::Aborted,
                        _ => Ending::Invalid,
                    };
                    if !text.is_empty() {
                        detail = Some(text.to_string());
                    }
                }
                "CONNECT_FAILED" => {
                    ended = true;
                    ending = Ending::ConnectFailed;
                    detail = Some(rest.to_string());
                }
                "WRITE_FAILED" => {
                    ended = true;
                    ending = Ending::WriteFailed;
                    detail = Some(rest.to_string());
                }
                _ => {
                    invalid = true;
                    break;
                }
            }
        }
        if invalid {
            ending = Ending::Invalid;
        }
        let parsed = parse_response(&bytes);
        Transcript {
            bytes,
            status_line: parsed.status_line,
            headers: parsed.headers,
            malformed: parsed.malformed,
            head_complete: parsed.head_complete,
            body: parsed.body,
            ending,
            detail,
        }
    }

    /// Every value of header `name`, in order.
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The value of header `name` when it appears exactly once.
    pub fn header(&self, name: &str) -> Option<&str> {
        match self.header_values(name).as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }

    /// The status code, when the status line is well-formed.
    pub fn status(&self) -> Option<u16> {
        self.status_line
            .as_deref()?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    }

    /// The body as text, lossily, for messages and marker checks.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

struct ParsedResponse {
    status_line: Option<String>,
    headers: Vec<(String, String)>,
    malformed: Option<String>,
    head_complete: bool,
    body: Vec<u8>,
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Parse one HTTP/1.1 response strictly: `HTTP/1.1 NNN reason\r\n`, header lines `token: value\r\n`
/// with no bare LF, an empty line, then the body. Anything else is recorded, not repaired.
fn parse_response(bytes: &[u8]) -> ParsedResponse {
    let mut parsed = ParsedResponse {
        status_line: None,
        headers: Vec::new(),
        malformed: None,
        head_complete: false,
        body: Vec::new(),
    };
    let Some(head_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        // No complete head: only a well-formed first line is read; the body stays empty.
        let text = String::from_utf8_lossy(bytes);
        if let Some(status) = text
            .split("\r\n")
            .next()
            .filter(|line| well_formed_status(line))
        {
            parsed.status_line = Some(status.to_string());
        }
        return parsed;
    };
    let head = String::from_utf8_lossy(&bytes[..head_end]).into_owned();
    parsed.body = bytes[head_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let Some(status) = lines.next() else {
        return parsed;
    };
    if !well_formed_status(status) {
        parsed.malformed = Some(status.to_string());
        return parsed;
    }
    parsed.status_line = Some(status.to_string());
    for line in lines {
        let ok = line
            .split_once(':')
            .filter(|(name, _)| !name.is_empty() && name.bytes().all(is_token_byte))
            .filter(|(_, value)| !value.contains('\n') && !value.contains('\r'));
        match ok {
            Some((name, value)) => parsed.headers.push((
                name.to_ascii_lowercase(),
                value.trim_matches([' ', '\t']).to_string(),
            )),
            None => {
                if parsed.malformed.is_none() {
                    parsed.malformed = Some(line.to_string());
                }
            }
        }
    }
    parsed.head_complete = true;
    parsed
}

/// `HTTP/1.1 NNN reason`, with a three-digit code and a non-empty reason.
fn well_formed_status(line: &str) -> bool {
    let mut parts = line.splitn(3, ' ');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some("HTTP/1.1"), Some(code), Some(reason))
            if code.len() == 3
                && code.bytes().all(|b| b.is_ascii_digit())
                && !reason.is_empty()
                && !line.contains('\n')
    )
}

/// The status code the gateway answered probe `tag` with, when the response has a well-formed
/// status line and the transcript is trustworthy.
pub fn status_code(out: &str, tag: &str) -> Option<u16> {
    let transcript = Transcript::of(out, tag);
    (transcript.ending != Ending::Invalid)
        .then(|| transcript.status())
        .flatten()
}

/// Whether probe `tag` reached the gateway and the gateway closed the connection after answering:
/// a complete, trustworthy transcript ending in EOF. A timeout, an error, a truncation or a missing
/// or duplicated end is not a reached gateway.
pub fn probe_reached_gateway(out: &str, tag: &str) -> bool {
    Transcript::of(out, tag).ending == Ending::Eof
}

/// Whether the response to probe `tag` is a complete `200` whose body is the recorder's marker and
/// nothing else, and the gateway closed after it.
pub fn probe_reached_recorder(out: &str, tag: &str) -> bool {
    let transcript = Transcript::of(out, tag);
    transcript.ending == Ending::Eof
        && transcript.status() == Some(200)
        && transcript.malformed.is_none()
        && transcript.body == format!("{RECORDER_BODY}\n").into_bytes()
}

/// What the HOST's own resolver says about a spelling. The gateway runs on the host and resolves
/// with the same `getaddrinfo`, so this is the independent observation a `502` needs before it may
/// be read as "the resolver refused this spelling".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostResolution {
    Resolves,
    Refuses,
}

impl HostResolution {
    /// Ask the host resolver about `spelling` as a host name.
    pub fn of(spelling: &str) -> Self {
        let resolves = (spelling, 80u16)
            .to_socket_addrs()
            .map(|addresses| addresses.count() > 0)
            .unwrap_or(false);
        if resolves {
            HostResolution::Resolves
        } else {
            HostResolution::Refuses
        }
    }
}

/// Which boundary answered a probe for a floor-denied destination: the gateway floor's bare
/// `403 forbidden`, or the resolver's refusal of the spelling (`502 bad gateway` from the gateway
/// AND the host's own resolver refusing the same spelling), which proves nothing about the floor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FloorAnswer {
    GatewayFloor,
    Unresolvable,
}

/// Whether `transcript` is exactly the gateway's own bare status answer (`write_status`): one
/// well-formed status line reading `expected`, exactly the headers `Content-Length: 0` and
/// `Connection: close` (once each, in any order, nothing else), a complete head, no body byte, and
/// EOF. Anything else names why not.
pub fn bare_gateway_answer(transcript: &Transcript, expected: &str) -> Result<(), String> {
    bare_ending(transcript)?;
    bare_shape(transcript, expected)
}

/// The ending a bare gateway answer must have: EOF, and nothing else.
fn bare_ending(transcript: &Transcript) -> Result<(), String> {
    match transcript.ending {
        Ending::ConnectFailed => return Err("the probe never reached the gateway".into()),
        Ending::WriteFailed => return Err("the request was not written whole".into()),
        Ending::TimedOut => {
            return Err("the gateway did not close the connection: timed out".into());
        }
        Ending::Reset => return Err("the connection was reset, not closed".into()),
        Ending::Error => {
            return Err(format!(
                "read error: {}",
                transcript.detail.as_deref().unwrap_or("unknown")
            ));
        }
        Ending::Truncated => return Err("the capture bound was reached".into()),
        Ending::Aborted => return Err("an aborted probe reads no answer".into()),
        Ending::Missing => return Err("truncated transcript: no end was observed".into()),
        Ending::Invalid => return Err("invalid transcript: duplicate or trailing records".into()),
        Ending::Eof => {}
    }
    Ok(())
}

/// The bytes of a bare gateway answer (`write_status`), apart from how the connection ended: one
/// well-formed status line reading `expected`, exactly `Content-Length: 0` and `Connection: close`
/// once each and nothing else, no malformed line, a complete head, no body byte.
pub fn bare_shape(transcript: &Transcript, expected: &str) -> Result<(), String> {
    if let Some(line) = &transcript.malformed {
        return Err(format!("malformed head line {line:?}"));
    }
    match transcript.status_line.as_deref() {
        Some(line) if line == expected => {}
        Some(line) => return Err(format!("status line {line:?}, expected {expected:?}")),
        None => return Err("no well-formed status line".into()),
    }
    if !transcript.head_complete {
        return Err("the head never ended: no blank line".into());
    }
    let mut names: Vec<&str> = transcript.headers.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    if names != ["connection", "content-length"] {
        return Err(format!(
            "a bare gateway answer carries exactly Content-Length and Connection once each, saw {:?}",
            transcript.headers
        ));
    }
    if transcript.header("content-length") != Some("0") {
        return Err(format!(
            "a bare gateway answer declares Content-Length: 0, saw {:?}",
            transcript.header_values("content-length")
        ));
    }
    if !transcript
        .header("connection")
        .is_some_and(|v| v.eq_ignore_ascii_case("close"))
    {
        return Err("a bare gateway answer declares Connection: close".into());
    }
    if !transcript.body.is_empty() {
        return Err(format!(
            "a bare gateway answer has no body, saw {} byte(s): {:?}",
            transcript.body.len(),
            transcript.body_text()
        ));
    }
    Ok(())
}

/// Judge probe `tag`'s answer for a destination that must be floored. `resolution` is the host's
/// own answer for the spelling, taken independently of the gateway.
pub fn judge_floor_probe(
    out: &str,
    tag: &str,
    resolution: HostResolution,
) -> Result<FloorAnswer, String> {
    let transcript = Transcript::of(out, tag);
    if transcript.ending == Ending::ConnectFailed {
        return Err("the probe never reached the gateway".into());
    }
    if transcript.ending == Ending::Invalid {
        return Err("invalid transcript: duplicate or trailing records".into());
    }
    let visible = String::from_utf8_lossy(&transcript.bytes);
    for leak in ["ami-id", "instance-id", "iam/", "local-ipv4", RECORDER_BODY] {
        if visible.contains(leak) {
            return Err(format!("content {leak:?} reached the workload"));
        }
    }
    let Some(status) = transcript.status_line.as_deref() else {
        return Err(match transcript.ending {
            Ending::TimedOut => "no status line: the gateway neither answered nor closed".into(),
            Ending::Eof if transcript.bytes.is_empty() => {
                "no status line: the gateway closed without answering".into()
            }
            Ending::Eof => format!(
                "no well-formed status line in {:?}",
                String::from_utf8_lossy(&transcript.bytes)
            ),
            _ => "truncated transcript: no status line and no end was observed".into(),
        });
    };
    match status {
        "HTTP/1.1 403 forbidden" => {
            bare_gateway_answer(&transcript, "HTTP/1.1 403 forbidden").map_err(|why| {
                format!("a 403 that is not the gateway floor's bare answer: {why}")
            })?;
            Ok(FloorAnswer::GatewayFloor)
        }
        "HTTP/1.1 502 bad gateway" => {
            bare_gateway_answer(&transcript, "HTTP/1.1 502 bad gateway")
                .map_err(|why| format!("a 502 that is not the gateway's bare answer: {why}"))?;
            match resolution {
                HostResolution::Refuses => Ok(FloorAnswer::Unresolvable),
                HostResolution::Resolves => Err(
                    "502 for a spelling the host resolver reads: a transport or interceptor failure, not the resolver and not the floor".into(),
                ),
            }
        }
        line if line.starts_with("HTTP/1.1 403") => Err(format!(
            "a 403 that is not the gateway floor's status line: {line}"
        )),
        line if line.starts_with("HTTP/1.1 401") => Err(format!(
            "{line}: IMDSv2 itself answered; the request reached the instance"
        )),
        line if line.starts_with("HTTP/1.1 200") => Err(format!("{line}: the request succeeded")),
        line => Err(format!("unexpected status {line}")),
    }
}

/// The rule and reason a policy refusal body names: `[<rule>]: <reason>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalBody {
    pub rule: String,
    pub reason: String,
}

/// The default-deny case has two producers with two spellings, both fixed by Core:
/// `policy::RuleId::DEFAULT_DENY` is the journal's rule and `telemetry.rs::deny_reason` its reason;
/// `policy::decision::message` writes the body's bracketed rule and sentence.
pub const DEFAULT_DENY_JOURNAL_RULE: &str = "<default-deny>";
pub const DEFAULT_DENY_JOURNAL_REASON: &str = "no permit matched";
pub const DEFAULT_DENY_BODY_RULE: &str = "default-deny";
pub const DEFAULT_DENY_BODY_REASON: &str = "No permit policy matched this request.";

/// Whether `decision` and `body` are the two representations of one default-deny of `target`: the
/// journal's `net:connect` deny with rule `<default-deny>`, reason `no permit matched` and no
/// determining id, and the body's `[default-deny]: No permit policy matched this request.`. A
/// forbid, a named rule, a bracket-stripped journal rule or another target each fail by name.
pub fn default_deny_pair(
    decision: &crate::Decision,
    body: &RefusalBody,
    target: &str,
) -> Result<(), String> {
    if !decision.is_action("net:connect") {
        return Err(format!("the decision is not a net:connect: {decision:?}"));
    }
    if decision.resource != target {
        return Err(format!(
            "the decision names {:?}, not the refused target {target:?}",
            decision.resource
        ));
    }
    if !decision.denied() {
        return Err(format!("the decision is not a deny: {decision:?}"));
    }
    if decision.rule != DEFAULT_DENY_JOURNAL_RULE {
        return Err(format!(
            "the journal rule is {:?}, not the default-deny rule {DEFAULT_DENY_JOURNAL_RULE:?}",
            decision.rule
        ));
    }
    if decision.reason != DEFAULT_DENY_JOURNAL_REASON {
        return Err(format!(
            "the journal reason is {:?}, not {DEFAULT_DENY_JOURNAL_REASON:?}",
            decision.reason
        ));
    }
    if !decision.determining_ids.is_empty() {
        return Err(format!(
            "a default deny is determined by no policy, saw {:?}",
            decision.determining_ids
        ));
    }
    if body.rule != DEFAULT_DENY_BODY_RULE {
        return Err(format!(
            "the body rule is {:?}, not {DEFAULT_DENY_BODY_RULE:?}",
            body.rule
        ));
    }
    if body.reason != DEFAULT_DENY_BODY_REASON {
        return Err(format!(
            "the body reason is {:?}, not {DEFAULT_DENY_BODY_REASON:?}",
            body.reason
        ));
    }
    Ok(())
}

/// Whether `transcript` is exactly the gateway's refusal of a policy-denied destination, as
/// `write_interceptor_error` writes it for a `net:connect` or `http:request` the authority refused:
/// `HTTP/1.1 403 Forbidden`, the origin marker `x-strands-box-egress: refused`,
/// `Connection: close`, one `Content-Length` equal to the body, a body that names the refused
/// `target` and a rule id in brackets, a complete head, and EOF. This is not the floor: the floor
/// answers bare and never names a target (see [`bare_gateway_answer`]).
pub fn policy_refusal(transcript: &Transcript, target: &str) -> Result<RefusalBody, String> {
    match transcript.ending {
        Ending::Eof => {}
        Ending::ConnectFailed => return Err("the probe never reached the gateway".into()),
        Ending::WriteFailed => return Err("the request was not written whole".into()),
        Ending::TimedOut => {
            return Err("the gateway did not close the connection: timed out".into());
        }
        Ending::Reset => return Err("the connection was reset, not closed".into()),
        Ending::Error => {
            return Err(format!(
                "read error: {}",
                transcript.detail.as_deref().unwrap_or("unknown")
            ));
        }
        Ending::Truncated => return Err("the capture bound was reached".into()),
        Ending::Aborted => return Err("an aborted probe reads no answer".into()),
        Ending::Missing => return Err("truncated transcript: no end was observed".into()),
        Ending::Invalid => return Err("invalid transcript: duplicate or trailing records".into()),
    }
    if let Some(line) = &transcript.malformed {
        return Err(format!("malformed head line {line:?}"));
    }
    match transcript.status_line.as_deref() {
        Some("HTTP/1.1 403 Forbidden") => {}
        Some("HTTP/1.1 403 forbidden") => {
            return Err("the floor's bare 403, not a policy refusal".into());
        }
        Some(line) => return Err(format!("status line {line:?}, expected a 403 Forbidden")),
        None => return Err("no well-formed status line".into()),
    }
    if !transcript.head_complete {
        return Err("the head never ended: no blank line".into());
    }
    let mut names: Vec<&str> = transcript.headers.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    if names != ["connection", "content-length", GATEWAY_ORIGIN_HEADER] {
        return Err(format!(
            "a policy refusal carries exactly {GATEWAY_ORIGIN_HEADER}, Connection and Content-Length once each, saw {:?}",
            transcript.headers
        ));
    }
    if transcript.header(GATEWAY_ORIGIN_HEADER) != Some("refused") {
        return Err(format!(
            "the origin marker reads {:?}, expected \"refused\"",
            transcript.header(GATEWAY_ORIGIN_HEADER)
        ));
    }
    if !transcript
        .header("connection")
        .is_some_and(|v| v.eq_ignore_ascii_case("close"))
    {
        return Err("a policy refusal declares Connection: close".into());
    }
    let declared: Option<usize> = transcript
        .header("content-length")
        .and_then(|v| v.parse().ok());
    if declared != Some(transcript.body.len()) {
        return Err(format!(
            "Content-Length {:?} does not frame the {}-byte body",
            transcript.header("content-length"),
            transcript.body.len()
        ));
    }
    let body = transcript.body_text();
    let expected = format!("policy denied this operation on '{target}' [");
    let Some(rest) = body.strip_prefix(&expected) else {
        return Err(format!(
            "the body does not name the refused target {target:?}: {body:?}"
        ));
    };
    // `[<rule>]: <reason>`: a closing bracket, then the separator, then a non-empty reason.
    let Some((rule, after)) = rest.split_once("]: ") else {
        return Err(format!(
            "the body has no closed rule bracket followed by \": \": {body:?}"
        ));
    };
    if rule.is_empty() || rule.contains('[') || rule.contains(']') || rule.contains('\n') {
        return Err(format!(
            "the body names no single rule id in brackets: {body:?}"
        ));
    }
    if after.trim().is_empty() {
        return Err(format!("the body gives no reason after the rule: {body:?}"));
    }
    Ok(RefusalBody {
        rule: rule.to_string(),
        reason: after.to_string(),
    })
}

/// Judge probe `tag`'s answer for a destination the authority must refuse: the gateway's policy
/// refusal naming `target`. Returns the rule and reason the body names.
pub fn judge_policy_refusal(out: &str, tag: &str, target: &str) -> Result<RefusalBody, String> {
    let transcript = Transcript::of(out, tag);
    let visible = String::from_utf8_lossy(&transcript.bytes);
    if visible.contains(RECORDER_BODY) {
        return Err(format!(
            "the recorder's body reached the workload: {visible:?}"
        ));
    }
    policy_refusal(&transcript, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    const BARE_403: &[u8] =
        b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const BARE_502: &[u8] =
        b"HTTP/1.1 502 bad gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    /// The probe, compiled once from `PROBE_SOURCE` with the host `rustc`.
    fn probe_binary() -> &'static std::path::Path {
        static PROBE: OnceLock<std::path::PathBuf> = OnceLock::new();
        PROBE.get_or_init(|| {
            // A unique, private temporary directory. The guard is leaked on purpose so the binary
            // outlives every test in the process; the directory is then the OS temp policy's to
            // remove, and its name is not predictable.
            let dir = Box::leak(Box::new(
                tempfile::Builder::new()
                    .prefix("det-egress-probe-")
                    .tempdir()
                    .unwrap(),
            ));
            let source = dir.path().join("egress-probe.rs");
            let binary = dir.path().join("egress-probe");
            std::fs::write(&source, PROBE_SOURCE).unwrap();
            let compiled = std::process::Command::new("rustc")
                .args(["--edition", "2021", "-O", "-o"])
                .arg(&binary)
                .arg(&source)
                .output()
                .expect("rustc is on PATH");
            assert!(
                compiled.status.success(),
                "rustc failed on the probe: {}",
                String::from_utf8_lossy(&compiled.stderr)
            );
            binary
        })
    }

    /// A one-shot host server: accept one connection, read the request head, write `reply`, then
    /// either close or hold the socket open for `hold`.
    fn one_shot_server(reply: &'static [u8], hold: Option<Duration>) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            let _ = read_head_and_body(
                &mut tcp,
                MAX_HEAD_BYTES,
                MAX_BODY_BYTES,
                Instant::now() + Duration::from_secs(5),
            );
            let _ = tcp.write_all(reply);
            let _ = tcp.flush();
            if let Some(hold) = hold {
                std::thread::sleep(hold);
            }
        });
        port
    }

    /// Run the compiled probe through the host bash, as the case does, against `port`.
    fn probe_against(port: u16, timeout: u64, mode: ProbeMode) -> String {
        let command = probe_command(
            probe_binary(),
            "T",
            &absolute_request("GET", "example.test", "/"),
            timeout,
            mode,
        );
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("HTTP_PROXY=http://127.0.0.1:{port}\n{command}\n"))
            .output()
            .expect("bash is on PATH");
        assert!(
            output.status.success(),
            "probe exited {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// A transcript string for `tag` carrying `bytes` and `end`.
    fn records(tag: &str, bytes: &[u8], end: &str) -> String {
        format!(
            "{PROBE_RECORD} {tag} DATA {}\n{PROBE_RECORD} {tag} END {end}\n",
            hex(bytes)
        )
    }

    /// The bare floor answer through the real probe and bash is judged the floor.
    #[test]
    fn a_bare_floor_answer_through_the_probe_is_judged_the_floor() {
        let out = probe_against(one_shot_server(BARE_403, None), 15, ProbeMode::Read);
        assert_eq!(
            judge_floor_probe(&out, "T", HostResolution::Resolves),
            Ok(FloorAnswer::GatewayFloor),
            "{out}"
        );
        assert!(probe_reached_gateway(&out, "T"));
        assert_eq!(status_code(&out, "T"), Some(403));
    }

    /// Reproductions, socket level: a body spelled like a control marker, a NUL body, a
    /// CR-only tail, an unterminated body and a body spelled like this probe's own end record are
    /// captured byte for byte and none is the floor.
    #[test]
    fn bodies_that_confused_the_text_reader_are_captured_exactly_and_refused() {
        let cases: &[(&'static [u8], &'static [u8], &str)] = &[
            (
                b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\nDET_PROXY_CLOSED\r\n",
                b"DET_PROXY_CLOSED\r\n",
                "no body",
            ),
            (
                b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n\x00",
                b"\x00",
                "no body",
            ),
            (
                b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n\r",
                b"\r",
                "no body",
            ),
            (
                b"HTTP/1.1 403 forbidden\r\nContent-Length: 9\r\n\r\nSECRET123",
                b"SECRET123",
                "exactly Content-Length and Connection",
            ),
            (
                b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\nDET_PROBE T END EOF\n",
                b"DET_PROBE T END EOF\n",
                "no body",
            ),
        ];
        for (reply, body, reason) in cases {
            let out = probe_against(one_shot_server(reply, None), 15, ProbeMode::Read);
            let transcript = Transcript::of(&out, "T");
            assert_eq!(transcript.bytes, reply.to_vec(), "{out}");
            assert_eq!(transcript.body, body.to_vec(), "{out}");
            assert_eq!(transcript.ending, Ending::Eof, "{out}");
            let err = judge_floor_probe(&out, "T", HostResolution::Resolves).expect_err(reason);
            assert!(err.contains(reason), "{reason}: {err}\n{out}");
        }
    }

    /// A server that answers and then holds the socket is a timeout within the deadline, never EOF.
    #[test]
    fn a_held_connection_is_a_timeout_within_the_deadline_not_an_eof() {
        // The probe binary is compiled once per test process; warm it before the timer starts so
        // the bound below measures the probe's deadline and not `rustc`.
        let _ = probe_binary();
        let started = Instant::now();
        let out = probe_against(
            one_shot_server(BARE_403, Some(Duration::from_secs(4))),
            1,
            ProbeMode::Read,
        );
        assert!(
            started.elapsed() < Duration::from_millis(2500),
            "{:?}",
            started.elapsed()
        );
        let transcript = Transcript::of(&out, "T");
        assert_eq!(transcript.ending, Ending::TimedOut, "{out}");
        assert_eq!(transcript.bytes, BARE_403.to_vec());
        assert!(!probe_reached_gateway(&out, "T"));
        let err = judge_floor_probe(&out, "T", HostResolution::Resolves).expect_err("timed out");
        assert!(err.contains("timed out"), "{err}");
    }

    /// Abort mode writes and closes without reading; a connect failure is its own record.
    #[test]
    fn abort_mode_and_connect_failure_are_distinct_records() {
        let out = probe_against(one_shot_server(BARE_403, None), 15, ProbeMode::Abort);
        assert_eq!(Transcript::of(&out, "T").ending, Ending::Aborted, "{out}");
        assert!(!probe_reached_gateway(&out, "T"));
        let port = {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            listener.local_addr().unwrap().port()
        };
        let out = probe_against(port, 2, ProbeMode::Read);
        assert_eq!(
            Transcript::of(&out, "T").ending,
            Ending::ConnectFailed,
            "{out}"
        );
        let err = judge_floor_probe(&out, "T", HostResolution::Resolves).expect_err("no connect");
        assert!(err.contains("never reached"), "{err}");
    }

    /// The judge requires the exact bare shape and a trustworthy transcript.
    #[test]
    fn the_floor_judge_requires_the_exact_bare_shape_and_a_trustworthy_transcript() {
        assert_eq!(
            judge_floor_probe(
                &records("t", BARE_403, "EOF"),
                "t",
                HostResolution::Resolves
            ),
            Ok(FloorAnswer::GatewayFloor)
        );
        assert_eq!(
            judge_floor_probe(
                &records(
                    "t",
                    b"HTTP/1.1 403 forbidden\r\nconnection: close\r\ncontent-length: 0\r\n\r\n",
                    "EOF"
                ),
                "t",
                HostResolution::Resolves
            ),
            Ok(FloorAnswer::GatewayFloor),
            "header order and name case do not matter"
        );
        let cases: &[(&[u8], &str, &str)] = &[
            // The parent's original two reproductions.
            (b"HTTP/1.1 403 forbidden\r\nContent-Length: 5\r\n\r\nhello", "EOF", "exactly Content-Length and Connection"),
            (b"HTTP/1.1 403 forbidden\r\n", "EOF", "head never ended"),
            // The parent's second-round reproductions.
            (b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nContent-Length: 9\r\nConnection: close\r\n\r\n", "EOF", "exactly Content-Length and Connection"),
            (b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nConnection: close\r\nthis is not a header\r\n\r\n", "EOF", "malformed head line"),
            (b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\nDET_PROXY_CLOSED\r\n", "EOF", "no body"),
            (b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n\x00", "EOF", "no body"),
            // Other shapes.
            (b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\n\r\n", "EOF", "exactly Content-Length and Connection"),
            (b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nConnection: close\r\nx-strands-box-egress: refused\r\n\r\n", "EOF", "exactly Content-Length and Connection"),
            (b"HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\nx-strands-box-egress: refused\r\n\r\nblocked by egress control", "EOF", "not the gateway floor's status line"),
            (b"HTTP/1.1 403 forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", "EOF", "no body"),
            (BARE_403, "TIMEOUT", "timed out"),
            (BARE_403, "TRUNCATED", "capture bound"),
            (BARE_403, "ERROR connection reset", "read error"),
            (BARE_403, "ABORTED", "aborted probe"),
            (b"HTTP/1.1 403\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "EOF", "no well-formed status line"),
            (b"HTTP/1.1 403 forbidden\nContent-Length: 0\nConnection: close\n\n", "EOF", "no well-formed status line"),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nami-id", "EOF", "ami-id"),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "EOF", "succeeded"),
            (b"HTTP/1.1 401 Unauthorized\r\n\r\n", "EOF", "IMDSv2"),
            (b"", "EOF", "closed without answering"),
            (b"", "TIMEOUT", "neither answered nor closed"),
        ];
        for (bytes, end, reason) in cases {
            let out = records("t", bytes, end);
            let err = judge_floor_probe(&out, "t", HostResolution::Resolves).expect_err(&out);
            assert!(err.contains(reason), "{out:?} -> {err}");
        }
        // Untrustworthy transcripts: two ends, a record after the end, a foreign tag only, no end,
        // the old text marker.
        for (out, reason) in [
            (
                format!(
                    "{}{PROBE_RECORD} t END EOF\n",
                    records("t", BARE_403, "EOF")
                ),
                "invalid transcript",
            ),
            (
                format!(
                    "{}{PROBE_RECORD} t DATA 00\n",
                    records("t", BARE_403, "EOF")
                ),
                "invalid transcript",
            ),
            (records("u", BARE_403, "EOF"), "truncated transcript"),
            (
                format!("{PROBE_RECORD} t DATA {}\n", hex(BARE_403)),
                "truncated transcript",
            ),
            (
                "PROXY_CONNECT_FAILED t\n".to_string(),
                "truncated transcript",
            ),
            (
                format!("{PROBE_RECORD} t CONNECT_FAILED refused\n"),
                "never reached",
            ),
        ] {
            let err = judge_floor_probe(&out, "t", HostResolution::Resolves).expect_err(&out);
            assert!(err.contains(reason), "{out:?} -> {err}");
        }
        assert_eq!(
            status_code(
                &format!(
                    "{}{PROBE_RECORD} t END EOF\n",
                    records("t", BARE_403, "EOF")
                ),
                "t"
            ),
            None,
            "an invalid transcript has no status"
        );
    }

    /// A 502 is the resolver's refusal only in the bare shape and only when the host resolver
    /// refuses the same spelling.
    #[test]
    fn a_502_needs_the_bare_shape_and_the_host_resolvers_refusal() {
        let bare = records("t", BARE_502, "EOF");
        assert_eq!(
            judge_floor_probe(&bare, "t", HostResolution::Refuses),
            Ok(FloorAnswer::Unresolvable)
        );
        let err = judge_floor_probe(&bare, "t", HostResolution::Resolves).expect_err("resolvable");
        assert!(err.contains("transport or interceptor failure"), "{err}");
        let bodied = records(
            "t",
            b"HTTP/1.1 502 bad gateway\r\nContent-Length: 3\r\n\r\nerr",
            "EOF",
        );
        let err = judge_floor_probe(&bodied, "t", HostResolution::Refuses).expect_err("bodied");
        assert!(err.contains("not the gateway's bare answer"), "{err}");
        assert_eq!(HostResolution::of("127.0.0.1"), HostResolution::Resolves);
        assert_eq!(
            HostResolution::of("no-such-host.det-egress.invalid"),
            HostResolution::Refuses
        );
    }

    #[test]
    fn a_recorder_answer_is_recognized_only_whole_and_only_on_eof() {
        let body = format!("{RECORDER_BODY}\n");
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        assert!(probe_reached_recorder(
            &records("t", reply.as_bytes(), "EOF"),
            "t"
        ));
        assert!(!probe_reached_recorder(
            &records("t", reply.as_bytes(), "TIMEOUT"),
            "t"
        ));
        let extra = format!("{reply}x");
        assert!(!probe_reached_recorder(
            &records("t", extra.as_bytes(), "EOF"),
            "t"
        ));
        assert!(!probe_reached_recorder(
            &records("t", b"HTTP/1.1 403 forbidden\r\n\r\n", "EOF"),
            "t"
        ));
        assert_eq!(
            String::from_utf8(absolute_request("GET", "127.0.0.1:8", "/p")).unwrap(),
            "GET http://127.0.0.1:8/p HTTP/1.1\r\nHost: 127.0.0.1:8\r\nConnection: close\r\n\r\n"
        );
        assert!(
            probe_command(
                std::path::Path::new("/x/p"),
                "T",
                b"AB",
                7,
                ProbeMode::Abort
            )
            .ends_with("T \"${HTTP_PROXY##*:}\" 4142 7 abort")
        );
    }

    #[test]
    fn the_recorder_counts_and_records_a_direct_request_and_nothing_else() {
        let recorder = HostRecorder::start();
        recorder.self_test();
        assert_eq!(recorder.connections(), 0);
        assert_eq!(recorder.bytes(), 0);
        let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        tcp.write_all(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc")
            .unwrap();
        let reply = read_head_and_body(
            &mut tcp,
            MAX_HEAD_BYTES,
            MAX_BODY_BYTES,
            Instant::now() + Duration::from_secs(5),
        );
        assert!(reply.complete && reply.raw.contains(RECORDER_BODY));
        let snapshot = recorder.snapshot();
        assert_eq!(
            snapshot.request_lines(),
            vec!["POST /x HTTP/1.1".to_string()]
        );
        assert!(snapshot.requests()[0].ends_with("abc"));
        assert!(snapshot.incomplete().is_empty());
        assert!(snapshot.accept_errors.is_empty());
    }

    /// A connection that stops short is an incomplete observation with a named error, counted as
    /// a connection and never as a delivered request or a silent zero.
    #[test]
    fn a_truncated_or_bare_connection_is_recorded_as_incomplete_with_its_reason() {
        let recorder = HostRecorder::start();
        recorder.self_test();
        let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        tcp.write_all(b"POST /short HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\npartial")
            .unwrap();
        drop(tcp);
        let tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        drop(tcp);
        let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        tcp.write_all(b"garbage\r\n\r\n").unwrap();
        drop(tcp);
        let snapshot = recorder.snapshot();
        let incomplete = snapshot.incomplete();
        assert_eq!(snapshot.observations.len(), 3, "{snapshot:?}");
        assert_eq!(incomplete.len(), 3, "{incomplete:?}");
        assert!(snapshot.request_lines().is_empty(), "no complete request");
        let short = incomplete
            .iter()
            .find(|o| o.request_line.as_deref() == Some("POST /short HTTP/1.1"))
            .expect("the truncated request is observed with its request line");
        assert!(!short.complete);
        assert!(short.raw.ends_with("partial"), "{}", short.raw);
        assert!(
            short
                .error
                .as_deref()
                .is_some_and(|e| e.contains("closed after 7 of 100 body bytes")),
            "{:?}",
            short.error
        );
        assert!(incomplete.iter().any(|o| {
            o.raw.is_empty()
                && o.error
                    .as_deref()
                    .is_some_and(|e| e.contains("closed before the end of the head"))
        }));
        assert!(
            incomplete
                .iter()
                .any(|o| o.error.as_deref() == Some("no request line"))
        );
    }

    /// Oversized declarations stop the read at the bound and are named.
    #[test]
    fn oversized_heads_and_bodies_are_bounded_and_named() {
        let recorder = HostRecorder::start();
        recorder.self_test();
        let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        tcp.write_all(b"POST /big HTTP/1.1\r\nHost: h\r\nContent-Length: 2000000\r\n\r\n")
            .unwrap();
        drop(tcp);
        let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        let long_head = format!(
            "GET /long HTTP/1.1\r\nX: {}\r\n\r\n",
            "y".repeat(MAX_HEAD_BYTES)
        );
        let _ = tcp.write_all(long_head.as_bytes());
        drop(tcp);
        let incomplete = recorder.incomplete();
        assert_eq!(incomplete.len(), 2, "{incomplete:?}");
        assert!(incomplete.iter().any(|o| {
            o.error
                .as_deref()
                .is_some_and(|e| e.contains("declared body 2000000 exceeds"))
        }));
        assert!(incomplete.iter().any(|o| {
            o.error
                .as_deref()
                .is_some_and(|e| e.contains("head exceeds"))
        }));
        assert!(recorder.request_lines().is_empty());
    }

    /// Reproduction: a peer that dribbles one byte at a time cannot hold a handler past the
    /// connection deadline, and `stop` shuts it down at once rather than waiting on its pace.
    #[test]
    fn a_dribbling_peer_meets_the_connection_deadline_and_stop_cuts_it_off() {
        // Deadline: a 600 ms total deadline against a peer that would dribble for 3 s.
        let recorder = HostRecorder::start_with_deadline(Duration::from_millis(600));
        recorder.self_test();
        let mut peer = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        peer.write_all(b"G").unwrap();
        let dribbler = std::thread::spawn(move || {
            for _ in 0..30 {
                std::thread::sleep(Duration::from_millis(100));
                if peer.write_all(b"x").is_err() {
                    break;
                }
            }
        });
        let started = Instant::now();
        let snapshot = recorder.snapshot();
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "the snapshot waited on the deadline, not the peer: {:?}",
            started.elapsed()
        );
        assert_eq!(snapshot.observations.len(), 1, "{snapshot:?}");
        let slow = &snapshot.observations[0];
        assert!(!slow.complete);
        assert!(
            slow.error
                .as_deref()
                .is_some_and(|e| e.contains("deadline exceeded")),
            "{:?}",
            slow.error
        );
        assert!(slow.raw.starts_with("Gx"), "{}", slow.raw);
        drop(recorder);
        let _ = dribbler.join();

        // Stop: the parent's shape — one byte, then a byte every 500 ms — with the default 5 s
        // deadline; stop must not wait for the deadline or the peer.
        let mut recorder = HostRecorder::start();
        let mut peer = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        peer.write_all(b"G").unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let dribbler = std::thread::spawn(move || {
            for _ in 0..15 {
                std::thread::sleep(Duration::from_millis(500));
                if peer.write_all(b"x").is_err() {
                    break;
                }
            }
        });
        let started = Instant::now();
        recorder.stop();
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "stop cut the reader off: {:?}",
            started.elapsed()
        );
        assert!(recorder.accept_thread.is_none());
        assert!(recorder.handlers.lock().unwrap().is_empty());
        let observations = recorder.shared.observations.lock().unwrap().clone();
        assert_eq!(observations.len(), 1, "{observations:?}");
        assert!(!observations[0].complete);
        let _ = dribbler.join();
    }

    /// Stopping joins the listener and its handlers; the port is released; a snapshot after stop
    /// is the final one and needs no acknowledgement.
    #[test]
    fn stop_joins_the_listener_and_releases_the_port() {
        let mut recorder = HostRecorder::start();
        recorder.self_test();
        let port = recorder.port();
        recorder.stop();
        assert!(recorder.accept_thread.is_none());
        assert!(recorder.handlers.lock().unwrap().is_empty());
        assert!(
            TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_millis(500)
            )
            .is_err(),
            "the recorder's port must be closed after stop"
        );
        let snapshot = recorder.snapshot();
        assert!(snapshot.observations.is_empty() && snapshot.accept_errors.is_empty());
    }

    /// The drain barrier: a connection completed before the snapshot is asked for is in it, with
    /// no scheduling grace involved.
    #[test]
    fn a_snapshot_includes_every_connection_completed_before_it_was_asked() {
        let recorder = HostRecorder::start();
        recorder.self_test();
        for i in 0..20 {
            let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
            tcp.write_all(format!("GET /n{i} HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes())
                .unwrap();
            let reply = read_head_and_body(
                &mut tcp,
                MAX_HEAD_BYTES,
                MAX_BODY_BYTES,
                Instant::now() + Duration::from_secs(5),
            );
            assert!(reply.complete, "{reply:?}");
            let snapshot = recorder.snapshot();
            assert_eq!(snapshot.observations.len(), i + 1, "{snapshot:?}");
            assert!(snapshot.accept_errors.is_empty());
        }
    }

    /// Reproduction: a request that arrives after a sweep ended empty
    /// but before the acknowledgement. The test inserts a 250 ms pause exactly there, connects and
    /// sends a whole request during the pause, then asks for a snapshot. The ticket was taken
    /// before the sweep, so the snapshot waits for the next sweep and observes the request; it
    /// can never observe zero.
    #[test]
    fn a_request_queued_after_an_empty_sweep_is_in_the_snapshot_that_asked_for_it() {
        let after_sweep = Arc::new(AtomicBool::new(false));
        let flag = after_sweep.clone();
        let recorder = HostRecorder::start_with(
            DEFAULT_CONNECTION_DEADLINE,
            Some(Arc::new(move || {
                flag.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(250));
            })),
        );
        for round in 0..3 {
            after_sweep.store(false, Ordering::SeqCst);
            while !after_sweep.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            let mut peer = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
            peer.write_all(b"GET /queued HTTP/1.1\r\nHost: test\r\n\r\n")
                .unwrap();
            drop(peer);
            let snapshot = recorder.snapshot();
            assert_eq!(
                snapshot.observations.len(),
                round + 1,
                "round {round}: the request queued during the pause is in the snapshot that asked for it: {snapshot:?}"
            );
            assert_eq!(
                snapshot.request_lines().last().map(String::as_str),
                Some("GET /queued HTTP/1.1")
            );
        }
    }

    /// A stream accepted while `stop` is under way is still shut down: the accept loop is joined
    /// before the shutdown set is taken. The `before_accept` hook parks the loop between its stop
    /// check and its `accept`; the peer connects while it is parked, `stop` sets its flag, and only
    /// then does the loop accept and register the stream. The stream is therefore in the active set
    /// when `stop` takes it, and its handler is live, so nothing but the shutdown can end it inside
    /// the bounds: the handler's own deadline is 5 s, the stop bound 1.5 s, the peer's read 500 ms.
    #[test]
    fn a_stream_accepted_during_stop_is_shut_down_and_stop_stays_bounded() {
        let gate = Arc::new(AcceptGate::default());
        let hook_gate = gate.clone();
        let mut recorder = HostRecorder::start_with_hooks(
            DEFAULT_CONNECTION_DEADLINE,
            None,
            Some(Arc::new(move |stop: &AtomicBool| hook_gate.park(stop))),
        );
        // Positive control: with the gate closed the recorder accepts and answers as usual.
        recorder.self_test();

        // Arm the gate, then wait for the loop to park at the accept.
        gate.armed.store(true, Ordering::SeqCst);
        wait_until(&gate.parked, "the accept loop parks before its accept");
        assert_eq!(recorder.shared.in_flight.load(Ordering::SeqCst), 0);
        assert!(recorder.shared.active.lock().unwrap().is_empty());
        assert!(recorder.shared.observations.lock().unwrap().is_empty());

        // Queued while parked: a peer that sends one byte and then holds the connection. Its
        // bounded read is armed now, before the recorder can reset it: a kernel may refuse the
        // option on a reset socket (macOS answers EINVAL), and the bound must exist before `stop`.
        let mut peer = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        peer.set_read_timeout(Some(PEER_OBSERVATION))
            .expect("arm the peer's bounded read before stop");
        peer.write_all(b"G").unwrap();
        assert!(
            !gate.released.load(Ordering::SeqCst),
            "the loop is still parked: the peer is queued, not accepted"
        );

        let started = Instant::now();
        recorder.stop();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(1500),
            "stop is bounded by the shutdown, not by the 5 s deadline: {elapsed:?}"
        );

        // The accept happened during stop: the hook saw the flag before it let the accept run.
        assert!(
            gate.saw_stop.load(Ordering::SeqCst),
            "the hook released on the stop flag, not on its bound: {gate:?}"
        );
        assert!(gate.released.load(Ordering::SeqCst));
        // The stream was accepted, registered and read by a live handler: its observation exists,
        // carries the one byte the peer sent, and ended short without a request line.
        let observations = recorder.shared.observations.lock().unwrap().clone();
        assert_eq!(observations.len(), 1, "{observations:?}");
        assert_eq!(observations[0].raw, "G", "{observations:?}");
        assert!(!observations[0].complete);
        assert!(observations[0].request_line.is_none());
        assert!(
            recorder.shared.accept_errors.lock().unwrap().is_empty(),
            "{:?}",
            recorder.shared.accept_errors.lock().unwrap()
        );
        // Stop shut the stream down and joined its handler: nothing is active or in flight.
        assert!(recorder.handlers.lock().unwrap().is_empty());
        assert!(recorder.shared.active.lock().unwrap().is_empty());
        assert_eq!(recorder.shared.in_flight.load(Ordering::SeqCst), 0);
        // The handler ended by the shutdown, not by its deadline: the stop bound above already
        // excludes the 5 s deadline, and the read error is not the deadline firing.
        let error = observations[0].error.clone().unwrap_or_default();
        assert!(
            !error.contains("deadline"),
            "the handler's read ended by shutdown, not by its deadline: {error}"
        );
        // The peer sees its connection closed: EOF or a closure error, observed within the bound
        // armed above. A timeout would mean the socket is still open, and fails.
        assert_eq!(
            peer_closure(&mut peer),
            Ok(()),
            "the accepted stream was shut down by stop"
        );
    }

    /// The accept-loop gate behind the stop/accept test. Once `armed`, the first `park` marks
    /// `parked`, waits (bounded) for the stop flag, records whether it saw it, marks `released` and
    /// returns; every later call returns at once. A failed assertion cannot leave the loop parked:
    /// the wait ends on the flag, which `stop` (and so `Drop`) always sets, or on its bound.
    #[derive(Debug, Default)]
    struct AcceptGate {
        armed: AtomicBool,
        parked: AtomicBool,
        saw_stop: AtomicBool,
        released: AtomicBool,
    }

    impl AcceptGate {
        fn park(&self, stop: &AtomicBool) {
            if !self.armed.load(Ordering::SeqCst) || self.parked.load(Ordering::SeqCst) {
                return;
            }
            self.parked.store(true, Ordering::SeqCst);
            let deadline = Instant::now() + GATE_BOUND;
            while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            self.saw_stop
                .store(stop.load(Ordering::SeqCst), Ordering::SeqCst);
            self.released.store(true, Ordering::SeqCst);
        }
    }

    /// How long the gate and the test wait for each other before failing by name.
    const GATE_BOUND: Duration = Duration::from_secs(2);

    fn wait_until(flag: &AtomicBool, what: &str) {
        let deadline = Instant::now() + GATE_BOUND;
        while !flag.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "DET_ERROR: {what} within {GATE_BOUND:?}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// The gate itself: it is inert until armed, parks once, releases on the stop flag and records
    /// it, and releases on its bound (recording no stop) rather than blocking a loop forever.
    #[test]
    fn the_accept_gate_parks_once_and_never_blocks_past_its_bound() {
        let gate = AcceptGate::default();
        let stop = AtomicBool::new(false);
        let started = Instant::now();
        gate.park(&stop);
        assert!(!gate.parked.load(Ordering::SeqCst), "inert until armed");
        assert!(started.elapsed() < Duration::from_millis(100));

        gate.armed.store(true, Ordering::SeqCst);
        stop.store(true, Ordering::SeqCst);
        gate.park(&stop);
        assert!(gate.parked.load(Ordering::SeqCst));
        assert!(gate.saw_stop.load(Ordering::SeqCst));
        assert!(gate.released.load(Ordering::SeqCst));
        let again = Instant::now();
        gate.park(&stop);
        assert!(again.elapsed() < Duration::from_millis(100), "parks once");

        let unstopped = AcceptGate::default();
        unstopped.armed.store(true, Ordering::SeqCst);
        let never = AtomicBool::new(false);
        let started = Instant::now();
        unstopped.park(&never);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= GATE_BOUND && elapsed < GATE_BOUND + Duration::from_millis(500),
            "released by the bound: {elapsed:?}"
        );
        assert!(!unstopped.saw_stop.load(Ordering::SeqCst));
        assert!(unstopped.released.load(Ordering::SeqCst));
    }

    /// How long a peer waits to observe its connection's fate.
    const PEER_OBSERVATION: Duration = Duration::from_millis(500);

    /// Whether one bounded read on `peer` shows the connection closed by the other side: `Ok(0)`
    /// (EOF) or a connection-closure error. A `WouldBlock`/`TimedOut` is an open connection, and
    /// any other error is unrelated; both are reported, never read as a closure. The read timeout
    /// must already be armed: this function sets no option, so a kernel that refuses options on a
    /// reset socket cannot leave the read unbounded.
    fn peer_closure(peer: &mut TcpStream) -> Result<(), String> {
        assert!(
            peer.read_timeout()
                .expect("read the peer's read timeout")
                .is_some(),
            "peer_closure needs a read timeout armed before the observation"
        );
        let mut byte = [0u8; 1];
        classify_closure(&peer.read(&mut byte))
    }

    /// The closure classifier behind [`peer_closure`], on a read result.
    fn classify_closure(read: &std::io::Result<usize>) -> Result<(), String> {
        match read {
            Ok(0) => Ok(()),
            Ok(n) => Err(format!(
                "the peer read {n} byte(s): the connection is open and answering"
            )),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                Ok(())
            }
            Err(error) if is_timeout(error) => Err(format!(
                "the read timed out ({error}): the connection is still open"
            )),
            Err(error) => Err(format!("an unrelated I/O error is not a closure: {error}")),
        }
    }

    /// The closure oracle itself: a holding peer cannot pass it, a closed one does, and a timeout
    /// or an unrelated error is named. The holding control is a live listener that accepts and
    /// keeps the connection open for longer than the observation bound.
    #[test]
    fn the_peer_closure_oracle_rejects_a_holding_peer_and_unrelated_errors() {
        // Pure classification.
        assert_eq!(classify_closure(&Ok(0)), Ok(()));
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::NotConnected,
            std::io::ErrorKind::BrokenPipe,
        ] {
            assert_eq!(
                classify_closure(&Err(std::io::Error::from(kind))),
                Ok(()),
                "{kind:?}"
            );
        }
        for kind in [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::TimedOut] {
            let err = classify_closure(&Err(std::io::Error::from(kind))).expect_err("open");
            assert!(err.contains("still open"), "{kind:?}: {err}");
        }
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::Other,
        ] {
            let err = classify_closure(&Err(std::io::Error::from(kind))).expect_err("unrelated");
            assert!(err.contains("unrelated"), "{kind:?}: {err}");
        }
        let err = classify_closure(&Ok(1)).expect_err("data");
        assert!(err.contains("open and answering"), "{err}");

        // Negative control on a socket: a peer of a listener that holds the connection open must
        // not pass, and the observation ends at its bound.
        let holder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = holder.local_addr().unwrap().port();
        let hold = std::thread::spawn(move || {
            let (stream, _) = holder.accept().unwrap();
            std::thread::sleep(Duration::from_secs(3));
            drop(stream);
        });
        let mut peer = TcpStream::connect(("127.0.0.1", port)).unwrap();
        peer.set_read_timeout(Some(PEER_OBSERVATION)).unwrap();
        let started = Instant::now();
        let verdict = peer_closure(&mut peer);
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "the observation is bounded: {:?}",
            started.elapsed()
        );
        let err = verdict.expect_err("a holding peer is not a closure");
        assert!(err.contains("still open"), "{err}");
        drop(peer);
        let _ = hold.join();

        // Positive control on a socket: a listener that accepts and closes at once.
        let closer = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = closer.local_addr().unwrap().port();
        let close = std::thread::spawn(move || {
            let (stream, _) = closer.accept().unwrap();
            drop(stream);
        });
        let mut peer = TcpStream::connect(("127.0.0.1", port)).unwrap();
        peer.set_read_timeout(Some(PEER_OBSERVATION)).unwrap();
        assert_eq!(peer_closure(&mut peer), Ok(()));
        let _ = close.join();
    }

    /// The probe's write phase is bounded by the total deadline: a peer that never reads lets the
    /// write block only until the deadline, then a `WRITE_FAILED` record ends the transcript.
    #[test]
    fn the_probe_bounds_its_write_phase_by_the_deadline() {
        // A listener that accepts and never reads; a request larger than any socket buffer will
        // block the probe's write until the deadline.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(6));
            drop(tcp);
        });
        // 16 MiB exceeds every loopback socket buffer; it travels by a unique temporary file that
        // is removed when the test ends, since one argument cannot carry it.
        let mut request_file = tempfile::Builder::new()
            .prefix("det-egress-big-")
            .tempfile()
            .unwrap();
        request_file
            .write_all(&vec![b'x'; 16 * 1024 * 1024])
            .unwrap();
        request_file.flush().unwrap();
        let command = format!(
            "'{}' T \"${{HTTP_PROXY##*:}}\" @{} 1",
            probe_binary().display(),
            request_file.path().display()
        );
        let started = Instant::now();
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("HTTP_PROXY=http://127.0.0.1:{port}\n{command}\n"))
            .output()
            .expect("bash is on PATH");
        assert!(
            started.elapsed() < Duration::from_millis(1800),
            "the write ended at its 1 s deadline, not at a retried timeout: {:?}",
            started.elapsed()
        );
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        let transcript = Transcript::of(&out, "T");
        assert_eq!(transcript.ending, Ending::WriteFailed, "{out}");
        assert!(
            transcript.detail.as_deref().is_some_and(|d| {
                d.starts_with("deadline exceeded after ") && d.ends_with(" of 16777216 bytes")
            }),
            "the failure names the deadline and the bytes written: {:?}",
            transcript.detail
        );
        let err = judge_floor_probe(&out, "T", HostResolution::Resolves).expect_err("write failed");
        assert!(
            err.contains("not written whole") || err.contains("truncated transcript"),
            "{err}"
        );
    }

    /// The exact bytes the native run recorded for a policy-denied destination (Linux, box
    /// e458ed41): the gateway's refusal is `403 Forbidden` with the origin marker and a body that
    /// names the target and the rule. It is a policy refusal, not the floor, and both judges say so.
    #[test]
    fn the_native_policy_refusal_bytes_are_a_policy_refusal_and_not_the_floor() {
        let hex_bytes = "485454502f312e312034303320466f7262696464656e0d0a782d737472616e64732d626f782d6567726573733a20726566757365640d0a436f6e6e656374696f6e3a20636c6f73650d0a436f6e74656e742d4c656e6774683a203130340d0a0d0a706f6c6963792064656e6965642074686973206f7065726174696f6e206f6e20273132372e302e302e313a333734363927205b64656661756c742d64656e795d3a204e6f207065726d697420706f6c696379206d617463686564207468697320726571756573742e";
        let out = format!("{PROBE_RECORD} t DATA {hex_bytes}\n{PROBE_RECORD} t END EOF\n");
        assert_eq!(
            judge_policy_refusal(&out, "t", "127.0.0.1:37469"),
            Ok(RefusalBody {
                rule: "default-deny".to_string(),
                reason: "No permit policy matched this request.".to_string(),
            })
        );
        // The pair with the journal decision the same native run recorded for its denied target
        // (verdict deny, rule `<default-deny>`, reason `no permit matched`, no determining id),
        // re-targeted to this body's port. Both spellings are Core's; neither is stripped.
        let body = judge_policy_refusal(&out, "t", "127.0.0.1:37469").unwrap();
        let native_decision = crate::Decision {
            action: "Box::Action::\"net:connect\"".to_string(),
            resource: "127.0.0.1:37469".to_string(),
            rule: "<default-deny>".to_string(),
            verdict: "deny".to_string(),
            reason: "no permit matched".to_string(),
            determining_ids: Vec::new(),
            at_unix_nano: 0,
        };
        assert_eq!(
            default_deny_pair(&native_decision, &body, "127.0.0.1:37469"),
            Ok(())
        );
        for (mutate, reason) in [
            (
                Box::new(|d: &mut crate::Decision| d.rule = "default-deny".to_string())
                    as Box<dyn Fn(&mut crate::Decision)>,
                "not the default-deny rule",
            ),
            (
                Box::new(|d: &mut crate::Decision| d.reason = crate::FORBID_REASON.to_string()),
                "journal reason",
            ),
            (
                Box::new(|d: &mut crate::Decision| {
                    d.rule = "policy_6".to_string();
                    d.determining_ids = vec!["no_loopback".to_string()];
                }),
                "not the default-deny rule",
            ),
            (
                Box::new(|d: &mut crate::Decision| d.determining_ids = vec!["x".to_string()]),
                "determined by no policy",
            ),
            (
                Box::new(|d: &mut crate::Decision| d.resource = "127.0.0.1:1".to_string()),
                "not the refused target",
            ),
            (
                Box::new(|d: &mut crate::Decision| d.verdict = "permit".to_string()),
                "not a deny",
            ),
            (
                Box::new(|d: &mut crate::Decision| {
                    d.action = "Box::Action::\"http:request\"".to_string()
                }),
                "not a net:connect",
            ),
        ] {
            let mut decision = native_decision.clone();
            mutate(&mut decision);
            let err = default_deny_pair(&decision, &body, "127.0.0.1:37469").expect_err(reason);
            assert!(err.contains(reason), "{reason}: {err}");
        }
        let forbid_body = RefusalBody {
            rule: "policy: no_loopback".to_string(),
            reason: "loopback is refused".to_string(),
        };
        let err = default_deny_pair(&native_decision, &forbid_body, "127.0.0.1:37469")
            .expect_err("named");
        assert!(err.contains("body rule"), "{err}");
        let other_reason = RefusalBody {
            rule: "default-deny".to_string(),
            reason: "no.".to_string(),
        };
        let err = default_deny_pair(&native_decision, &other_reason, "127.0.0.1:37469")
            .expect_err("reason");
        assert!(err.contains("body reason"), "{err}");
        let err =
            judge_floor_probe(&out, "t", HostResolution::Resolves).expect_err("not the floor");
        assert!(err.contains("not the gateway floor's status line"), "{err}");
        // The refusal names the target: another target does not pass.
        let err = judge_policy_refusal(&out, "t", "127.0.0.1:1").expect_err("wrong target");
        assert!(err.contains("does not name the refused target"), "{err}");
    }

    /// The policy-refusal judge requires the exact refusal shape: the floor's bare 403, a missing
    /// marker, a wrong Content-Length, a bodyless refusal, a recorder body, and every non-EOF
    /// ending fail by name.
    #[test]
    fn the_policy_refusal_judge_requires_the_exact_refusal_shape() {
        fn refusal(body: &str) -> String {
            format!(
                "HTTP/1.1 403 Forbidden\r\nx-strands-box-egress: refused\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        }
        let body = "policy denied this operation on '127.0.0.1:9' [rule_x]: no.";
        let ok = format!(
            "HTTP/1.1 403 Forbidden\r\nx-strands-box-egress: refused\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(
            judge_policy_refusal(&records("t", ok.as_bytes(), "EOF"), "t", "127.0.0.1:9"),
            Ok(RefusalBody {
                rule: "rule_x".to_string(),
                reason: "no.".to_string(),
            })
        );
        let cases: &[(String, &str, &str)] = &[
            (String::from_utf8_lossy(BARE_403).into_owned(), "EOF", "floor's bare 403"),
            (ok.replace("x-strands-box-egress: refused\r\n", ""), "EOF", "exactly x-strands-box-egress"),
            (
                ok.replace(&format!("Content-Length: {}", body.len()), "Content-Length: 5"),
                "EOF",
                "does not frame",
            ),
            (
                "HTTP/1.1 403 Forbidden\r\nx-strands-box-egress: refused\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_string(),
                "EOF",
                "does not name the refused target",
            ),
            (
                {
                    let unnamed = body.replace("[rule_x]", "[]");
                    format!(
                        "HTTP/1.1 403 Forbidden\r\nx-strands-box-egress: refused\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{unnamed}",
                        unnamed.len()
                    )
                },
                "EOF",
                "no single rule id",
            ),
            (format!("{ok}{RECORDER_BODY}"), "EOF", "recorder's body reached"),
            (ok.clone(), "TIMEOUT", "timed out"),
            (ok.clone(), "RESET", "reset, not closed"),
            (ok.clone(), "ERROR boom", "read error"),
            // Delimiters: an unterminated bracket, a bracket without the separator, an empty
            // reason, and a nested bracket.
            (refusal("policy denied this operation on '127.0.0.1:9' [rule_x"), "EOF", "no closed rule bracket"),
            (refusal("policy denied this operation on '127.0.0.1:9' [rule_x] no separator"), "EOF", "no closed rule bracket"),
            (refusal("policy denied this operation on '127.0.0.1:9' [rule_x]: "), "EOF", "no reason after the rule"),
            (refusal("policy denied this operation on '127.0.0.1:9' [ru[le]]: no."), "EOF", "no single rule id"),
        ];
        for (bytes, end, reason) in cases {
            let out = records("t", bytes.as_bytes(), end);
            let err = judge_policy_refusal(&out, "t", "127.0.0.1:9").expect_err(&out);
            assert!(err.contains(reason), "{out:?} -> {err}");
        }
        assert_ne!(
            body.len(),
            5,
            "the replaced Content-Length above differs from the real one"
        );
    }

    /// Run the compiled probe with `DET_PROBE_FAULT=rearm-einval`: the first read-timeout setup
    /// fails as macOS does on a reset socket.
    fn probe_against_with_rearm_fault(port: u16, timeout: u64) -> (String, Duration) {
        let command = probe_command(
            probe_binary(),
            "T",
            &absolute_request("GET", "example.test", "/"),
            timeout,
            ProbeMode::Read,
        );
        let started = Instant::now();
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "HTTP_PROXY=http://127.0.0.1:{port}\nDET_PROBE_FAULT=rearm-einval {command}\n"
            ))
            .output()
            .expect("bash is on PATH");
        assert!(output.status.success(), "{:?}", output.status);
        (
            String::from_utf8_lossy(&output.stdout).into_owned(),
            started.elapsed(),
        )
    }

    /// Reproduction: the first read-timeout setup fails and the peer
    /// holds the connection open with nothing to read. The probe must end at its deadline with a
    /// TIMEOUT, never block past it, and never report EOF or a denial.
    #[test]
    fn a_refused_read_timeout_against_a_holding_peer_ends_at_the_deadline_as_a_timeout() {
        let port = one_shot_server(b"", Some(Duration::from_secs(4)));
        let (out, elapsed) = probe_against_with_rearm_fault(port, 1);
        assert!(
            elapsed < Duration::from_millis(1800),
            "the probe ended at its 1 s deadline: {elapsed:?}"
        );
        let transcript = Transcript::of(&out, "T");
        assert_eq!(transcript.ending, Ending::TimedOut, "{out}");
        assert!(transcript.bytes.is_empty());
        let err = judge_floor_probe(&out, "T", HostResolution::Resolves).expect_err("timeout");
        assert!(err.contains("neither answered nor closed"), "{err}");
        assert!(!probe_reached_gateway(&out, "T"));
    }

    /// After a refused read-timeout setup the probe still tells data, EOF and a hold apart: a peer
    /// that answers and closes gives the bytes and EOF; one that answers and holds gives the bytes
    /// and a TIMEOUT at the deadline.
    #[test]
    fn a_refused_read_timeout_still_yields_the_bytes_and_a_distinct_ending() {
        let (out, elapsed) = probe_against_with_rearm_fault(one_shot_server(BARE_403, None), 15);
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        let transcript = Transcript::of(&out, "T");
        assert_eq!(transcript.bytes, BARE_403.to_vec(), "{out}");
        assert_eq!(transcript.ending, Ending::Eof, "{out}");
        assert_eq!(
            judge_floor_probe(&out, "T", HostResolution::Resolves),
            Ok(FloorAnswer::GatewayFloor)
        );

        let (out, elapsed) = probe_against_with_rearm_fault(
            one_shot_server(BARE_403, Some(Duration::from_secs(4))),
            1,
        );
        assert!(elapsed < Duration::from_millis(1800), "{elapsed:?}");
        let transcript = Transcript::of(&out, "T");
        assert_eq!(transcript.bytes, BARE_403.to_vec(), "{out}");
        assert_eq!(transcript.ending, Ending::TimedOut, "{out}");
        let err = judge_floor_probe(&out, "T", HostResolution::Resolves).expect_err("timed out");
        assert!(err.contains("timed out"), "{err}");
    }

    /// A peer that closes with unread request bytes resets the connection instead of closing it.
    /// The probe reports the bytes it received and `END RESET`, which no judge reads as a close.
    #[test]
    fn a_reset_after_the_response_is_its_own_ending() {
        // The server writes a complete bare 400 and drops the socket without reading the request,
        // so the kernel answers the unread bytes with RST.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let _ = tcp.write_all(
                b"HTTP/1.1 400 bad request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            let _ = tcp.flush();
            drop(tcp);
        });
        let out = probe_against(port, 15, ProbeMode::Read);
        let transcript = Transcript::of(&out, "T");
        assert_eq!(transcript.status(), Some(400), "{out}");
        assert!(
            matches!(transcript.ending, Ending::Eof | Ending::Reset),
            "a close with unread bytes is EOF or RESET, never an error or a timeout: {out}"
        );
        // Both judges refuse a reset as a clean close.
        let reset = records("t", BARE_403, "RESET");
        let err = judge_floor_probe(&reset, "t", HostResolution::Resolves).expect_err("reset");
        assert!(err.contains("reset, not closed"), "{err}");
        assert!(!probe_reached_gateway(&reset, "t"));
    }

    /// A request that arrives after the accept is read whole under the connection deadline: the
    /// accepted stream blocks. On BSD and macOS an accepted socket inherits the listener's
    /// O_NONBLOCK, which made every read fail at once; Linux never inherited it, so this is the
    /// control there and the regression on macOS.
    #[test]
    fn a_delayed_request_on_an_accepted_stream_is_read_whole() {
        let recorder = HostRecorder::start();
        recorder.self_test();
        let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        tcp.set_read_timeout(Some(DEFAULT_CONNECTION_DEADLINE))
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        tcp.write_all(b"GET /late HTTP/1.1\r\nHost: h\r\n").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        tcp.write_all(b"\r\n").unwrap();
        let reply = read_head_and_body(
            &mut tcp,
            MAX_HEAD_BYTES,
            MAX_BODY_BYTES,
            Instant::now() + DEFAULT_CONNECTION_DEADLINE,
        );
        assert!(
            reply.complete && reply.raw.contains(RECORDER_BODY),
            "{reply:?}"
        );
        let snapshot = recorder.snapshot();
        assert_eq!(
            snapshot.request_lines(),
            vec!["GET /late HTTP/1.1".to_string()]
        );
        assert!(snapshot.incomplete().is_empty(), "{snapshot:?}");
        assert!(snapshot.accept_errors.is_empty(), "{snapshot:?}");
    }
}
