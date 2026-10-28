//! WebSocket through the egress gateway, end to end over real TLS.
//!
//! A real `MitmInterceptor` stands between a TLS workload client and a TLS WebSocket upstream that
//! this file implements, so every handshake, frame, and close crosses the gateway's relay, and the
//! upstream records what reached it. Authorization comes from `PathPolicy`, the test's stand-in for the policy: the
//! handshake is an ordinary `http:request` `GET`, decided on its host and path.
//!
//! Requires the default-on `tls-intercept` feature.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, RouteSpec, Vault, VaultConfig,
};
use egress_gateway::{
    AuditDecision, CapabilitySet, CredentialCapability, EffectAttempt, EffectInterceptor,
    EffectOutcome, EffectPermit, MitmConfig, MitmHandle, MitmInterceptor, ResponseLimits,
    StubEmitter,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use harness::{TlsUpstream, WorkloadClient};

const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CONTINUATION: u8 = 0x0;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xA;

/// The RFC 6455 example key; its accept value is `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// The mask the test client puts on each frame it sends.
const CLIENT_MASK: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

// ============================================================================================
// The policy stand-in: the handshake is an `http:request` `GET`
// ============================================================================================

/// Permits a connection to `hosts`, and each `HttpRequest` to them but the `(host, path)` pairs in
/// `denied`. It logs each request and release it decides, and the outcome each permit receives,
/// and it keeps the kind of every attempt and each request attempt whole.
struct PathPolicy {
    hosts: Vec<String>,
    denied: Vec<(String, String)>,
    log: Arc<Mutex<Vec<String>>>,
    kinds: Mutex<Vec<&'static str>>,
    request_attempts: Mutex<Vec<String>>,
}

impl PathPolicy {
    fn new(hosts: &[&str], denied: &[(&str, &str)]) -> Arc<Self> {
        Arc::new(Self {
            hosts: hosts.iter().map(|host| (*host).to_string()).collect(),
            denied: denied
                .iter()
                .map(|(host, path)| ((*host).to_string(), (*path).to_string()))
                .collect(),
            log: Arc::default(),
            kinds: Mutex::default(),
            request_attempts: Mutex::default(),
        })
    }

    /// Permit the connection and every request to `host`.
    fn permitting(host: &str) -> Arc<Self> {
        Self::new(&[host], &[])
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// The kind of each attempt, in order.
    fn kinds(&self) -> Vec<&'static str> {
        self.kinds.lock().unwrap().clone()
    }

    /// Each `HttpRequest` attempt, with every field.
    fn request_attempts(&self) -> Vec<String> {
        self.request_attempts.lock().unwrap().clone()
    }

    /// The request entries of the log.
    fn requests(&self) -> Vec<String> {
        self.log()
            .into_iter()
            .filter(|entry| entry.starts_with("request "))
            .collect()
    }
}

fn listed(hosts: &[String], host: &str) -> bool {
    hosts.iter().any(|listed| listed.eq_ignore_ascii_case(host))
}

impl EffectInterceptor for PathPolicy {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let denied = |message: &str| Err(io::Error::new(io::ErrorKind::PermissionDenied, message));
        self.kinds.lock().unwrap().push(match attempt {
            EffectAttempt::Resolve { .. } => "Resolve",
            EffectAttempt::Connect { .. } => "Connect",
            EffectAttempt::HttpRequest { .. } => "HttpRequest",
            EffectAttempt::ResponseRelease { .. } => "ResponseRelease",
            _ => "other",
        });
        if let EffectAttempt::HttpRequest {
            host,
            port,
            method,
            path,
            body_bytes,
            intercepted,
            mcp,
        } = attempt
        {
            self.request_attempts.lock().unwrap().push(format!(
                "{host}:{port} {method} {path} body_bytes={body_bytes} intercepted={intercepted} \
                 mcp={}",
                mcp.is_some()
            ));
        }
        let entry =
            match attempt {
                EffectAttempt::Resolve { host, .. } | EffectAttempt::Connect { host, .. } => {
                    if !listed(&self.hosts, host) {
                        return denied("connect denied by test policy");
                    }
                    None
                }
                EffectAttempt::HttpRequest {
                    host, method, path, ..
                } => {
                    if self.denied.iter().any(|(denied_host, denied_path)| {
                        denied_host == host && denied_path == path
                    }) {
                        return denied("http:request gate: denied by test policy");
                    }
                    Some(format!("request {method} {path}"))
                }
                EffectAttempt::ResponseRelease { status, .. } => {
                    Some(format!("release status={status}"))
                }
                _ => None,
            };
        if let Some(entry) = &entry {
            self.log.lock().unwrap().push(entry.clone());
        }
        Ok(Box::new(LoggedPermit {
            log: entry.map(|_| self.log.clone()),
        }))
    }
}

struct LoggedPermit {
    log: Option<Arc<Mutex<Vec<String>>>>,
}

impl EffectPermit for LoggedPermit {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        if let Some(log) = self.log {
            log.lock().unwrap().push(format!("outcome {outcome:?}"));
        }
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {
        if let Some(log) = self.log {
            log.lock().unwrap().push("indeterminate".to_string());
        }
    }
}

// ============================================================================================
// The frame format, written again here so the test does not trust the gateway's own codec
// ============================================================================================

/// One frame as it crossed a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    fin: bool,
    opcode: u8,
    masked: bool,
    /// The masking key on the wire, when the frame is masked.
    key: Option<[u8; 4]>,
    payload: Vec<u8>,
}

impl Frame {
    fn close_code(&self) -> u16 {
        assert_eq!(self.opcode, CLOSE, "expected a close frame: {self:?}");
        u16::from_be_bytes([self.payload[0], self.payload[1]])
    }
}

fn encode(out: &mut Vec<u8>, fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) {
    out.push(if fin { 0x80 } else { 0 } | opcode);
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    if payload.len() < 126 {
        out.push(mask_bit | payload.len() as u8);
    } else if payload.len() <= 0xFFFF {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(i, byte)| byte ^ key[i % 4]),
            );
        }
        None => out.extend_from_slice(payload),
    }
}

fn read_frame<R: Read>(stream: &mut R) -> io::Result<Frame> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    let length = match head[1] & 0x7F {
        126 => {
            let mut length = [0u8; 2];
            stream.read_exact(&mut length)?;
            u64::from(u16::from_be_bytes(length))
        }
        127 => {
            let mut length = [0u8; 8];
            stream.read_exact(&mut length)?;
            u64::from_be_bytes(length)
        }
        short => u64::from(short),
    };
    let masked = head[1] & 0x80 != 0;
    let mut key = [0u8; 4];
    if masked {
        stream.read_exact(&mut key)?;
    }
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload)?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[index % 4];
        }
    }
    Ok(Frame {
        fin: head[0] & 0x80 != 0,
        opcode: head[0] & 0x0F,
        masked,
        key: masked.then_some(key),
        payload,
    })
}

fn accept_value(key: &str) -> String {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(digest.finish())
}

// ============================================================================================
// Heads on the wire
// ============================================================================================

/// Read an HTTP head up to its blank line, one byte at a time so no frame byte is taken with it.
fn read_head<R: Read>(stream: &mut R) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 64 * 1024 {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// The value of header `name` in a raw head, if present.
fn header(head: &str, name: &str) -> Option<String> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn status(head: &str) -> u16 {
    head.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

// ============================================================================================
// The WebSocket upstream
// ============================================================================================

/// How the upstream answers a handshake.
#[derive(Clone, Copy)]
enum Answer {
    /// Accept, send the greeting in the same write as the 101 when one is set, then echo.
    Echo(Option<&'static str>),
    /// Accept, send the handshake's `Authorization` back in a text message and a ping, then echo.
    Reflect,
    /// Accept, send the frames that this builds from the handshake head in the same write, then
    /// echo.
    Script(fn(&str) -> Vec<u8>),
    /// Accept, send this many binary messages of this many bytes, each led by its index, then echo.
    Burst(u32, usize),
    /// Accept, with one more header line in the 101.
    AcceptWith(&'static str),
    /// Accept with the `Sec-WebSocket-Accept` of another key.
    WrongAccept,
    /// Answer with this response instead of a 101.
    Fixed(&'static str),
    /// Accept, then echo, and close with 1009 on any frame whose payload is above this size.
    FrameLimit(usize),
    /// Accept, send this many text messages `tick <n>`, one each interval, and never read.
    Talk(u32, Duration),
    /// Answer a request with no `Sec-WebSocket-Key` with a `200` and the body `ok`; accept and echo
    /// a handshake.
    OkOrEcho,
}

/// What reached the upstream.
#[derive(Default)]
struct Seen {
    handshakes: Vec<String>,
    frames: Vec<Frame>,
}

/// A TLS WebSocket server that echoes each message, answers each ping, and returns each close.
struct WsUpstream {
    port: u16,
    ca_pem: String,
    seen: Arc<Mutex<Seen>>,
}

impl WsUpstream {
    fn start(host: &str, answer: Answer) -> Self {
        let certified =
            rcgen::generate_simple_self_signed(vec![host.to_string(), "localhost".to_string()])
                .unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(certified.cert.der().to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        certified.signing_key.serialize_der(),
                    )),
                )
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let record = seen.clone();
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let config = config.clone();
                let record = record.clone();
                std::thread::spawn(move || {
                    let tls = StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
                    let _ = serve(tls, answer, &record);
                });
            }
        });
        Self {
            port,
            ca_pem: certified.cert.pem(),
            seen,
        }
    }

    fn handshakes(&self) -> Vec<String> {
        std::thread::sleep(Duration::from_millis(100));
        self.seen.lock().unwrap().handshakes.clone()
    }

    /// The frames the upstream received, once there are at least `count`.
    fn frames(&self, count: usize) -> Vec<Frame> {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let frames = self.seen.lock().unwrap().frames.clone();
            if frames.len() >= count || Instant::now() > until {
                return frames;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn serve(
    mut tls: StreamOwned<ServerConnection, TcpStream>,
    answer: Answer,
    seen: &Mutex<Seen>,
) -> io::Result<()> {
    tls.sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    let head = read_head(&mut tls);
    if !head.contains("HTTP/") {
        return Ok(());
    }
    seen.lock().unwrap().handshakes.push(head.clone());
    let key = header(&head, "sec-websocket-key").unwrap_or_default();
    let switching = |accept: &str, extra: &str| {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n{extra}\r\n"
        )
        .into_bytes()
    };
    let mut reply = Vec::new();
    match answer {
        Answer::Fixed(response) => {
            tls.write_all(response.as_bytes())?;
            return tls.flush();
        }
        Answer::WrongAccept => {
            reply.extend(switching(&accept_value("AAAAAAAAAAAAAAAAAAAAAA=="), ""));
        }
        Answer::AcceptWith(extra) => reply.extend(switching(&accept_value(&key), extra)),
        Answer::Echo(greeting) => {
            reply.extend(switching(&accept_value(&key), ""));
            if let Some(greeting) = greeting {
                encode(&mut reply, true, TEXT, greeting.as_bytes(), None);
            }
        }
        Answer::Burst(count, size) => {
            tls.write_all(&switching(&accept_value(&key), ""))?;
            for index in 0..count {
                let mut message = vec![0x5A; size];
                message[..4].copy_from_slice(&index.to_be_bytes());
                encode(&mut reply, true, BINARY, &message, None);
                tls.write_all(&reply)?;
                reply.clear();
            }
        }
        Answer::FrameLimit(_) => reply.extend(switching(&accept_value(&key), "")),
        Answer::OkOrEcho if key.is_empty() => {
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
            return tls.flush();
        }
        Answer::OkOrEcho => reply.extend(switching(&accept_value(&key), "")),
        Answer::Reflect => {
            reply.extend(switching(&accept_value(&key), ""));
            let authorization = header(&head, "authorization").unwrap_or_default();
            let message = format!("you sent {authorization}");
            encode(&mut reply, true, TEXT, message.as_bytes(), None);
            encode(&mut reply, true, PING, authorization.as_bytes(), None);
        }
        Answer::Script(script) => {
            reply.extend(switching(&accept_value(&key), ""));
            reply.extend(script(&head));
        }
        Answer::Talk(count, interval) => {
            tls.write_all(&switching(&accept_value(&key), ""))?;
            tls.flush()?;
            for index in 0..count {
                std::thread::sleep(interval);
                encode(
                    &mut reply,
                    true,
                    TEXT,
                    format!("tick {index}").as_bytes(),
                    None,
                );
                tls.write_all(&reply)?;
                tls.flush()?;
                reply.clear();
            }
            // Hold the connection, and read nothing.
            std::thread::sleep(Duration::from_secs(10));
            return Ok(());
        }
    }
    tls.write_all(&reply)?;
    tls.flush()?;
    let mut open: Option<(u8, Vec<u8>)> = None;
    loop {
        let frame = read_frame(&mut tls)?;
        seen.lock().unwrap().frames.push(frame.clone());
        let mut out = Vec::new();
        if let Answer::FrameLimit(limit) = answer
            && frame.payload.len() > limit
        {
            encode(&mut out, true, CLOSE, b"\x03\xf1frame too big", None);
            tls.write_all(&out)?;
            tls.conn.send_close_notify();
            return tls.flush();
        }
        match frame.opcode {
            TEXT | BINARY | CONTINUATION => {
                let (opcode, mut message) = open.take().unwrap_or((frame.opcode, Vec::new()));
                message.extend_from_slice(&frame.payload);
                if !frame.fin {
                    open = Some((opcode, message));
                    continue;
                }
                encode(&mut out, true, opcode, &message, None);
            }
            PING => encode(&mut out, true, PONG, &frame.payload, None),
            CLOSE => {
                encode(&mut out, true, CLOSE, &frame.payload, None);
                tls.write_all(&out)?;
                tls.conn.send_close_notify();
                return tls.flush();
            }
            _ => continue,
        }
        tls.write_all(&out)?;
        tls.flush()?;
    }
}

// ============================================================================================
// The workload client
// ============================================================================================

fn handshake_head(host: &str, port: u16, extra: &str) -> String {
    format!(
        "GET /chat HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
}

/// A WebSocket workload over a TLS tunnel through the gateway.
struct WsClient<S: Read + Write> {
    tls: StreamOwned<ClientConnection, S>,
}

impl WsClient<TcpStream> {
    /// CONNECT through the gateway's TCP port and complete TLS with its minted leaf.
    fn connect(handle: &MitmHandle, host: &str, port: u16) -> Self {
        let tls = WorkloadClient::connect(handle.port().unwrap(), host, port).into_tls();
        tls.sock
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Self { tls }
    }

    /// Connect and send a handshake with `extra` header lines; returns the client and the reply.
    fn open(handle: &MitmHandle, host: &str, port: u16, extra: &str) -> (Self, String) {
        let mut client = Self::connect(handle, host, port);
        let reply = client.request(&handshake_head(host, port, extra));
        (client, reply)
    }

    /// Send `outgoing` while reading frames, on a non-blocking socket, until `want` text frames
    /// arrived or 10 s passed. Returns the text frames and the bytes of `outgoing` that left.
    fn send_while_reading(&mut self, outgoing: &[u8], want: usize) -> (Vec<Frame>, usize) {
        let tls = &mut self.tls;
        tls.sock.set_nonblocking(true).unwrap();
        let (mut sent, mut received, mut texts) = (0, Vec::new(), Vec::new());
        let until = Instant::now() + Duration::from_secs(10);
        while texts.len() < want && Instant::now() < until {
            if sent < outgoing.len() {
                sent += tls.conn.writer().write(&outgoing[sent..]).unwrap_or(0);
            }
            while tls.conn.wants_write() {
                match tls.conn.write_tls(&mut tls.sock) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("writing to the gateway: {error}"),
                }
            }
            match tls.conn.read_tls(&mut tls.sock) {
                Ok(0) => break,
                Ok(_) => {
                    tls.conn.process_new_packets().unwrap();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("reading from the gateway: {error}"),
            }
            let mut plain = [0u8; 16 * 1024];
            while let Ok(count) = tls.conn.reader().read(&mut plain) {
                if count == 0 {
                    break;
                }
                received.extend_from_slice(&plain[..count]);
            }
            loop {
                let mut cursor = io::Cursor::new(&received[..]);
                let Ok(frame) = read_frame(&mut cursor) else {
                    break;
                };
                let used = cursor.position() as usize;
                received.drain(..used);
                if frame.opcode == TEXT {
                    texts.push(frame);
                }
            }
        }
        tls.sock.set_nonblocking(false).unwrap();
        (texts, sent)
    }
}

impl<S: Read + Write> WsClient<S> {
    /// Send a request head and read the reply head, with its body when it has a length.
    fn request(&mut self, head: &str) -> String {
        self.tls.write_all(head.as_bytes()).unwrap();
        self.tls.flush().unwrap();
        let mut reply = read_head(&mut self.tls);
        if let Some(length) = header(&reply, "content-length") {
            let mut body = vec![0u8; length.parse().unwrap()];
            self.tls.read_exact(&mut body).unwrap();
            reply.push_str(&String::from_utf8_lossy(&body));
        }
        reply
    }

    fn send_frame(&mut self, fin: bool, opcode: u8, payload: &[u8]) {
        let mut wire = Vec::new();
        encode(&mut wire, fin, opcode, payload, Some(CLIENT_MASK));
        self.send_raw(&wire);
    }

    fn send(&mut self, opcode: u8, payload: &[u8]) {
        self.send_frame(true, opcode, payload);
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        self.tls.write_all(bytes).unwrap();
        self.tls.flush().unwrap();
    }

    fn recv(&mut self) -> Frame {
        read_frame(&mut self.tls).expect("a frame from the gateway")
    }

    /// Read past the last frame: `Ok(0)` is the gateway's TLS close_notify.
    fn read_end(&mut self) -> io::Result<usize> {
        let mut byte = [0u8; 1];
        self.tls.read(&mut byte)
    }

    /// Complete the close handshake with code 1000, then close the connection.
    fn close(mut self) {
        self.send(CLOSE, b"\x03\xe8");
        assert_eq!(self.recv().close_code(), 1000);
        assert_eq!(self.read_end().unwrap(), 0);
    }
}

// ============================================================================================
// Gateway setup
// ============================================================================================

fn start_gateway(
    host: &str,
    upstream: &WsUpstream,
    policy: Arc<PathPolicy>,
    config: MitmConfig,
) -> MitmHandle {
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem.clone()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..config
    };
    MitmInterceptor::start(config, CapabilitySet::default(), policy).unwrap()
}

/// A gateway with the default config, permitting `host` and every request to it.
fn plain_gateway(host: &str, upstream: &WsUpstream) -> MitmHandle {
    start_gateway(
        host,
        upstream,
        PathPolicy::permitting(host),
        MitmConfig::default(),
    )
}

/// A gateway like [`plain_gateway`] with the credential `controls`.
fn credential_gateway(host: &str, upstream: &WsUpstream, controls: CapabilitySet) -> MitmHandle {
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem.clone()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    MitmInterceptor::start(config, controls, PathPolicy::permitting(host)).unwrap()
}

fn pattern(host: &str, port: u16) -> DestinationPattern {
    DestinationPattern::parse(&format!("{host}:{port}")).unwrap()
}

/// Place `secret` in a uniquely-named environment variable and return its `env://` locator.
fn env_locator(secret: &str) -> Locator {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "EGRESS_WEBSOCKET_TEST_SECRET_{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // SAFETY: the name is unique to this call, so no other test reads or writes it.
    unsafe { std::env::set_var(&name, secret) };
    Locator::parse_uri(&format!("env://{name}")).unwrap()
}

/// A gateway like [`plain_gateway`] that keeps each decision it emits.
fn recording_gateway(host: &str, upstream: &WsUpstream) -> (MitmHandle, StubEmitter) {
    let emitter = StubEmitter::new();
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem.clone()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start_with_emitter(
        config,
        CapabilitySet::default(),
        PathPolicy::permitting(host),
        Box::new(emitter.clone()),
    )
    .unwrap();
    (handle, emitter)
}

/// The `(method, path, reason)` of each deny decision the gateway emitted.
fn emitted_denials(emitter: &StubEmitter) -> Vec<(String, String, String)> {
    emitter
        .records()
        .into_iter()
        .filter(|record| record.decision == AuditDecision::Deny)
        .map(|record| (record.method, record.path, record.reason))
        .collect()
}

/// The deny reasons in the gateway's audit log.
fn denials(handle: &MitmHandle) -> Vec<String> {
    handle
        .drain_audit_events()
        .into_iter()
        .filter(|event| event.decision == AuditDecision::Deny)
        .map(|event| event.reason)
        .collect()
}

/// A reply that a server with no WebSocket endpoint gives.
const NOT_FOUND: &str = "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnone";

// ============================================================================================
// Refusals before policy and before the upstream sees a request
// ============================================================================================

#[test]
fn an_upgrade_to_an_mcp_host_is_refused() {
    let host = "mcp.ws.test";
    let upstream = WsUpstream::start(host, Answer::Fixed(NOT_FOUND));
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(
        host,
        &upstream,
        policy.clone(),
        MitmConfig {
            mcp_servers: vec![(host.to_string(), "tools".to_string())],
            ..MitmConfig::default()
        },
    );

    let (_client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 403, "{reply:?}");
    assert!(reply.ends_with("WebSocket refused for an MCP server"));
    assert!(header(&reply, egress_gateway::PROXY_ORIGIN_HEADER).is_some());
    assert!(upstream.handshakes().is_empty());
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: upgrade to a remote MCP server")
    );
    assert_eq!(
        policy.requests(),
        Vec::<String>::new(),
        "the refusal comes before policy"
    );
}

#[test]
fn a_malformed_handshake_is_refused_with_400() {
    let host = "malformed.ws.test";
    let upstream = WsUpstream::start(host, Answer::Fixed(NOT_FOUND));
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(host, &upstream, policy.clone(), MitmConfig::default());

    let mut client = WsClient::connect(&handle, host, upstream.port);
    let reply = client
        .request(&handshake_head(host, upstream.port, "").replace("Version: 13", "Version: 8"));
    assert_eq!(status(&reply), 400, "{reply:?}");
    assert!(
        reply.ends_with("malformed WebSocket handshake"),
        "{reply:?}"
    );
    assert!(header(&reply, egress_gateway::PROXY_ORIGIN_HEADER).is_some());
    assert!(upstream.handshakes().is_empty());
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: handshake version is not 13")
    );
    assert_eq!(policy.requests(), Vec::<String>::new());
}

/// A `POST` that names `websocket` in `Upgrade` was stripped and forwarded before; now it is a
/// malformed handshake.
#[test]
fn a_post_that_asks_for_websocket_is_refused_with_400() {
    let host = "post.ws.test";
    let upstream = WsUpstream::start(host, Answer::Fixed(NOT_FOUND));
    let handle = start_gateway(
        host,
        &upstream,
        PathPolicy::permitting(host),
        MitmConfig::default(),
    );

    let mut client = WsClient::connect(&handle, host, upstream.port);
    let reply = client.request(
        &handshake_head(host, upstream.port, "Content-Length: 0\r\n").replacen("GET", "POST", 1),
    );
    assert_eq!(status(&reply), 400, "{reply:?}");
    assert!(upstream.handshakes().is_empty());
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: handshake method is not GET")
    );
}

/// The refusal comes before the policy decides the connection: no `net:connect`, and no dial.
#[test]
fn a_plaintext_websocket_handshake_is_refused() {
    let host = "plain.ws.test";
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = origin.local_addr().unwrap().port();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let record = heads.clone();
    let dials = Arc::new(AtomicUsize::new(0));
    let dialed = dials.clone();
    std::thread::spawn(move || {
        for mut stream in origin.incoming().flatten() {
            dialed.fetch_add(1, Ordering::SeqCst);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let head = read_head(&mut stream);
            if !head.is_empty() {
                record.lock().unwrap().push(head);
            }
        }
    });
    let policy = PathPolicy::permitting(host);
    let handle = MitmInterceptor::start(
        MitmConfig {
            dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
            ..MitmConfig::default()
        },
        CapabilitySet::default(),
        policy.clone(),
    )
    .unwrap();

    let mut proxy = TcpStream::connect(("127.0.0.1", handle.port().unwrap())).unwrap();
    proxy
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = handshake_head(host, port, "").replacen(
        "GET /chat",
        &format!("GET http://{host}:{port}/chat"),
        1,
    );
    proxy.write_all(request.as_bytes()).unwrap();
    let mut reply = String::new();
    let _ = proxy.read_to_string(&mut reply);

    assert!(reply.starts_with("HTTP/1.1 403"), "{reply:?}");
    assert!(reply.ends_with("WebSocket requires TLS"), "{reply:?}");
    assert!(header(&reply, egress_gateway::PROXY_ORIGIN_HEADER).is_some());
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        heads.lock().unwrap().is_empty(),
        "the origin sees no request"
    );
    assert_eq!(dials.load(Ordering::SeqCst), 0, "no upstream is dialed");
    assert_eq!(
        policy.kinds(),
        Vec::<&str>::new(),
        "the policy decides nothing"
    );
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: upgrade on a plaintext request")
    );
}

// ============================================================================================
// The handshake as forwarded
// ============================================================================================

/// The offer of `permessage-deflate` never reaches the upstream, so no message is compressed
/// before the gateway reads it.
#[test]
fn extensions_are_removed_from_the_handshake() {
    let host = "extensions.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(host, &upstream, policy.clone(), MitmConfig::default());

    let (mut client, reply) = WsClient::open(
        &handle,
        host,
        upstream.port,
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\
         Sec-WebSocket-Extensions: x-other\r\n",
    );
    assert_eq!(status(&reply), 101, "{reply:?}");
    let handshake = &upstream.handshakes()[0];
    assert_eq!(header(handshake, "sec-websocket-extensions"), None);
    assert_eq!(header(handshake, "sec-websocket-key").as_deref(), Some(KEY));
    assert_eq!(
        header(handshake, "sec-websocket-version").as_deref(),
        Some("13")
    );
    assert_eq!(policy.requests(), ["request GET /chat"]);
    client.send(TEXT, b"uncompressed");
    assert_eq!(client.recv().payload, b"uncompressed");
}

/// A normal request that asks for `h2c` still loses its upgrade fields and is forwarded as before.
#[test]
fn an_h2c_upgrade_on_a_normal_request_is_still_stripped() {
    let host = "h2c.ws.test";
    let upstream = TlsUpstream::start(host);
    let policy = PathPolicy::permitting(host);
    let handle = MitmInterceptor::start(
        MitmConfig {
            upstream_ca_pems: vec![upstream.ca_pem()],
            dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
            ..MitmConfig::default()
        },
        CapabilitySet::default(),
        policy.clone(),
    )
    .unwrap();

    let mut client = WorkloadClient::connect(handle.port().unwrap(), host, upstream.port());
    client.send_request(
        "GET",
        "/",
        &[
            ("Upgrade", "h2c"),
            ("Connection", "Upgrade, HTTP2-Settings"),
            ("HTTP2-Settings", "AAMAAABkAAQAAP__"),
        ],
        b"",
    );
    assert_eq!(client.read_status(), 200);

    let seen = upstream.last_request();
    assert_eq!(seen.header("upgrade"), None);
    assert_eq!(seen.header("http2-settings"), None);
    assert_eq!(seen.header("connection").as_deref(), Some("close"));
    assert_eq!(policy.requests(), ["request GET /"]);
}

// ============================================================================================
// The handshake is an ordinary `http:request`
// ============================================================================================

#[test]
fn text_and_binary_messages_round_trip_and_the_lifecycle_records_the_101() {
    let host = "echo.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(host, &upstream, policy.clone(), MitmConfig::default());

    let (mut client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert!(
        reply.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{reply:?}"
    );
    assert_eq!(header(&reply, "upgrade").as_deref(), Some("websocket"));
    assert_eq!(header(&reply, "connection").as_deref(), Some("Upgrade"));
    assert_eq!(
        header(&reply, "sec-websocket-accept").as_deref(),
        Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    );
    assert_eq!(header(&reply, "content-length"), None);
    assert_eq!(header(&reply, egress_gateway::PROXY_ORIGIN_HEADER), None);

    client.send(TEXT, b"hello");
    let text = client.recv();
    assert_eq!(
        (text.opcode, text.payload.as_slice()),
        (TEXT, &b"hello"[..])
    );
    assert!(
        text.fin && !text.masked,
        "the gateway frames to the workload unmasked"
    );
    client.send(BINARY, &[0, 1, 2, 255]);
    assert_eq!(client.recv().payload, vec![0, 1, 2, 255]);

    let frames = upstream.frames(2);
    assert_eq!(frames[0].payload, b"hello");
    assert_eq!(frames[1].payload, vec![0, 1, 2, 255]);
    assert!(
        frames.iter().all(|frame| frame.masked && frame.fin),
        "the gateway re-masks each frame to the upstream: {frames:?}"
    );

    let handshake = &upstream.handshakes()[0];
    assert_eq!(header(handshake, "upgrade").as_deref(), Some("websocket"));
    assert_eq!(header(handshake, "connection").as_deref(), Some("Upgrade"));
    assert_eq!(header(handshake, "content-length"), None);

    let log = policy.log();
    assert_eq!(log[0], "request GET /chat", "{log:?}");
    assert!(
        log[1].starts_with("outcome Replied") && log[1].contains("status: 101"),
        "the request permit records the 101: {log:?}"
    );
    assert_eq!(log[2], "release status=101", "{log:?}");
    assert!(log[3].starts_with("outcome Completed"), "{log:?}");
}

#[test]
fn the_handshake_attempt_is_an_ordinary_get() {
    let host = "attempt.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(host, &upstream, policy.clone(), MitmConfig::default());

    let (_client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 101, "{reply:?}");
    assert_eq!(
        policy.request_attempts(),
        [format!(
            "{host}:{} GET /chat body_bytes=0 intercepted=true mcp=false",
            upstream.port
        )]
    );
}

#[test]
fn messages_raise_no_effect_attempt() {
    let host = "quiet.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(host, &upstream, policy.clone(), MitmConfig::default());

    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");
    for index in 0..20 {
        let message = format!("message {index}");
        client.send(TEXT, message.as_bytes());
        assert_eq!(client.recv().payload, message.as_bytes());
    }
    assert_eq!(upstream.frames(20).len(), 20);
    assert_eq!(
        policy.kinds(),
        ["Resolve", "Connect", "HttpRequest", "ResponseRelease"]
    );
}

#[test]
fn a_handshake_the_policy_denies_is_refused_before_the_upstream() {
    let host = "denied.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    // The policy permits the connection, and refuses `GET /chat`.
    let handle = start_gateway(
        host,
        &upstream,
        PathPolicy::new(&[host], &[(host, "/chat")]),
        MitmConfig::default(),
    );

    let (_client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 403, "{reply:?}");
    assert!(reply.contains("http:request gate"), "{reply:?}");
    assert!(
        header(&reply, egress_gateway::PROXY_ORIGIN_HEADER).is_some(),
        "the refusal is the gateway's own"
    );
    assert!(
        upstream.handshakes().is_empty(),
        "the upstream sees no handshake"
    );
}

// ============================================================================================
// Messages cross the relay
// ============================================================================================

#[test]
fn a_one_mib_message_round_trips() {
    let host = "large.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = plain_gateway(host, &upstream);
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    let message: Vec<u8> = (0..1024 * 1024).map(|index| (index % 251) as u8).collect();
    client.send(BINARY, &message);
    let echoed = client.recv();
    assert_eq!(echoed.opcode, BINARY);
    assert!(echoed.payload == message, "the 1 MiB message changed");
    let frames = upstream.frames(1);
    assert_eq!(
        frames.len(),
        1,
        "a message sent in one frame goes on in one frame"
    );
    assert!(frames[0].fin && frames[0].payload.len() == message.len());
}

/// A server that caps its frame size, as AgentCore Runtime (64 KB) and API Gateway (32 KB) do, gets
/// a large message in fragments no larger than the ones the client sent.
#[test]
fn a_fragmented_message_reaches_a_frame_limited_server_in_fragments() {
    let host = "limited.ws.test";
    let upstream = WsUpstream::start(host, Answer::FrameLimit(64 * 1024));
    let handle = plain_gateway(host, &upstream);
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    let fragment = 32 * 1024;
    let message: Vec<u8> = (0..200 * 1024).map(|index| (index % 251) as u8).collect();
    let count = message.len().div_ceil(fragment);
    for (index, chunk) in message.chunks(fragment).enumerate() {
        let opcode = if index == 0 { BINARY } else { CONTINUATION };
        client.send_frame(index + 1 == count, opcode, chunk);
    }
    let echoed = client.recv();
    assert_eq!(
        (echoed.opcode, echoed.payload.len()),
        (BINARY, message.len()),
        "the server closes 1009 on a frame above its limit"
    );
    assert!(echoed.payload == message, "the message changed");

    let frames = upstream.frames(count);
    assert_eq!(frames.len(), count);
    assert!(
        frames
            .iter()
            .all(|frame| frame.masked && frame.payload.len() <= fragment)
    );
    assert_eq!(frames[0].opcode, BINARY);
    assert!(frames[1..].iter().all(|frame| frame.opcode == CONTINUATION));
    assert!(frames[..count - 1].iter().all(|frame| !frame.fin) && frames[count - 1].fin);
}

#[test]
fn a_fragmented_message_with_a_ping_between_its_fragments_is_reassembled() {
    let host = "fragments.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = plain_gateway(host, &upstream);
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    client.send_frame(false, TEXT, b"frag");
    client.send_frame(true, PING, b"between");
    client.send_frame(false, CONTINUATION, b"ment");
    client.send_frame(true, CONTINUATION, b"ed");

    let pong = client.recv();
    assert_eq!(
        (pong.opcode, pong.payload.as_slice()),
        (PONG, &b"between"[..])
    );
    let message = client.recv();
    assert_eq!(
        (message.opcode, message.payload.as_slice()),
        (TEXT, &b"fragmented"[..])
    );

    let frames = upstream.frames(2);
    assert_eq!(frames[0].opcode, PING, "the control frame passes at once");
    let message = &frames[1];
    assert_eq!(
        (
            message.fin,
            message.opcode,
            message.masked,
            message.payload.as_slice()
        ),
        (true, TEXT, true, &b"fragmented"[..]),
        "a message below the smallest fragment goes on in one frame"
    );
}

/// A sender's fragments below 1 KiB go on as 1 KiB fragments, so a message in one-byte fragments
/// costs the gateway no frame header per byte.
#[test]
fn a_message_in_tiny_fragments_goes_on_in_one_kib_fragments() {
    let host = "tiny.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = plain_gateway(host, &upstream);
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    let message: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
    let count = message.len() / 16;
    for (index, chunk) in message.chunks(16).enumerate() {
        let opcode = if index == 0 { BINARY } else { CONTINUATION };
        client.send_frame(index + 1 == count, opcode, chunk);
    }
    assert!(client.recv().payload == message, "the message changed");
    let sizes: Vec<usize> = upstream
        .frames(4)
        .iter()
        .map(|frame| frame.payload.len())
        .collect();
    assert_eq!(sizes, vec![1024; 4]);
}

#[test]
fn each_frame_to_the_upstream_has_a_fresh_mask_key() {
    let host = "masks.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = plain_gateway(host, &upstream);
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    for message in [&b"one"[..], b"two", b"three"] {
        client.send(TEXT, message);
        assert_eq!(client.recv().payload, message);
    }
    let keys: Vec<[u8; 4]> = upstream
        .frames(3)
        .iter()
        .map(|frame| frame.key.expect("a masked frame"))
        .collect();
    assert!(
        keys.iter().all(|key| *key != CLIENT_MASK),
        "the workload's key never reaches the upstream"
    );
    assert!(
        keys[0] != keys[1] && keys[1] != keys[2] && keys[0] != keys[2],
        "each frame gets its own key"
    );
}

#[test]
fn ping_and_pong_pass_end_to_end() {
    let host = "ping.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = plain_gateway(host, &upstream);
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    client.send(PONG, b"unsolicited");
    client.send(PING, b"are you there");
    let pong = client.recv();
    assert_eq!(
        (pong.opcode, pong.payload.as_slice()),
        (PONG, &b"are you there"[..])
    );

    let frames = upstream.frames(2);
    assert_eq!(
        frames
            .iter()
            .map(|frame| (frame.opcode, frame.payload.as_slice()))
            .collect::<Vec<_>>(),
        vec![(PONG, &b"unsolicited"[..]), (PING, &b"are you there"[..])],
        "the upstream, not the gateway, answers the ping"
    );
}

#[test]
fn the_close_handshake_completes_and_tls_closes() {
    let host = "close.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = plain_gateway(host, &upstream);
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    client.send(CLOSE, b"\x03\xe8bye");
    let close = client.recv();
    assert_eq!(close.payload, b"\x03\xe8bye");
    assert_eq!(close.close_code(), 1000);
    assert_eq!(
        client.read_end().unwrap(),
        0,
        "TLS close_notify follows the close"
    );

    let frames = upstream.frames(1);
    assert_eq!(frames[0].payload, b"\x03\xe8bye");
    assert!(frames[0].masked);
}

#[test]
fn the_first_server_message_after_the_101_arrives() {
    let host = "greeting.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(Some("welcome")));
    let handle = plain_gateway(host, &upstream);
    let (mut client, reply) = WsClient::open(&handle, host, upstream.port, "");

    assert_eq!(status(&reply), 101);
    let greeting = client.recv();
    assert_eq!(
        (greeting.opcode, greeting.payload.as_slice()),
        (TEXT, &b"welcome"[..])
    );
    client.send(TEXT, b"then");
    assert_eq!(client.recv().payload, b"then");
}

#[test]
fn a_frame_sent_with_the_handshake_is_relayed() {
    let host = "eager.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = plain_gateway(host, &upstream);
    let mut client = WsClient::connect(&handle, host, upstream.port);

    // The head and the first frame leave in one write, before the 101 arrives.
    let mut eager = handshake_head(host, upstream.port, "").into_bytes();
    encode(&mut eager, true, TEXT, b"early", Some(CLIENT_MASK));
    client.send_raw(&eager);
    let reply = read_head(&mut client.tls);
    assert_eq!(status(&reply), 101, "{reply:?}");
    assert_eq!(client.recv().payload, b"early");
}

/// A burst larger than every buffer on the way backs up both directions, and still arrives whole,
/// in order, and with the other direction still moving.
#[test]
fn a_burst_larger_than_the_buffers_arrives_whole_and_in_order() {
    let host = "burst.ws.test";
    let (count, size) = (64u32, 64 * 1024);
    let upstream = WsUpstream::start(host, Answer::Burst(count, size));
    let handle = plain_gateway(host, &upstream);
    let (mut client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 101, "{reply:?}");

    client.send(TEXT, b"still here");
    std::thread::sleep(Duration::from_millis(300));
    for index in 0..count {
        let message = client.recv();
        assert_eq!(message.opcode, BINARY, "message {index}");
        assert_eq!(message.payload.len(), size, "message {index}");
        assert_eq!(message.payload[..4], index.to_be_bytes(), "message {index}");
        assert!(message.payload[4..].iter().all(|byte| *byte == 0x5A));
    }
    let echoed = client.recv();
    assert_eq!(echoed.payload, b"still here");
}

/// A server that reads nothing still delivers its messages to the client while the client's own
/// messages wait: each direction has its own outbox.
#[test]
fn a_stalled_server_does_not_stall_messages_to_the_client() {
    let host = "stalled.ws.test";
    let ticks = 20;
    let upstream = WsUpstream::start(host, Answer::Talk(ticks, Duration::from_millis(100)));
    let handle = plain_gateway(host, &upstream);
    let (mut client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 101, "{reply:?}");

    // 48 MiB in 64 KiB messages: more than every socket buffer and outbox on the way.
    let mut flood = Vec::new();
    for _ in 0..768 {
        encode(
            &mut flood,
            true,
            BINARY,
            &[0x33; 64 * 1024],
            Some(CLIENT_MASK),
        );
    }
    let (texts, sent) = client.send_while_reading(&flood, ticks as usize);
    let texts: Vec<String> = texts
        .into_iter()
        .map(|frame| String::from_utf8(frame.payload).unwrap())
        .collect();
    let expected: Vec<String> = (0..ticks).map(|index| format!("tick {index}")).collect();
    assert_eq!(texts, expected);
    assert!(
        sent < flood.len(),
        "the client's messages wait for a server that reads nothing: {sent} of {}",
        flood.len()
    );
}

#[test]
fn a_websocket_runs_over_the_af_unix_transport() {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let host = "unix.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let socket = std::env::temp_dir().join(format!(
        "ws-e2e-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&socket);
    let handle = start_gateway(
        host,
        &upstream,
        PathPolicy::permitting(host),
        MitmConfig {
            unix_socket_path: Some(socket.clone()),
            ..MitmConfig::default()
        },
    );

    let mut unix = UnixStream::connect(&socket).unwrap();
    unix.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let authority = format!("{host}:{}", upstream.port);
    unix.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .unwrap();
    assert!(read_head(&mut unix).contains("200 Connection Established"));
    let tls = ClientConnection::new(
        Arc::new(harness::permissive_client_config()),
        ServerName::try_from(host.to_string()).unwrap(),
    )
    .unwrap();
    let mut client = WsClient {
        tls: StreamOwned::new(tls, unix),
    };

    let reply = client.request(&handshake_head(host, upstream.port, ""));
    assert_eq!(status(&reply), 101, "{reply:?}");
    client.send(TEXT, b"over AF_UNIX");
    assert_eq!(client.recv().payload, b"over AF_UNIX");

    handle.shutdown();
    let _ = std::fs::remove_file(&socket);
}

// ============================================================================================
// Credentials on the handshake
// ============================================================================================

/// The secret a credentialed route attaches to the handshake as `Bearer <secret>`.
const SECRET: &str = "sk_live_REALSECRET";

/// A WebSocket opened through a route that attaches [`SECRET`] to the handshake.
struct Credentialed {
    client: WsClient<TcpStream>,
    reply: String,
    handle: MitmHandle,
    upstream: WsUpstream,
    phantom: String,
}

fn open_credentialed(host: &str, answer: Answer) -> Credentialed {
    let upstream = WsUpstream::start(host, answer);
    let port = upstream.port;
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(
        RouteSpec::opaque(
            pattern(host, port),
            env_locator(SECRET),
            InjectMode::header("Bearer {}".to_string(), None).unwrap(),
        ),
    ))
    .unwrap();
    let phantom = opened.phantoms()[0].token().to_string();
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(
            pattern(host, port),
            Arc::new(opened.into_vault()),
        ))
        .build();
    let handle = credential_gateway(host, &upstream, controls);
    let (client, reply) = WsClient::open(
        &handle,
        host,
        port,
        &format!("Authorization: Bearer {phantom}\r\n"),
    );
    Credentialed {
        client,
        reply,
        handle,
        upstream,
        phantom,
    }
}

/// The secret the upstream received on the handshake.
fn secret_from(head: &str) -> String {
    header(head, "authorization")
        .unwrap_or_default()
        .trim_start_matches("Bearer ")
        .to_string()
}

#[test]
fn a_credential_is_injected_on_the_handshake_and_a_reflected_secret_is_redacted() {
    let Credentialed {
        mut client,
        reply,
        handle,
        upstream,
        phantom,
    } = open_credentialed("secret.ws.test", Answer::Reflect);
    assert_eq!(status(&reply), 101, "{reply:?}");

    let handshake = &upstream.handshakes()[0];
    assert_eq!(
        header(handshake, "authorization").as_deref(),
        Some("Bearer sk_live_REALSECRET"),
        "the upstream sees the real secret on the handshake"
    );
    assert!(!handshake.contains(&phantom));

    let message = client.recv();
    assert_eq!(
        String::from_utf8(message.payload).unwrap(),
        "you sent Bearer [REDACTED]",
        "the reflected secret is redacted in the server message"
    );
    let ping = client.recv();
    assert_eq!(ping.opcode, PING);
    assert!(
        ping.payload.is_empty(),
        "a control frame that carried the secret loses its payload"
    );
    client.send(TEXT, b"after");
    assert_eq!(client.recv().payload, b"after");

    for event in handle.drain_audit_events() {
        assert!(!format!("{event:?}").contains("sk_live_REALSECRET"));
    }
}

#[test]
fn a_secret_in_a_fragmented_server_message_is_redacted_before_the_message_is_fragmented_again() {
    let mut opened = open_credentialed(
        "fragsecret.ws.test",
        Answer::Script(|head| {
            let secret = secret_from(head);
            let (first, second) = secret.split_at(8);
            let mut out = Vec::new();
            let lead = format!("{}you sent {first}", "x".repeat(1500));
            encode(&mut out, false, TEXT, lead.as_bytes(), None);
            let tail = format!("{second}{}", "y".repeat(1500));
            encode(&mut out, true, CONTINUATION, tail.as_bytes(), None);
            out
        }),
    );
    assert_eq!(status(&opened.reply), 101, "{:?}", opened.reply);
    assert_eq!(secret_from(&opened.upstream.handshakes()[0]), SECRET);

    let mut frames = vec![opened.client.recv()];
    while !frames.last().unwrap().fin {
        frames.push(opened.client.recv());
    }
    let joined: Vec<u8> = frames
        .iter()
        .flat_map(|frame| frame.payload.clone())
        .collect();
    let expected = format!(
        "{}you sent [REDACTED]{}",
        "x".repeat(1500),
        "y".repeat(1500)
    );
    assert!(
        String::from_utf8(joined).unwrap() == expected,
        "the secret is redacted"
    );
    let largest = 1500 + "you sent sk_live_".len();
    assert_eq!(
        frames
            .iter()
            .map(|frame| (frame.opcode, frame.payload.len()))
            .collect::<Vec<_>>(),
        vec![(TEXT, largest), (CONTINUATION, expected.len() - largest)],
        "the message goes on in the server's largest fragment size"
    );
}

#[test]
fn a_secret_in_a_server_close_reason_leaves_only_the_close_code() {
    let mut opened = open_credentialed(
        "closesecret.ws.test",
        Answer::Script(|head| {
            let reason = format!("bye {}", secret_from(head));
            let mut out = Vec::new();
            encode(
                &mut out,
                true,
                CLOSE,
                &[&b"\x03\xe8"[..], reason.as_bytes()].concat(),
                None,
            );
            out
        }),
    );
    assert_eq!(status(&opened.reply), 101, "{:?}", opened.reply);
    assert_eq!(opened.client.recv().payload, b"\x03\xe8");
}

/// LIVE GAP: the scrub reads one server message at a time, so a secret that the server splits
/// across two messages reaches the workload in two parts.
#[test]
fn a_secret_split_across_two_server_messages_is_not_redacted() {
    let mut opened = open_credentialed(
        "split.ws.test",
        Answer::Script(|head| {
            let secret = secret_from(head);
            let (first, second) = secret.split_at(8);
            let mut out = Vec::new();
            encode(&mut out, true, TEXT, first.as_bytes(), None);
            encode(&mut out, true, TEXT, second.as_bytes(), None);
            out
        }),
    );
    assert_eq!(status(&opened.reply), 101, "{:?}", opened.reply);
    let joined = [opened.client.recv().payload, opened.client.recv().payload].concat();
    assert_eq!(joined, SECRET.as_bytes());
}

/// With no credential route on the destination, a server message that holds the secret's text
/// passes unchanged: the scrub reads only the server messages of a credentialed handshake.
#[test]
fn a_server_message_to_a_destination_with_no_route_passes_unchanged() {
    let host = "noroute.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(Some("sk_live_REALSECRET")));
    let handle = plain_gateway(host, &upstream);
    let (mut client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 101, "{reply:?}");
    assert_eq!(client.recv().payload, SECRET.as_bytes());
    client.close();
}

/// The SigV4 signature the upstream receives verifies over the headers the upstream receives.
#[test]
fn a_sigv4_route_signs_the_handshake_and_the_relay_carries_frames() {
    let secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let _env = harness::AwsEnvGuard::set("AKIDEXAMPLE", secret_key, Some("session-EXAMPLE"));
    let host = "bedrock-agentcore.us-west-2.amazonaws.com";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let port = upstream.port;
    let source = Locator::structured(
        [("source".to_string(), "aws".to_string())]
            .into_iter()
            .collect(),
    )
    .unwrap();
    let store = Vault::open(
        VaultConfig::new(Backend::local(), "t")
            .route(RouteSpec::signed_aws(pattern(host, port), source)),
    )
    .unwrap()
    .into_vault();
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(
            pattern(host, port),
            Arc::new(store),
        ))
        .build();
    let handle = credential_gateway(host, &upstream, controls);

    let (mut client, reply) = WsClient::open(
        &handle,
        host,
        port,
        "Authorization: AWS4-HMAC-SHA256 Credential=DUMMY/x, SignedHeaders=host, Signature=dead\r\n\
         X-Amz-Date: 19700101T000000Z\r\nSec-WebSocket-Protocol: chat\r\n",
    );
    assert_eq!(status(&reply), 101, "{reply:?}");

    let handshake = &upstream.handshakes()[0];
    let authorization = header(handshake, "authorization").unwrap();
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
            && authorization.contains("/us-west-2/bedrock-agentcore/aws4_request"),
        "{authorization}"
    );
    let signed = signed_headers(&authorization);
    for name in [
        "host",
        "sec-websocket-key",
        "sec-websocket-protocol",
        "sec-websocket-version",
        "x-amz-date",
        "x-amz-security-token",
    ] {
        assert!(signed.contains(&name), "{name} is signed: {signed:?}");
    }
    for name in ["upgrade", "connection", "content-length"] {
        assert!(!signed.contains(&name), "{name} is not signed: {signed:?}");
    }
    assert_eq!(header(handshake, "upgrade").as_deref(), Some("websocket"));
    assert_eq!(header(handshake, "connection").as_deref(), Some("Upgrade"));
    assert_eq!(header(handshake, "content-length"), None);
    assert!(!handshake.contains("Signature=dead") && !handshake.contains(secret_key));
    assert!(
        sigv4_verifies(handshake, secret_key, "us-west-2", "bedrock-agentcore"),
        "the signature covers the handshake as the upstream received it: {handshake}"
    );
    assert!(
        !sigv4_verifies(
            &handshake.replace(KEY, "AAAAAAAAAAAAAAAAAAAAAA=="),
            secret_key,
            "us-west-2",
            "bedrock-agentcore"
        ),
        "the check fails for a handshake the signature does not cover"
    );

    client.send(TEXT, b"signed");
    assert_eq!(client.recv().payload, b"signed");
}

fn signed_headers(authorization: &str) -> Vec<&str> {
    authorization
        .split("SignedHeaders=")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .unwrap()
        .split(';')
        .collect()
}

/// Recompute SigV4 over a received GET head with no body, and compare it with its `Authorization`.
fn sigv4_verifies(head: &str, secret_key: &str, region: &str, service: &str) -> bool {
    use ring::{digest, hmac};
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let mac = |key: &[u8], data: &[u8]| {
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
            .as_ref()
            .to_vec()
    };
    let authorization = header(head, "authorization").unwrap();
    let signed = signed_headers(&authorization);
    let signature = authorization.rsplit("Signature=").next().unwrap();
    let amz_date = header(head, "x-amz-date").unwrap();
    let path = head.split_whitespace().nth(1).unwrap();
    let canonical_headers: String = signed
        .iter()
        .map(|name| format!("{name}:{}\n", header(head, name).unwrap()))
        .collect();
    let canonical_request = format!(
        "GET\n{path}\n\n{canonical_headers}\n{}\n{}",
        signed.join(";"),
        hex(digest::digest(&digest::SHA256, b"").as_ref())
    );
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(digest::digest(&digest::SHA256, canonical_request.as_bytes()).as_ref())
    );
    let key = mac(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let key = mac(&key, region.as_bytes());
    let key = mac(&key, service.as_bytes());
    let key = mac(&key, b"aws4_request");
    hex(&mac(&key, string_to_sign.as_bytes())) == signature
}

// ============================================================================================
// The 101 as accepted
// ============================================================================================

#[test]
fn a_101_that_does_not_answer_the_handshake_is_refused() {
    for (answer, reason) in [
        (
            Answer::WrongAccept,
            "websocket: 101 carries a wrong Sec-WebSocket-Accept",
        ),
        (
            Answer::AcceptWith("Sec-WebSocket-Extensions: permessage-deflate\r\n"),
            "websocket: 101 negotiates an extension",
        ),
        (
            Answer::AcceptWith("Sec-WebSocket-Protocol: unoffered\r\n"),
            "websocket: 101 selects a subprotocol the request did not offer",
        ),
    ] {
        let host = "refused101.ws.test";
        let upstream = WsUpstream::start(host, answer);
        let handle = plain_gateway(host, &upstream);

        let (_client, reply) = WsClient::open(&handle, host, upstream.port, "");
        assert_eq!(status(&reply), 502, "{reason}: {reply:?}");
        assert!(reply.ends_with("WebSocket upgrade response refused"));
        assert!(header(&reply, egress_gateway::PROXY_ORIGIN_HEADER).is_some());
        assert!(
            denials(&handle).iter().any(|denial| denial == reason),
            "{reason}"
        );
    }
}

#[test]
fn a_non_101_answer_to_a_handshake_is_relayed() {
    let host = "unauthorized.ws.test";
    let upstream = WsUpstream::start(
        host,
        Answer::Fixed("HTTP/1.1 401 Unauthorized\r\nContent-Length: 6\r\n\r\nno key"),
    );
    let handle = plain_gateway(host, &upstream);

    let (_client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 401, "{reply:?}");
    assert!(reply.ends_with("no key"));
    assert_eq!(header(&reply, "connection").as_deref(), Some("close"));
    assert_eq!(header(&reply, egress_gateway::PROXY_ORIGIN_HEADER), None);
}

/// F6: a 101 to a request that did not ask to upgrade ends with EOF and one `Deny`, as before.
#[test]
fn a_101_to_a_request_that_asked_for_no_upgrade_is_refused() {
    let host = "unasked.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let (handle, emitter) = recording_gateway(host, &upstream);

    let mut client = WsClient::connect(&handle, host, upstream.port);
    let reply = client.request(&format!(
        "GET /chat HTTP/1.1\r\nHost: {host}:{}\r\n\r\n",
        upstream.port
    ));
    assert_eq!(reply, "", "no reply byte reaches the workload");
    assert_eq!(
        emitted_denials(&emitter),
        vec![(
            "GET".to_string(),
            "/chat".to_string(),
            "the reply was refused: the gateway does not accept its head, framing, or upgrade"
                .to_string()
        )]
    );
    drop(handle);
}

// ============================================================================================
// Limits, slots, and the end of a session
// ============================================================================================

#[test]
fn an_idle_websocket_is_closed_with_1001() {
    let host = "idle.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = start_gateway(
        host,
        &upstream,
        PathPolicy::permitting(host),
        MitmConfig {
            upstream_read_deadline: Duration::from_secs(1),
            ..MitmConfig::default()
        },
    );
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");
    let opened = Instant::now();

    let close = client.recv();
    assert_eq!(close.close_code(), 1001);
    assert!(
        opened.elapsed() >= Duration::from_millis(900),
        "{:?}",
        opened.elapsed()
    );
    assert_eq!(client.read_end().unwrap(), 0);
    assert_eq!(upstream.frames(1)[0].close_code(), 1001);
}

#[test]
fn traffic_past_the_old_total_deadline_survives() {
    let host = "steady.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let deadline = Duration::from_secs(1);
    let handle = start_gateway(
        host,
        &upstream,
        PathPolicy::permitting(host),
        MitmConfig {
            upstream_read_deadline: deadline,
            ..MitmConfig::default()
        },
    );
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");
    let opened = Instant::now();

    for index in 0..12 {
        std::thread::sleep(Duration::from_millis(250));
        let message = format!("tick {index}");
        client.send(TEXT, message.as_bytes());
        let echoed = client.recv();
        assert_eq!(echoed.opcode, TEXT, "tick {index}: {echoed:?}");
        assert_eq!(echoed.payload, message.as_bytes());
    }
    assert!(opened.elapsed() > deadline * 2, "{:?}", opened.elapsed());
}

/// The idle limit counts a byte in either direction: a server that streams to a silent client
/// keeps the session open past the limit.
#[test]
fn a_silent_client_does_not_close_a_streaming_server_before_the_idle_limit() {
    let host = "streaming.ws.test";
    let upstream = WsUpstream::start(host, Answer::Talk(12, Duration::from_millis(250)));
    let deadline = Duration::from_secs(1);
    let handle = start_gateway(
        host,
        &upstream,
        PathPolicy::permitting(host),
        MitmConfig {
            upstream_read_deadline: deadline,
            ..MitmConfig::default()
        },
    );
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");
    let opened = Instant::now();

    for index in 0..12 {
        let tick = client.recv();
        assert_eq!(
            (tick.opcode, tick.payload),
            (TEXT, format!("tick {index}").into_bytes())
        );
    }
    assert!(opened.elapsed() > deadline * 2, "{:?}", opened.elapsed());
}

#[test]
fn a_message_above_the_cap_closes_with_1009() {
    let host = "cap.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = start_gateway(
        host,
        &upstream,
        PathPolicy::permitting(host),
        MitmConfig {
            response_limits: ResponseLimits {
                max_body_bytes: 16 * 1024,
            },
            ..MitmConfig::default()
        },
    );
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    client.send(BINARY, &[7u8; 16 * 1024]);
    assert_eq!(
        client.recv().payload.len(),
        16 * 1024,
        "the cap itself passes"
    );
    client.send(BINARY, &[7u8; 20 * 1024]);
    assert_eq!(client.recv().close_code(), 1009);

    let frames = upstream.frames(2);
    assert_eq!(frames.len(), 2, "{frames:?}");
    assert_eq!(frames[1].close_code(), 1001, "the upstream gets 1001");
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: client message exceeds the size limit")
    );
}

/// The workload gets 1014, not the 1001 a client library reads as a clean close, when the gateway
/// drops a server message.
#[test]
fn a_server_message_above_the_cap_closes_the_workload_with_1014() {
    let host = "servercap.ws.test";
    let upstream = WsUpstream::start(host, Answer::Burst(1, 20 * 1024));
    let handle = start_gateway(
        host,
        &upstream,
        PathPolicy::permitting(host),
        MitmConfig {
            response_limits: ResponseLimits {
                max_body_bytes: 16 * 1024,
            },
            ..MitmConfig::default()
        },
    );
    let (mut client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 101, "{reply:?}");

    assert_eq!(client.recv().close_code(), 1014);
    assert_eq!(upstream.frames(1)[0].close_code(), 1009);
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: server message exceeds the size limit")
    );
}

#[test]
fn an_unmasked_client_frame_closes_with_1002() {
    let host = "unmasked.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = plain_gateway(host, &upstream);
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    let mut unmasked = Vec::new();
    encode(&mut unmasked, true, TEXT, b"plain", None);
    client.send_raw(&unmasked);
    assert_eq!(client.recv().close_code(), 1002);

    let frames = upstream.frames(1);
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(
        frames[0].close_code(),
        1001,
        "no message reached the upstream"
    );
    let reasons = denials(&handle);
    assert!(
        reasons
            .iter()
            .any(|reason| reason == "websocket: client frame not masked"),
        "{reasons:?}"
    );
    assert!(
        reasons.iter().all(|reason| !reason.contains("plain")),
        "no payload byte reaches the audit"
    );
}

#[test]
fn a_client_text_message_not_utf8_closes_with_1007() {
    let host = "clientutf8.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = plain_gateway(host, &upstream);
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    client.send(TEXT, &[0xFF, 0xFE]);
    assert_eq!(client.recv().close_code(), 1007);

    let frames = upstream.frames(1);
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0].close_code(), 1001, "the upstream gets 1001");
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: client text message not UTF-8")
    );
}

/// The server sent a masked frame, which RFC 6455 forbids: the server gets 1002, and the workload
/// 1014.
#[test]
fn a_server_frame_that_breaks_a_rule_closes_the_workload_with_1014() {
    let host = "servermask.ws.test";
    let upstream = WsUpstream::start(
        host,
        Answer::Script(|_| {
            let mut out = Vec::new();
            encode(&mut out, true, TEXT, b"masked", Some([1, 2, 3, 4]));
            out
        }),
    );
    let handle = plain_gateway(host, &upstream);
    let (mut client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 101, "{reply:?}");

    assert_eq!(client.recv().close_code(), 1014);
    assert_eq!(upstream.frames(1)[0].close_code(), 1002);
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: server frame masked")
    );
}

#[test]
fn a_server_text_message_not_utf8_closes_the_workload_with_1014() {
    let host = "serverutf8.ws.test";
    let upstream = WsUpstream::start(
        host,
        Answer::Script(|_| {
            let mut out = Vec::new();
            encode(&mut out, true, TEXT, &[0xC3, 0x28], None);
            out
        }),
    );
    let handle = plain_gateway(host, &upstream);
    let (mut client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 101, "{reply:?}");

    assert_eq!(client.recv().close_code(), 1014);
    assert_eq!(upstream.frames(1)[0].close_code(), 1007);
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: server text message not UTF-8")
    );
}

#[test]
fn gateway_shutdown_closes_an_open_websocket_with_1001() {
    let host = "shutdown.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = plain_gateway(host, &upstream);
    let (mut client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 101, "{reply:?}");

    let stopped = Instant::now();
    drop(handle);
    assert_eq!(client.recv().close_code(), 1001);
    assert_eq!(client.read_end().unwrap(), 0);
    assert_eq!(upstream.frames(1)[0].close_code(), 1001);
    assert!(
        stopped.elapsed() < Duration::from_secs(5),
        "{:?}",
        stopped.elapsed()
    );
}

/// An open WebSocket holds its connection slot until it closes: with two slots, a WebSocket and
/// a connection that sends nothing leave a third connection unserved.
#[test]
fn the_slot_stays_held_while_a_websocket_is_open() {
    let host = "slot.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let handle = start_gateway(
        host,
        &upstream,
        PathPolicy::permitting(host),
        MitmConfig {
            max_connections: 2,
            ..MitmConfig::default()
        },
    );
    let (client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 101, "{reply:?}");
    let _silent = TcpStream::connect(("127.0.0.1", handle.port().unwrap())).unwrap();
    std::thread::sleep(Duration::from_millis(100));

    let mut third = TcpStream::connect(("127.0.0.1", handle.port().unwrap())).unwrap();
    let authority = format!("{host}:{}", upstream.port);
    third
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .unwrap();
    third
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    assert!(
        third.read(&mut [0u8; 64]).is_err(),
        "no slot is free while the WebSocket is open"
    );

    client.close();
    third
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert!(
        read_head(&mut third).contains("200 Connection Established"),
        "the slot frees when the WebSocket closes"
    );
}

/// Open WebSockets hold at most three quarters of the connection slots; a handshake past that
/// share gets a 503, on a slot that stays free for ordinary requests.
#[test]
fn open_websockets_hold_at_most_three_quarters_of_the_slots() {
    let host = "share.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(
        host,
        &upstream,
        policy.clone(),
        MitmConfig {
            max_connections: 4,
            ..MitmConfig::default()
        },
    );
    let mut open = Vec::new();
    for _ in 0..3 {
        let (client, reply) = WsClient::open(&handle, host, upstream.port, "");
        assert_eq!(status(&reply), 101, "{reply:?}");
        open.push(client);
    }

    let (_refused, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 503, "{reply:?}");
    assert!(
        reply.ends_with("WebSocket session limit reached"),
        "{reply:?}"
    );
    assert!(header(&reply, egress_gateway::PROXY_ORIGIN_HEADER).is_some());
    assert!(denials(&handle).iter().any(|reason| reason
        == "websocket: the open WebSockets hold their share of the connection slots"));
    assert_eq!(
        policy.requests().len(),
        3,
        "the refusal comes before policy"
    );

    open.pop().unwrap().close();
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let (_client, reply) = WsClient::open(&handle, host, upstream.port, "");
        if status(&reply) == 101 {
            break;
        }
        assert!(Instant::now() < until, "the session slot frees: {reply:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ============================================================================================
// A refusal after the handshake reaches the decision emitter
// ============================================================================================

#[test]
fn a_relay_refusal_is_emitted_as_a_deny_decision() {
    let host = "emitrelay.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let (handle, emitter) = recording_gateway(host, &upstream);
    let (mut client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 101, "{reply:?}");

    let mut unmasked = Vec::new();
    encode(&mut unmasked, true, TEXT, b"plain", None);
    client.send_raw(&unmasked);
    assert_eq!(client.recv().close_code(), 1002);
    upstream.frames(1);

    let records = emitter.records();
    assert!(
        records
            .iter()
            .any(|record| record.decision == AuditDecision::Allow && record.method == "GET"),
        "the handshake's allow comes first: {records:?}"
    );
    assert_eq!(
        emitted_denials(&emitter),
        vec![(
            "GET".to_string(),
            "/chat".to_string(),
            "websocket: client frame not masked".to_string()
        )],
        "one deny names the exchange and the fault, and no payload byte"
    );
}

#[test]
fn a_refused_101_is_emitted_as_a_deny_decision() {
    let host = "emit101.ws.test";
    let upstream = WsUpstream::start(host, Answer::WrongAccept);
    let (handle, emitter) = recording_gateway(host, &upstream);

    let (_client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 502, "{reply:?}");
    assert_eq!(
        emitted_denials(&emitter),
        vec![(
            "GET".to_string(),
            "/chat".to_string(),
            "websocket: 101 carries a wrong Sec-WebSocket-Accept".to_string()
        )]
    );
}

#[test]
fn a_clean_close_emits_no_deny_decision() {
    let host = "emitclose.ws.test";
    let upstream = WsUpstream::start(host, Answer::Echo(None));
    let (handle, emitter) = recording_gateway(host, &upstream);
    let (mut client, _) = WsClient::open(&handle, host, upstream.port, "");

    client.send(CLOSE, b"\x03\xe8bye");
    assert_eq!(client.recv().close_code(), 1000);
    assert_eq!(client.read_end().unwrap(), 0);
    upstream.frames(1);

    assert_eq!(emitted_denials(&emitter), Vec::new());
}

// ============================================================================================
// A WebSocket on a kept-alive connection
// ============================================================================================

/// **A WebSocket opens as a later request on a kept-alive tunnel, and the upgraded connection
/// never carries HTTP again.** Request 1 is an ordinary `GET` whose reply keeps the tunnel open.
/// Request 2 on the same tunnel is a handshake: it opens its own governed upstream socket, with its
/// own `Resolve` and `Connect`, and gets the `101`. Messages then cross the relay. An HTTP head
/// that the workload sends after the `101` is a frame to the relay, which breaks RFC 6455: the
/// workload gets 1002 and the end of the tunnel, and no upstream sees a third request.
#[test]
fn a_websocket_opens_on_a_kept_alive_tunnel_and_the_connection_never_carries_http_again() {
    let host = "kept.ws.test";
    let upstream = WsUpstream::start(host, Answer::OkOrEcho);
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(host, &upstream, policy.clone(), MitmConfig::default());
    let mut client = WsClient::connect(&handle, host, upstream.port);

    let first = format!(
        "GET /first HTTP/1.1\r\nHost: {host}:{}\r\n\r\n",
        upstream.port
    );
    let reply = client.request(&first);
    assert_eq!(status(&reply), 200, "{reply:?}");
    assert!(reply.ends_with("ok"), "{reply:?}");
    assert_eq!(
        header(&reply, "connection"),
        None,
        "the first reply keeps the tunnel open"
    );

    let switching = client.request(&handshake_head(host, upstream.port, ""));
    assert!(
        switching.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{switching:?}"
    );
    client.send(TEXT, b"hello");
    assert_eq!(client.recv().payload, b"hello");

    client.send_raw(first.as_bytes());
    assert_eq!(client.recv().close_code(), 1002);
    assert_eq!(client.read_end().unwrap(), 0, "the tunnel ends");

    let heads = upstream.handshakes();
    assert_eq!(heads.len(), 2, "{heads:?}");
    assert!(heads[0].starts_with("GET /first "), "{heads:?}");
    assert!(heads[1].starts_with("GET /chat "), "{heads:?}");
    assert_eq!(
        policy.kinds(),
        vec![
            "Resolve",
            "Connect",
            "HttpRequest",
            "ResponseRelease",
            "Resolve",
            "Connect",
            "HttpRequest",
            "ResponseRelease",
        ],
        "each request opens its own governed socket"
    );
    assert_eq!(
        policy.requests(),
        vec!["request GET /first", "request GET /chat"]
    );
    let log = policy.log();
    let release = log
        .iter()
        .position(|entry| entry == "release status=101")
        .expect("the 101 is released");
    assert_eq!(
        log[release + 1],
        format!("outcome Completed({})", switching.len()),
        "the release of the 101 counts the bytes of the 101 only: {log:?}"
    );
}
