//! Test harness for the full-interception E2E: a real TLS upstream, a real TLS workload client that
//! trusts the proxy's ephemeral CA, and a serialized AWS-env guard.
//!
//! Kept in a `mod harness` shared file so each `#[test]` reads as the four goal steps. Everything is
//! synchronous (matching the adapter's thread-per-connection model) and self-contained.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConnection, ServerConnection, StreamOwned};

/// A request the upstream saw on the wire, captured for assertions.
#[derive(Debug, Clone, Default)]
pub struct SeenRequest {
    /// The full raw request head + body as received (plaintext, post-decryption at the upstream).
    pub raw: String,
}

impl SeenRequest {
    /// The value of header `name` (case-insensitive), if present.
    pub fn header(&self, name: &str) -> Option<String> {
        for line in self.raw.split("\r\n") {
            if let Some((n, v)) = line.split_once(':')
                && n.trim().eq_ignore_ascii_case(name)
            {
                return Some(v.trim().to_string());
            }
        }
        None
    }
}

/// A local TLS upstream server: presents a self-signed cert for a host, records the requests it
/// receives, and replies `200 OK`. The proxy trusts its CA via `MitmConfig::upstream_ca_pems`.
/// How a fixture upstream answers a request.
#[derive(Clone)]
enum Reply {
    Whole(Arc<[u8]>),
    Drip(Arc<[u8]>, Duration),
    Silent,
    Deaf,
    Sip(Duration),
}

pub struct TlsUpstream {
    port: u16,
    ca_pem: String,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
}

impl TlsUpstream {
    /// Start a TLS upstream presenting a cert valid for `host` (and `localhost`), on an ephemeral
    /// loopback port. Serves connections on a background thread until the process exits.
    pub fn start(host: &str) -> Self {
        Self::start_with_response(
            host,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
    }

    /// Start a TLS upstream that returns a chunked response with hop-by-hop fields.
    pub fn start_chunked(host: &str) -> Self {
        Self::start_with_response(
            host,
            concat!(
                "HTTP/1.1 200 OK\r\n",
                "Transfer-Encoding: chunked\r\n",
                "Connection: close, X-Upstream-Hop\r\n",
                "X-Upstream-Hop: remove-me\r\n",
                "Trailer: Digest\r\n",
                "\r\n",
                "7;source=mantle\r\n",
                "mantle-\r\n",
                "9\r\n",
                "stream-ok\r\n",
                "0\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
    }

    /// Start a TLS upstream that returns the supplied static HTTP response.
    pub fn start_with_response(host: &str, response: &'static [u8]) -> Self {
        Self::start_serving(host, Reply::Whole(Arc::from(response)))
    }

    /// Start a TLS upstream that reads each request and never replies, holding the connection
    /// open until the peer closes it.
    pub fn start_silent(host: &str) -> Self {
        Self::start_serving(host, Reply::Silent)
    }

    /// Start a TLS upstream that writes its response one byte per `interval`.
    pub fn start_dripping(host: &str, response: &'static [u8], interval: Duration) -> Self {
        Self::start_serving(host, Reply::Drip(Arc::from(response), interval))
    }

    /// Start a TLS upstream that completes the handshake and then never reads, so the peer's
    /// send buffers fill and its writes block.
    pub fn start_deaf(host: &str) -> Self {
        Self::start_serving(host, Reply::Deaf)
    }

    /// Start a TLS upstream that reads 64 KiB per `interval` and never replies, so every write
    /// the peer makes progresses while the whole request outlasts a deadline.
    pub fn start_sipping(host: &str, interval: Duration) -> Self {
        Self::start_serving(host, Reply::Sip(interval))
    }

    fn start_serving(host: &str, reply: Reply) -> Self {
        // Self-signed cert valid for the requested host + localhost (the proxy connects by SNI host).
        let sans = vec![host.to_string(), "localhost".to_string()];
        let certified = rcgen::generate_simple_self_signed(sans).unwrap();
        let cert_der = CertificateDer::from(certified.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let ca_pem = certified.cert.pem();

        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<SeenRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_bg = seen.clone();

        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(tcp) = incoming else { continue };
                let config = server_config.clone();
                let seen = seen_bg.clone();
                let reply = reply.clone();
                std::thread::spawn(move || {
                    let Ok(conn) = ServerConnection::new(config) else {
                        return;
                    };
                    let mut tls = StreamOwned::new(conn, tcp);
                    if matches!(reply, Reply::Deaf | Reply::Sip(_)) {
                        while tls.conn.is_handshaking() {
                            if tls.conn.complete_io(&mut tls.sock).is_err() {
                                return;
                            }
                        }
                        let mut probe = [0u8; 1];
                        while matches!(tls.sock.peek(&mut probe), Ok(n) if n > 0) {
                            match &reply {
                                Reply::Sip(interval) => {
                                    let mut chunk = [0u8; 65536];
                                    let mut got = 0;
                                    while got < chunk.len() {
                                        match tls.read(&mut chunk[got..]) {
                                            Ok(n) if n > 0 => got += n,
                                            _ => return,
                                        }
                                    }
                                    std::thread::sleep(*interval);
                                }
                                _ => std::thread::sleep(Duration::from_millis(50)),
                            }
                        }
                        return;
                    }
                    // Read one request head (+ small body) and record it. A bare TLS connection that
                    // closes without sending a request head (e.g. a proxy that connected upstream but
                    // then blocked the request) is NOT counted — only a real request line is.
                    let raw = read_http_head_and_body(&mut tls);
                    if raw.contains("HTTP/") {
                        seen.lock().unwrap().push(SeenRequest { raw });
                        match &reply {
                            Reply::Whole(response) => {
                                let _ = tls.write_all(response);
                                let _ = tls.flush();
                            }
                            Reply::Drip(response, interval) => {
                                for byte in response.iter() {
                                    if tls.write_all(&[*byte]).and_then(|()| tls.flush()).is_err() {
                                        break;
                                    }
                                    std::thread::sleep(*interval);
                                }
                            }
                            Reply::Silent => {
                                let mut sink = [0u8; 1024];
                                while matches!(tls.read(&mut sink), Ok(n) if n > 0) {}
                            }
                            Reply::Deaf | Reply::Sip(_) => {}
                        }
                    }
                });
            }
        });

        Self { port, ca_pem, seen }
    }

    /// The upstream's listening port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The upstream's CA cert PEM, to add to the proxy's additive trust bundle.
    pub fn ca_pem(&self) -> String {
        self.ca_pem.clone()
    }

    /// The most recent request the upstream received (panics if none — the test expected one).
    pub fn last_request(&self) -> SeenRequest {
        // Give the background handler a moment to record the request.
        for _ in 0..50 {
            if let Some(r) = self.seen.lock().unwrap().last().cloned() {
                return r;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("upstream received no request");
    }

    /// How many requests the upstream has received (0 proves a request was blocked before it).
    pub fn request_count(&self) -> usize {
        // Small settle delay so a (possibly in-flight) forward would have landed.
        std::thread::sleep(std::time::Duration::from_millis(50));
        self.seen.lock().unwrap().len()
    }
}

/// A TLS workload client that talks to the upstream *through* the proxy: it `CONNECT`s to the proxy,
/// then performs a TLS handshake trusting the proxy's ephemeral leaf and sends an HTTPS request.
///
/// The proxy mints its leaf under a fresh ephemeral CA per session and we cannot pre-know it, so the
/// client uses a permissive verifier that accepts the proxy's presented cert (a test-only stand-in
/// for "the workload trusts the CA the supervisor installed via `SSL_CERT_FILE`"). This exercises the
/// real TLS termination + evaluate + forward path end-to-end.
pub struct WorkloadClient {
    tls: Option<StreamOwned<ClientConnection, TcpStream>>,
    raw: Option<TcpStream>,
    request_authority: Option<String>,
}

impl WorkloadClient {
    /// CONNECT to the proxy for `sni_host`, tunneling to the upstream on `upstream_port` (loopback),
    /// then TLS-handshake against the proxy's leaf. Used for the plaintext-host scenarios.
    pub fn connect(proxy_port: u16, sni_host: &str, upstream_port: u16) -> Self {
        Self::connect_inner(proxy_port, sni_host, upstream_port)
    }

    /// Same as [`connect`](Self::connect) — a distinct name for the AWS scenario where the SNI host is
    /// the amazonaws name but the tunnel target port is the loopback upstream.
    pub fn connect_to_ip(proxy_port: u16, sni_host: &str, upstream_port: u16) -> Self {
        Self::connect_inner(proxy_port, sni_host, upstream_port)
    }

    fn connect_inner(proxy_port: u16, sni_host: &str, upstream_port: u16) -> Self {
        let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        // CONNECT to <sni_host>:<upstream_port> — the proxy resolves the host and pins; for the test
        // the host resolves to loopback so the tunnel target is our local upstream.
        let authority = format_authority(sni_host, upstream_port);
        let connect = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        tcp.write_all(connect.as_bytes()).unwrap();
        // Read the CONNECT ack (up to the blank line).
        let ack = read_until_blank_line(&mut tcp);
        assert!(
            ack.contains("200 Connection Established"),
            "proxy did not establish the tunnel: {ack:?}"
        );

        // TLS handshake against the proxy's ephemeral leaf, using a permissive verifier.
        let config = permissive_client_config();
        let server_name = ServerName::try_from(sni_host.to_string()).unwrap();
        let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
        let tls = StreamOwned::new(conn, tcp);
        Self {
            tls: Some(tls),
            raw: None,
            request_authority: Some(authority),
        }
    }

    /// A raw (non-TLS) client for CONNECT-refusal scenarios (a policy deny), where the proxy answers
    /// the CONNECT itself and no TLS handshake happens.
    pub fn connect_raw(proxy_port: u16) -> Self {
        let tcp = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        Self {
            tls: None,
            raw: Some(tcp),
            request_authority: None,
        }
    }

    /// Send a `CONNECT host:port` and return the proxy's raw reply (for refusal scenarios).
    pub fn raw_connect(&mut self, host: &str, port: u16) -> String {
        self.raw_connect_authority(&format_authority(host, port))
    }

    /// Send a `CONNECT` for an authority spelled exactly as given and return the proxy's raw reply.
    pub fn raw_connect_authority(&mut self, authority: &str) -> String {
        let tcp = self.raw.as_mut().expect("connect_raw first");
        let connect = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        tcp.write_all(connect.as_bytes()).unwrap();
        read_until_blank_line(tcp)
    }

    /// Send an HTTPS request over the established TLS tunnel.
    pub fn send_request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) {
        let authority = self.request_authority.clone().expect("connect (TLS) first");
        self.send_request_with_authority(method, path, &authority, headers, body);
    }

    /// Send an HTTPS request with an explicit Host authority for negative binding tests.
    pub fn send_request_with_authority(
        &mut self,
        method: &str,
        target: &str,
        authority: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) {
        let tls = self.tls.as_mut().expect("connect (TLS) first");
        let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {authority}\r\n");
        for (n, v) in headers {
            head.push_str(&format!("{n}: {v}\r\n"));
        }
        head.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        ));
        tls.write_all(head.as_bytes()).unwrap();
        tls.write_all(body).unwrap();
        tls.flush().unwrap();
    }

    /// Send a chunked HTTPS request with hop-by-hop fields over the established TLS tunnel.
    pub fn send_chunked_request(&mut self, method: &str, path: &str, body: &[u8]) {
        use std::fmt::Write as _;

        let tls = self.tls.as_mut().expect("connect (TLS) first");
        let authority = self
            .request_authority
            .as_deref()
            .expect("connect (TLS) first");
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {authority}\r\n\
             Transfer-Encoding: chunked\r\n\
             Connection: close, X-Client-Hop\r\n\
             X-Client-Hop: remove-me\r\n\r\n"
        );
        for (index, chunk) in body.chunks(5).enumerate() {
            let extension = if index == 0 { ";source=codex" } else { "" };
            write!(head, "{:X}{extension}\r\n", chunk.len()).unwrap();
            tls.write_all(head.as_bytes()).unwrap();
            head.clear();
            tls.write_all(chunk).unwrap();
            tls.write_all(b"\r\n").unwrap();
        }
        tls.write_all(b"0\r\n\r\n").unwrap();
        tls.flush().unwrap();
    }

    /// Write raw bytes over the established TLS tunnel, exactly as given.
    pub fn send_raw(&mut self, bytes: &[u8]) {
        let tls = self.tls.as_mut().expect("connect (TLS) first");
        tls.write_all(bytes).unwrap();
        tls.flush().unwrap();
    }

    /// Drop the TCP connection to the proxy without a TLS close_notify, as a killed client does.
    pub fn abort(self) {
        if let Some(tls) = self.tls {
            let (_, tcp) = tls.into_parts();
            let _ = tcp.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Read one complete `Content-Length`-framed response from the proxy.
    pub fn read_response(&mut self) -> String {
        let tls = self.tls.as_mut().expect("connect (TLS) first");
        read_http_head_and_body(tls)
    }

    /// Read the response status code the proxy returned over the TLS tunnel.
    pub fn read_status(&mut self) -> u16 {
        parse_status(&self.read_response())
    }
}

/// A serialized guard that sets the ambient `AWS_*` env for the v1 provider and restores it on drop.
pub struct AwsEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

static AWS_ENV_LOCK: Mutex<()> = Mutex::new(());

impl AwsEnvGuard {
    /// Set the ambient AWS credentials for the duration of the guard.
    pub fn set(access_key: &str, secret_key: &str, session_token: Option<&str>) -> Self {
        let lock = AWS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("AWS_ACCESS_KEY_ID", access_key);
            std::env::set_var("AWS_SECRET_ACCESS_KEY", secret_key);
            match session_token {
                Some(t) => std::env::set_var("AWS_SESSION_TOKEN", t),
                None => std::env::remove_var("AWS_SESSION_TOKEN"),
            }
        }
        Self { _lock: lock }
    }
}

impl Drop for AwsEnvGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var("AWS_ACCESS_KEY_ID");
            std::env::remove_var("AWS_SECRET_ACCESS_KEY");
            std::env::remove_var("AWS_SESSION_TOKEN");
        }
    }
}

// ---- helpers ------------------------------------------------------------------------------------

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Read from a plain TCP stream until the `\r\n\r\n` head terminator (bounded).
fn read_until_blank_line(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).unwrap_or(0) == 1 {
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.len() > 16 * 1024 {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Read an HTTP head + Content-Length body from a TLS stream (upstream side), returning the raw text.
fn read_http_head_and_body<S: Read>(stream: &mut S) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    // Head.
    while stream.read(&mut byte).unwrap_or(0) == 1 {
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.len() > 64 * 1024 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    // Body per Content-Length.
    let len = head
        .split("\r\n")
        .find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    if len > 0 {
        let _ = stream.read_exact(&mut body);
    }
    format!("{head}{}", String::from_utf8_lossy(&body))
}

/// Parse the status code from an HTTP response head.
fn parse_status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// A permissive rustls client config that accepts any server cert — a test-only stand-in for the
/// workload trusting the ephemeral CA the supervisor installed. Never used outside tests.
fn permissive_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth()
}

/// A verifier that accepts any certificate (test-only).
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
