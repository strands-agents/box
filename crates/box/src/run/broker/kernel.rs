//! Bind backend callbacks to one immutable Call context, and send HTTP through the egress gateway
//! (docs/design/decisions.md#shell-network-goes-through-the-egress-gateway).

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use strands_shell::os::{
    DirEntry, Fd, FileStat, Follow, HostSpawn, HostSpawnOutcome, HttpRequest, HttpResponse, Kernel,
    OpenFlags, Process, Resolved, ScriptOutcome, WriteFailure,
};

use crate::run::broker::shell::EgressRouting;

pub(super) struct CallKernel {
    backend: Arc<dyn Kernel>,
    correlation: telemetry::Correlation,
    egress: Option<EgressRouting>,
}

impl CallKernel {
    /// Share the backend while retaining this Call's correlation and the box's gateway route.
    pub(super) fn new(
        backend: Arc<dyn Kernel>,
        correlation: telemetry::Correlation,
        egress: Option<EgressRouting>,
    ) -> Self {
        Self {
            backend,
            correlation,
            egress,
        }
    }

    fn route(&self, url: &str) -> io::Result<&EgressRouting> {
        let egress = self.egress.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "network access disabled")
        })?;
        strands_shell::vfs_kernel::check_url_safe(url)?;
        Ok(egress)
    }
}

/// Refuse a gateway CA that no client can trust.
pub(super) fn verify_gateway_ca(egress: &EgressRouting) -> io::Result<()> {
    gateway_client(egress)
        .map(drop)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// A client that dials only the gateway, trusts only its CA, and follows no redirect.
fn gateway_client(egress: &EgressRouting) -> io::Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .proxy(reqwest::Proxy::all(&egress.proxy_target).map_err(io::Error::other)?)
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&egress.ca_pem).map_err(io::Error::other)?,
        )
        .build()
        .map_err(io::Error::other)
}

/// Send one request through the gateway, which alone decides it; `req.insecure` is not read.
async fn send(egress: &EgressRouting, req: HttpRequest) -> io::Result<HttpResponse> {
    let method: reqwest::Method = req.method.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bad HTTP method: {}", req.method),
        )
    })?;
    let mut request = gateway_client(egress)?.request(method, &req.url);
    for (name, value) in &req.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if let Some(body) = req.body {
        request = request.body(body);
    }
    let mut response = request
        .send()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;

    if response
        .headers()
        .contains_key(egress_gateway::PROXY_ORIGIN_HEADER)
    {
        let reason = response.text().await.unwrap_or_default();
        let reason = reason
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("the egress gateway refused this request");
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }

    let status = response.status();
    let version = match response.version() {
        reqwest::Version::HTTP_2 => "2",
        reqwest::Version::HTTP_11 => "1.1",
        _ => "1.0",
    };
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
        if req.max_response > 0 && body.len() + chunk.len() > req.max_response {
            return Err(io::Error::other("response body too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(HttpResponse {
        status: status.as_u16(),
        headers,
        body,
        version: version.to_string(),
        reason: status.canonical_reason().unwrap_or("").to_string(),
    })
}

#[async_trait::async_trait]
impl Kernel for CallKernel {
    async fn resolve(&self, proc: &Process, path: &str, follow: Follow) -> Resolved {
        self.backend.resolve(proc, path, follow).await
    }

    fn new_process(&self) -> Process {
        self.backend.new_process()
    }

    async fn open(&self, proc: &mut Process, path: Resolved, flags: OpenFlags) -> io::Result<Fd> {
        self.backend.open(proc, path, flags).await
    }

    async fn list_dir(&self, proc: &Process, path: Resolved) -> io::Result<Vec<DirEntry>> {
        self.backend.list_dir(proc, path).await
    }

    async fn change_dir(&self, proc: &mut Process, path: Resolved) -> io::Result<()> {
        self.backend.change_dir(proc, path).await
    }

    async fn stat(&self, proc: &Process, path: Resolved) -> FileStat {
        self.backend.stat(proc, path).await
    }

    async fn lstat(&self, proc: &Process, path: Resolved) -> FileStat {
        self.backend.lstat(proc, path).await
    }

    async fn access(&self, proc: &Process, path: Resolved, mode: i32) -> bool {
        self.backend.access(proc, path, mode).await
    }

    async fn stat_answer(&self, proc: &Process, path: Resolved) -> io::Result<FileStat> {
        self.backend.stat_answer(proc, path).await
    }

    async fn lstat_answer(&self, proc: &Process, path: Resolved) -> io::Result<FileStat> {
        self.backend.lstat_answer(proc, path).await
    }

    async fn access_answer(&self, proc: &Process, path: Resolved, mode: i32) -> io::Result<bool> {
        self.backend.access_answer(proc, path, mode).await
    }

    async fn canonicalize(&self, proc: &Process, path: Resolved) -> io::Result<PathBuf> {
        self.backend.canonicalize(proc, path).await
    }

    async fn is_executable(&self, proc: &Process, path: Resolved) -> bool {
        self.backend.is_executable(proc, path).await
    }

    async fn glob(&self, proc: &Process, pattern: &str) -> Vec<String> {
        self.backend.glob(proc, pattern).await
    }

    fn isatty(&self, fd: i32) -> bool {
        self.backend.isatty(fd)
    }

    async fn remove_file(&self, proc: &Process, path: Resolved) -> io::Result<()> {
        self.backend.remove_file(proc, path).await
    }

    async fn remove_dir(&self, proc: &Process, path: Resolved) -> io::Result<()> {
        self.backend.remove_dir(proc, path).await
    }

    async fn create_dir(&self, proc: &Process, path: Resolved) -> io::Result<()> {
        self.backend.create_dir(proc, path).await
    }

    async fn rename(&self, proc: &Process, from: Resolved, to: Resolved) -> io::Result<()> {
        self.backend.rename(proc, from, to).await
    }

    async fn symlink(&self, proc: &Process, target: &str, link: Resolved) -> io::Result<()> {
        self.backend.symlink(proc, target, link).await
    }

    async fn read_link(&self, proc: &Process, path: Resolved) -> io::Result<String> {
        self.backend.read_link(proc, path).await
    }

    async fn set_permissions(&self, proc: &Process, path: Resolved, mode: u32) -> io::Result<()> {
        self.backend.set_permissions(proc, path, mode).await
    }

    fn now(&self) -> SystemTime {
        self.backend.now()
    }

    async fn settle_writes(&self) -> Vec<WriteFailure> {
        self.backend.settle_writes().await
    }

    fn check_url(&self, url: &str) -> io::Result<()> {
        self.route(url).map(drop)
    }

    async fn http_request(&self, mut req: HttpRequest) -> io::Result<HttpResponse> {
        let egress = self.route(&req.url)?;
        self.correlation.inject_http(&mut req.headers);
        self.correlation.scope(send(egress, req)).await
    }

    async fn run_script(&self, source: String) -> io::Result<ScriptOutcome> {
        self.correlation
            .scope(self.backend.run_script(source))
            .await
    }

    async fn spawn_host(&self, spawn: HostSpawn) -> io::Result<HostSpawnOutcome> {
        self.correlation.scope(self.backend.spawn_host(spawn)).await
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;

    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration;

    use strands_shell::Shell;
    use strands_shell::vfs_config::{VfsConfig, build_vfs};
    use strands_shell::vfs_kernel::VfsKernel;

    fn read_head(stream: &mut impl std::io::Read) {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") && matches!(stream.read(&mut byte), Ok(1)) {
            head.push(byte[0]);
        }
    }

    /// A self-signed certificate for `a.example` and its PEM.
    fn certificate() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        rcgen::generate_simple_self_signed(vec!["a.example".to_string()]).expect("a certificate")
    }

    /// A fake gateway that answers each connection with `response`, and reports each connection.
    fn gateway(response: &'static str) -> (EgressRouting, mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake gateway");
        let address = listener.local_addr().expect("the gateway has an address");
        let (seen, connections) = mpsc::channel();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let _ = seen.send(());
                read_head(&mut stream);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        let routing = EgressRouting {
            proxy_target: format!("http://{address}"),
            ca_pem: Arc::new(certificate().cert.pem().into_bytes()),
        };
        (routing, connections)
    }

    fn run(egress: Option<EgressRouting>, command: &str) -> (i32, String, String) {
        let mut backend = VfsKernel::new(build_vfs(&VfsConfig::default()).expect("a VFS"));
        backend.network_enabled = false;
        let kernel = CallKernel::new(
            Arc::new(backend),
            telemetry::Correlation::from_headers(None, None),
            egress,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let local = tokio::task::LocalSet::new();
        runtime.block_on(local.run_until(async {
            let mut shell = Shell::builder()
                .kernel(Arc::new(kernel))
                .build()
                .expect("a Shell builds");
            let output = shell.run(command).await;
            (output.status, output.stdout, output.stderr)
        }))
    }

    #[test]
    fn with_no_gateway_every_request_is_refused() {
        let (status, _stdout, stderr) = run(None, "curl -sS https://a.example/");

        assert_eq!(status, 1, "{stderr}");
        assert!(stderr.contains("network access disabled"), "{stderr}");
    }

    #[test]
    fn a_marked_refusal_fails_curl() {
        let (routing, _connections) = gateway(
            "HTTP/1.1 403 Forbidden\r\nx-strands-box-egress: refused\r\nContent-Length: 13\r\n\
             Connection: close\r\n\r\npolicy denied",
        );

        let (status, stdout, stderr) = run(Some(routing), "curl -sS http://a.example/");

        assert_eq!(status, 1, "{stdout} {stderr}");
        assert!(stderr.contains("policy denied"), "{stderr}");
        assert!(!stdout.contains("policy denied"), "{stdout}");
    }

    #[test]
    fn a_private_address_is_refused_before_transport() {
        let (routing, connections) =
            gateway("HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nLEAKED");

        let (_status, stdout, stderr) = run(
            Some(routing),
            "curl -sS http://169.254.169.254/; echo \" status=$?\"\n\
             curl -sS http://127.0.0.1/; echo \" status=$?\"",
        );

        assert_eq!(stdout.matches(" status=1").count(), 2, "{stdout} {stderr}");
        assert!(!stdout.contains("LEAKED"), "{stdout}");
        assert!(
            connections
                .recv_timeout(Duration::from_millis(300))
                .is_err(),
            "no private address reaches the gateway"
        );
    }

    #[test]
    fn a_redirect_hop_meets_the_floor_in_the_wrapper() {
        let (routing, connections) = gateway(
            "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n",
        );

        let (status, stdout, stderr) = run(Some(routing), "curl -sSL http://a.example/");

        assert_eq!(status, 1, "{stdout} {stderr}");
        assert!(stderr.contains("169.254.169.254"), "{stderr}");
        assert!(connections.recv_timeout(Duration::from_secs(5)).is_ok());
        assert!(
            connections
                .recv_timeout(Duration::from_millis(300))
                .is_err(),
            "the private hop never reaches the gateway"
        );
    }

    #[test]
    fn insecure_does_not_widen_trust() {
        let leaf = certificate();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf.signing_key.serialize_der().into());
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![leaf.cert.der().clone()], key)
                .expect("server TLS config"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake gateway");
        let address = listener.local_addr().expect("the gateway has an address");
        let (tunnel, tunnelled) = mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            read_head(&mut stream);
            let _ = tunnel.send(());
            let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
            let mut tls = rustls::StreamOwned::new(
                rustls::ServerConnection::new(config).expect("a TLS server"),
                stream,
            );
            read_head(&mut tls);
            let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTRUSTED");
        });
        let routing = EgressRouting {
            proxy_target: format!("http://{address}"),
            ca_pem: Arc::new(certificate().cert.pem().into_bytes()),
        };

        let (status, stdout, stderr) = run(Some(routing), "curl -sSk https://a.example/");

        assert_ne!(status, 0, "{stdout} {stderr}");
        assert!(!stdout.contains("TRUSTED"), "{stdout}");
        assert!(
            tunnelled.recv_timeout(Duration::from_secs(5)).is_ok(),
            "the request reached the gateway and failed at its certificate"
        );
    }
}
