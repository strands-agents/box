//! The v1 MITM proxy adapter — the localhost MITM `Interceptor` impl.

mod ca;
mod connect;
mod diagnostic;
mod handle;
mod http1;
mod l7;
mod listener;
mod request_leg;
mod resolve;
mod response_leg;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::ClientConfig;

use self::ca::EphemeralCa;
use self::handle::{BoundTransport, CredentialEnv};
use crate::audit::SharedAuditLog;
use crate::capability::CapabilitySet;
use crate::effect::EffectInterceptor;
use crate::error::{ProxyError, Result};
use crate::intercept::Interceptor;
use crate::seams::{Emitter, StubEmitter};

pub use handle::MitmHandle;

/// Response size/content limits enforced on the response leg.
#[derive(Debug, Clone)]
pub struct ResponseLimits {
    /// Maximum response body bytes buffered before a `ResponseLimit` error.
    pub max_body_bytes: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        // 16 MiB — generous for API responses, bounded so a hostile upstream cannot exhaust memory.
        Self {
            max_body_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Configuration for the MITM adapter.
#[derive(Debug, Clone)]
pub struct MitmConfig {
    /// The TCP address to bind (defaults to `127.0.0.1:0` — an ephemeral localhost port).
    /// Used **only** when [`unix_socket_path`](Self::unix_socket_path) is `None`; in the
    /// AF_UNIX-only pin mode no TCP listener is bound at all and this field is ignored.
    pub bind_addr: SocketAddr,
    /// When `Some(path)`, bind **only** an AF_UNIX socket at `path` and never a `TcpListener`:
    /// the sole reachable egress for a workload contained by the seccomp pin, which cannot create
    /// an `AF_INET` socket to reach a TCP port at all. Defaults to `None` — every existing caller keeps
    /// today's TCP-only behavior unchanged. The socket file is created
    /// mode `0600`; `bind_ports`/DNS-rebind concerns do not apply to a filesystem-scoped socket.
    pub unix_socket_path: Option<PathBuf>,
    /// An optional upstream proxy to forward through (chained egress); `None` connects directly.
    pub external_proxy: Option<SocketAddr>,
    /// Where to write the public ephemeral CA cert; `None` keeps it in memory only.
    pub intercept_ca_dir: Option<PathBuf>,
    /// Whether to offer HTTP/2 on intercepted TLS (h1 + h2 share one evaluate path).
    pub enable_h2: bool,
    /// Response size/content limits.
    pub response_limits: ResponseLimits,
    /// An optional expected proxy session token (best-effort CONNECT check).
    pub expected_token: Option<String>,
    /// Credential env pairs (`*_BASE_URL` / phantom) the supervisor seeds the workload with.
    pub credential_env: Vec<(String, String)>,
    /// Extra CA certificates (PEM) added to the **additive** upstream trust bundle — a
    /// deployment's private CA, or a corporate root the box must trust for the upstream leg. Added on
    /// top of the system roots; never replaces them.
    pub upstream_ca_pems: Vec<String>,
    /// Static host→IP overrides applied at resolve time (a supervisor-provided pinned endpoint map —
    /// split-horizon DNS, or a fixed upstream address). When a host is present here it resolves to the
    /// mapped IP with no DNS lookup; the DNS-rebind pin still holds since the connect uses only
    /// the pinned address.
    pub dns_overrides: Vec<(String, std::net::IpAddr)>,
    /// The longest one exchange waits on its upstream socket, per read or write and in total;
    /// defaults to 300 seconds.
    pub upstream_read_deadline: std::time::Duration,
    /// The maximum number of connections handled concurrently. The adapter is thread-per-connection
    /// (this crate pulls in no async runtime), so this bounds the thread count: excess connections wait
    /// for a slot rather than spawning unbounded OS threads. The workload is contained but *untrusted*
    /// (it is the very thing this crate exists to contain), so the cap is a hard backpressure limit,
    /// not an optimization. Defaults to 256.
    pub max_connections: usize,
    /// Remote MCP servers, as `(host, name)` pairs. A request whose destination host matches an entry
    /// is treated as an MCP stream for the server `name`: the L7 leg parses the JSON-RPC frame and
    /// raises an `mcp:call` decision alongside `http:request`. The name is **config-assigned** — it is
    /// keyed by the host the connection reached and is never read from the frame, so an agent cannot
    /// borrow another server's identity. Host-only match (a host registers all its ports). Empty means
    /// no remote MCP servers, and every existing caller keeps today's behavior unchanged.
    pub mcp_servers: Vec<(String, String)>,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            unix_socket_path: None,
            external_proxy: None,
            intercept_ca_dir: None,
            enable_h2: false,
            response_limits: ResponseLimits::default(),
            expected_token: None,
            credential_env: Vec::new(),
            upstream_ca_pems: Vec::new(),
            dns_overrides: Vec::new(),
            upstream_read_deadline: std::time::Duration::from_secs(300),
            max_connections: 256,
            mcp_servers: Vec::new(),
        }
    }
}

/// The shared, read-only state every connection handler borrows (behind an `Arc`).
pub(crate) struct SharedState {
    /// Part B — the controls this adapter drives.
    controls: CapabilitySet,
    /// The adapter config.
    config: MitmConfig,
    /// The ephemeral session CA; `None` only if TLS interception is disabled at runtime.
    ca: Option<EphemeralCa>,
    /// The upstream (client) TLS config with the additive trust bundle.
    upstream_config: Arc<ClientConfig>,
    /// The fast in-memory audit log.
    audit: SharedAuditLog,
    /// The final outbound decision emitter.
    emitter: Box<dyn Emitter>,
    /// The authorization authority for every outbound effect.
    effect_interceptor: Arc<dyn EffectInterceptor>,
    /// The best-effort proxy session token.
    expected_token: Option<String>,
}

impl SharedState {
    /// The current Unix time in seconds — the clock seam handed to each [`CapabilityContext`](crate::capability::CapabilityContext).
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// The pinned IP override for `host`, if the supervisor configured one (split-horizon / fixed
    /// endpoint map). `None` falls back to normal resolution.
    fn dns_override(&self, host: &str) -> Option<std::net::IpAddr> {
        self.config
            .dns_overrides
            .iter()
            .find(|(h, _)| h.eq_ignore_ascii_case(host))
            .map(|(_, ip)| *ip)
    }

    /// The remote MCP server name configured for `host`, if any (host-only match).
    ///
    /// The name is config-assigned, keyed by the host the connection reached — never read from the
    /// frame — so an agent cannot claim a different server by putting a name in the JSON-RPC body. A
    /// match tells the L7 leg to parse the frame and raise `mcp:call`; `None` leaves the request a
    /// plain `http:request`.
    fn mcp_server_for(&self, host: &str) -> Option<&str> {
        self.config
            .mcp_servers
            .iter()
            .find(|(configured, _)| connect::same_host(configured, host))
            .map(|(_, name)| name.as_str())
    }
}

/// The v1 MITM proxy adapter. Constructed via [`start`](Self::start).
pub struct MitmInterceptor {
    state: Arc<SharedState>,
}

impl MitmInterceptor {
    /// Start the adapter: validate the credential injection against the adapter's max visibility,
    /// build the ephemeral CA and upstream trust bundle, bind `127.0.0.1:0`, spawn the accept loop,
    /// and return a [`MitmHandle`].
    pub fn start(
        config: MitmConfig,
        credentials: CapabilitySet,
        effect_interceptor: Arc<dyn EffectInterceptor>,
    ) -> Result<MitmHandle> {
        Self::start_inner(
            config,
            credentials,
            Box::new(StubEmitter::new()),
            effect_interceptor,
            None,
        )
    }

    /// [`start`](Self::start) with an explicit audit [`Emitter`] (the shared L2 seam).
    pub fn start_with_emitter(
        config: MitmConfig,
        credentials: CapabilitySet,
        effect_interceptor: Arc<dyn EffectInterceptor>,
        emitter: Box<dyn Emitter>,
    ) -> Result<MitmHandle> {
        Self::start_inner(config, credentials, emitter, effect_interceptor, None)
    }

    /// Start with an already-open file for the public interception CA.
    pub fn start_with_emitter_and_opened_ca(
        config: MitmConfig,
        credentials: CapabilitySet,
        effect_interceptor: Arc<dyn EffectInterceptor>,
        emitter: Box<dyn Emitter>,
        ca_file: &std::fs::File,
    ) -> Result<MitmHandle> {
        Self::start_inner(
            config,
            credentials,
            emitter,
            effect_interceptor,
            Some(ca_file),
        )
    }

    fn start_inner(
        config: MitmConfig,
        controls: CapabilitySet,
        emitter: Box<dyn Emitter>,
        effect_interceptor: Arc<dyn EffectInterceptor>,
        ca_file: Option<&std::fs::File>,
    ) -> Result<MitmHandle> {
        // The MITM adapter's max visibility is `Http` when tls-intercept is on (this compile), so a
        // Control needing Http is satisfiable. Validate the set fail-closed.
        controls.validate()?;

        // Ephemeral CA. Its public cert path (if a dir was configured) is the SSL_CERT_FILE.
        let ca = EphemeralCa::generate(config.intercept_ca_dir.as_deref(), ca_file)?;
        let ca_path = ca.ca_path().map(|p| p.to_path_buf());
        let ssl_cert_file = ca_path.clone();

        // Upstream additive trust bundle: system roots + any configured extra CA PEMs
        // (a deployment's private CA / corporate root).
        let upstream_config = Arc::new(tls::upstream_client_config(&config.upstream_ca_pems)?);

        let audit = SharedAuditLog::new();
        let credential_env: Vec<CredentialEnv> = config
            .credential_env
            .iter()
            .map(|(name, value)| CredentialEnv {
                name: name.clone(),
                value: value.clone(),
            })
            .collect();
        let expected_token = config.expected_token.clone();

        let state = Arc::new(SharedState {
            controls,
            config: config.clone(),
            ca: Some(ca),
            upstream_config,
            audit: audit.clone(),
            emitter,
            effect_interceptor,
            expected_token,
        });

        let stop = Arc::new(AtomicBool::new(false));

        // Bind exactly one transport. `unix_socket_path: Some(path)` binds ONLY an AF_UNIX
        // socket — no `TcpListener` is created in that mode — since a workload contained by the
        // seccomp pin cannot reach a TCP port at all. `None` (the default) keeps today's behavior:
        // bind `127.0.0.1:0`. Each arm records the transport it bound so the handle never guesses.
        let (transport, accept_thread) = match &config.unix_socket_path {
            None => {
                // Default: bind 127.0.0.1:0.
                let listener = std::net::TcpListener::bind(config.bind_addr)
                    .map_err(|e| ProxyError::Bind(format!("binding {}: {e}", config.bind_addr)))?;
                let port = listener
                    .local_addr()
                    .map_err(|e| ProxyError::Bind(format!("reading bound addr: {e}")))?
                    .port();
                let accept_thread = {
                    let state = state.clone();
                    let stop = stop.clone();
                    std::thread::spawn(move || listener::accept_loop(listener, state, stop))
                };
                (BoundTransport::Tcp(port), accept_thread)
            }
            Some(path) => {
                // AF_UNIX-only pin: bind ONLY the UnixListener, never a TcpListener.
                let listener = std::os::unix::net::UnixListener::bind(path).map_err(|e| {
                    ProxyError::Bind(format!("binding AF_UNIX socket {}: {e}", path.display()))
                })?;
                // Restrict the socket file to owner-only: DAC is the entire mechanism
                // scoping which endpoint can reach the proxy — nothing else gates this connect(),
                // so getting this mode wrong (e.g. 0666) silently reopens a
                // same-host lateral-movement path. There is a brief, unavoidable TOCTOU window between
                // `bind()` creating the file and this call tightening it (umask manipulation around the
                // bind is left as a v1 limitation). A bind failure already returned above.
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                    |e| {
                        ProxyError::Bind(format!(
                            "setting 0600 on AF_UNIX socket {}: {e}",
                            path.display()
                        ))
                    },
                )?;
                let accept_thread = {
                    let state = state.clone();
                    let stop = stop.clone();
                    std::thread::spawn(move || listener::accept_loop_unix(listener, state, stop))
                };
                (BoundTransport::Unix(path.clone()), accept_thread)
            }
        };

        Ok(MitmHandle::new(
            transport,
            ca_path,
            ssl_cert_file,
            credential_env,
            audit,
            stop,
            accept_thread,
        ))
    }
}

impl Interceptor for MitmInterceptor {
    fn credential_injection(&self) -> &CapabilitySet {
        &self.state.controls
    }
}
