//! [`MitmHandle`] — the supervisor's control surface for a running adapter.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use crate::audit::{NetworkAuditEvent, SharedAuditLog};

/// Which transport the adapter actually bound.
pub(super) enum BoundTransport {
    /// A TCP listener on `127.0.0.1:<port>` (the default mode).
    Tcp(u16),
    /// A single AF_UNIX listener at this filesystem path (the pin mode).
    Unix(PathBuf),
}

/// A phantom-token env pair the supervisor seeds into the workload (a `*_BASE_URL` plus the phantom).
#[derive(Debug, Clone)]
pub(super) struct CredentialEnv {
    /// The env var name (e.g. `OPENAI_API_KEY`, `GITHUB_TOKEN`).
    pub(super) name: String,
    /// The value — a phantom token, never a real secret.
    pub(super) value: String,
}

/// The running MITM adapter's control surface.
pub struct MitmHandle {
    transport: BoundTransport,
    ca_path: Option<PathBuf>,
    ssl_cert_file: Option<PathBuf>,
    credential_env: Vec<CredentialEnv>,
    audit: SharedAuditLog,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl MitmHandle {
    /// Build a handle over a running adapter's parts (called by `MitmInterceptor::start`).
    pub(super) fn new(
        transport: BoundTransport,
        ca_path: Option<PathBuf>,
        ssl_cert_file: Option<PathBuf>,
        credential_env: Vec<CredentialEnv>,
        audit: SharedAuditLog,
        stop: Arc<AtomicBool>,
        accept_thread: JoinHandle<()>,
    ) -> Self {
        Self {
            transport,
            ca_path,
            ssl_cert_file,
            credential_env,
            audit,
            stop,
            accept_thread: Some(accept_thread),
        }
    }

    /// The localhost port the proxy is listening on, if it bound a `TcpListener`.
    pub fn port(&self) -> Option<u16> {
        match self.transport {
            BoundTransport::Tcp(port) => Some(port),
            BoundTransport::Unix(_) => None,
        }
    }

    /// The AF_UNIX socket path the proxy is listening on, if configured for the pin.
    pub fn unix_socket_path(&self) -> Option<&Path> {
        match &self.transport {
            BoundTransport::Tcp(_) => None,
            BoundTransport::Unix(path) => Some(path),
        }
    }

    /// The path to the **public** ephemeral CA cert to install in the box trust store, if a CA dir
    /// was configured. `None` when the CA is memory-only.
    pub fn intercept_ca_path(&self) -> Option<&Path> {
        self.ca_path.as_deref()
    }

    /// The env vars that pin the workload's HTTP client to the proxy and its trust store.
    pub fn env_vars(&self) -> Vec<(String, String)> {
        let mut vars = match &self.transport {
            BoundTransport::Tcp(port) => {
                let proxy = format!("http://127.0.0.1:{port}");
                vec![
                    ("HTTP_PROXY".to_string(), proxy.clone()),
                    ("HTTPS_PROXY".to_string(), proxy.clone()),
                    ("http_proxy".to_string(), proxy.clone()),
                    ("https_proxy".to_string(), proxy),
                ]
            }
            BoundTransport::Unix(_) => Vec::new(),
        };
        if let Some(cert) = &self.ssl_cert_file {
            vars.push(("SSL_CERT_FILE".to_string(), cert.display().to_string()));
        }
        vars
    }

    /// The credential env vars (`*_BASE_URL` + phantom token) the supervisor seeds the workload
    /// with. The phantom is non-secret; the real secret never enters the box.
    pub fn credential_env_vars(&self) -> Vec<(String, String)> {
        self.credential_env
            .iter()
            .map(|e| (e.name.clone(), e.value.clone()))
            .collect()
    }

    /// Drain the buffered fast-lane audit events. Leaves the log empty.
    pub fn drain_audit_events(&self) -> Vec<NetworkAuditEvent> {
        self.audit.drain()
    }

    /// Shut the adapter down: flip the stop flag and unblock the accept loop by poking the
    /// listener. Idempotent — a second call (or `Drop`) is a no-op.
    pub fn shutdown(&self) {
        if self.stop.swap(true, Ordering::SeqCst) {
            return; // already shutting down
        }
        // Unblock the blocking `accept()` by opening (and dropping) a throwaway connection over the
        // same transport the accept loop is waiting on.
        match &self.transport {
            BoundTransport::Tcp(port) => {
                let _ = std::net::TcpStream::connect(("127.0.0.1", *port));
            }
            BoundTransport::Unix(path) => {
                let _ = UnixStream::connect(path);
            }
        }
    }
}

impl Drop for MitmHandle {
    /// Shut down and join the accept thread on drop.
    fn drop(&mut self) {
        self.shutdown();
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU32;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// A short, unique AF_UNIX socket path under the temp dir. Kept short deliberately: `sun_path` is
    /// capped (~104 bytes on macOS, 108 on Linux), so a long tempdir base plus a long filename would
    /// overflow the bind. The counter + pid keep parallel test runs from colliding.
    fn unique_sock_path() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("slc-{}-{n}.sock", std::process::id()))
    }

    /// Mirror `listener::accept_loop`'s stop-poll + blocking-accept shape: block in `accept()` and only
    /// recheck `stop` when a connection wakes the loop. This is exactly the structure `shutdown()` must
    /// unblock, so the drop-does-not-hang test exercises the real regression rather than a stand-in.
    fn unix_handle() -> (MitmHandle, PathBuf) {
        let path = unique_sock_path();
        // A stale socket file from a crashed prior run would fail bind; clear it first (best-effort).
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let accept_thread = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                for incoming in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    drop(incoming);
                }
            })
        };
        let handle = MitmHandle::new(
            BoundTransport::Unix(path.clone()),
            None,
            None,
            Vec::new(),
            SharedAuditLog::new(),
            stop,
            accept_thread,
        );
        (handle, path)
    }

    /// A TCP-transport handle whose accept thread mirrors the same stop-poll shape.
    fn tcp_handle() -> MitmHandle {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let accept_thread = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                for incoming in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    drop(incoming);
                }
            })
        };
        MitmHandle::new(
            BoundTransport::Tcp(port),
            None,
            None,
            Vec::new(),
            SharedAuditLog::new(),
            stop,
            accept_thread,
        )
    }

    /// `port()`/`unix_socket_path()` each report the transport actually bound.
    #[test]
    fn accessors_report_per_transport() {
        let tcp = tcp_handle();
        assert!(tcp.port().is_some_and(|p| p > 0), "TCP reports its port");
        assert!(tcp.unix_socket_path().is_none(), "TCP has no socket path");

        let (unix, path) = unix_handle();
        assert_eq!(unix.port(), None, "AF_UNIX has no TCP port");
        assert_eq!(
            unix.unix_socket_path(),
            Some(path.as_path()),
            "AF_UNIX reports its socket path"
        );
    }

    /// `env_vars()` still emits the four proxy vars on the TCP path…
    #[test]
    fn env_vars_emit_proxy_vars_under_tcp() {
        let handle = tcp_handle();
        let env: HashMap<_, _> = handle.env_vars().into_iter().collect();
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert!(env.contains_key(k), "TCP mode must emit {k}");
        }
    }

    /// …and omits them entirely under the AF_UNIX-only pin. No proxy-URL syntax for
    /// an AF_UNIX socket is invented; `SSL_CERT_FILE` (when set) is unaffected — none is set here.
    #[test]
    fn env_vars_omit_proxy_vars_under_af_unix() {
        let (handle, _path) = unix_handle();
        let env: HashMap<_, _> = handle.env_vars().into_iter().collect();
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert!(!env.contains_key(k), "AF_UNIX mode must omit {k}");
        }
    }

    /// `Drop` (via `shutdown()`) must
    /// unblock the AF_UNIX accept loop over `UnixStream`, not the old `TcpStream::connect` that would
    /// never wake it. Bounded so a regression fails this test rather than hanging the whole suite.
    #[test]
    fn drop_does_not_hang_under_af_unix() {
        let (handle, _path) = unix_handle();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            drop(handle); // shutdown() self-connects over UnixStream, unblocking accept()
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "MitmHandle::drop() must not hang under the AF_UNIX-only pin (a regression)"
        );
    }
}
