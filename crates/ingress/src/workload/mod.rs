#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(all(test, target_os = "linux"))]
pub(crate) use linux::tests as fake_pid_one;

#[cfg(target_os = "linux")]
type Platform = linux::InNamespace;
#[cfg(target_os = "macos")]
type Platform = macos::Loopback;

/// The contained workload's port: where the relay carries each caller.
#[derive(Debug)]
pub struct Workload(Platform);

impl Workload {
    pub(crate) async fn connect(&self) -> Result<tokio::net::TcpStream, ConnectError> {
        self.0.connect().await
    }

    /// The workload's port.
    pub(crate) fn port(&self) -> u16 {
        self.0.port
    }
}

/// Why no connection to the workload was opened.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConnectError {
    /// Nothing accepts on the workload's port on `127.0.0.1` within the timeout.
    NotReady,
    /// No connection can be opened again.
    Fatal,
}

/// How long one connection to the workload may take before the caller is closed.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A port on `127.0.0.1` that refuses every connection and that no other test can bind: a socket
/// holds it bound, and never listens.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn refusing_port() -> (tokio::net::TcpSocket, u16) {
    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    socket.bind(loopback(0)).expect("bind");
    let port = socket.local_addr().expect("address").port();
    (socket, port)
}

/// The workload's `port` on the IPv4 loopback address.
fn loopback(port: u16) -> std::net::SocketAddr {
    (std::net::Ipv4Addr::LOCALHOST, port).into()
}

/// Connect `socket` to `port` on `127.0.0.1`, within [`CONNECT_TIMEOUT`].
async fn connect_loopback(
    socket: tokio::net::TcpSocket,
    port: u16,
) -> Result<tokio::net::TcpStream, ConnectError> {
    match tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(loopback(port))).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_)) | Err(_) => Err(ConnectError::NotReady),
    }
}
