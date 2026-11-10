use super::{ConnectError, connect_loopback};
use crate::Workload;

#[derive(Debug)]
pub(super) struct Loopback {
    pub(super) port: u16,
}

impl Workload {
    /// Connections to the workload's `port` on the loopback address.
    pub fn loopback(port: u16) -> Self {
        Self(Loopback { port })
    }
}

impl Loopback {
    pub(super) async fn connect(&self) -> Result<tokio::net::TcpStream, ConnectError> {
        let socket = tokio::net::TcpSocket::new_v4().map_err(|_| ConnectError::Fatal)?;
        connect_loopback(socket, self.port).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_port_with_no_listener_is_not_ready() {
        let unused = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = unused.local_addr().expect("address").port();
        drop(unused);

        let refused = Workload::loopback(port).connect().await;
        assert_eq!(refused.err(), Some(ConnectError::NotReady));
    }

    #[tokio::test]
    async fn a_listener_on_the_ipv6_loopback_alone_is_not_reached() {
        let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
            println!("skipping: this host has no IPv6 loopback");
            return;
        };
        let port = listener.local_addr().expect("address").port();
        let refused = Workload::loopback(port).connect().await;
        assert_eq!(refused.err(), Some(ConnectError::NotReady));
    }
}
