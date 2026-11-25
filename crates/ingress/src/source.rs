use crate::IngressError;

/// Where callers arrive.
#[derive(Debug)]
pub struct Source(Kind);

#[derive(Debug)]
enum Kind {
    Tcp(std::net::TcpListener),
}

impl Source {
    /// Callers that connect to a bound TCP listener.
    pub fn tcp(listener: std::net::TcpListener) -> Self {
        Self(Kind::Tcp(listener))
    }

    pub(crate) fn open(self) -> Result<Callers, IngressError> {
        match self.0 {
            Kind::Tcp(listener) => {
                listener.set_nonblocking(true)?;
                Ok(Callers::Tcp(tokio::net::TcpListener::from_std(listener)?))
            }
        }
    }
}

/// An opened [`Source`].
pub(crate) enum Callers {
    Tcp(tokio::net::TcpListener),
}

impl Callers {
    /// The next caller's connection.
    pub(crate) async fn next(&mut self) -> std::io::Result<tokio::net::TcpStream> {
        match self {
            Self::Tcp(listener) => {
                let (stream, _peer) = listener.accept().await?;
                // Best-effort: Nagle's algorithm off. The root `AGENTS.md` records why.
                let _ = stream.set_nodelay(true);
                Ok(stream)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_caller_connection_has_tcp_nodelay_set() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind source");
        let address = listener.local_addr().expect("address");
        let mut callers = Source::tcp(listener).open().expect("open");
        let _caller = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");

        let accepted = callers.next().await.expect("accept");
        assert!(
            accepted.nodelay().expect("nodelay"),
            "Nagle's algorithm is off on the caller's connection"
        );
    }
}
