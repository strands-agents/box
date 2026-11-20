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
            Self::Tcp(listener) => listener.accept().await.map(|(stream, _peer)| stream),
        }
    }
}
