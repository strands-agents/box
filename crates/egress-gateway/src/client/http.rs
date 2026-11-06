//! The upstream side: TLS to the pinned upstream, and hyper's client.

use std::borrow::Cow;
use std::cell::Cell;
use std::io;
use std::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;

use http_body_util::Empty;
use hyper::Request;
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, timeout_at};
use tokio_rustls::TlsConnector;

use crate::effect::EffectOutcome;
use crate::error::{ProxyError, Result};
use crate::intercept::mitm::SharedState;
use crate::intercept::mitm::http1::{self, ParsedResponse, ResponseHead};
use crate::transport::socket::{self, Counted, MAX_HEAD_BYTES, Socket, WriteCount};

/// The pinned upstream socket, and the deadline of the one exchange on it.
pub(crate) struct Upstream {
    socket: TcpStream,
    /// The name to verify, when the exchange runs inside TLS.
    tls: Option<ServerName<'static>>,
    deadline: Instant,
}

/// Why an exchange got no response head, and the I/O kind to record.
type NoResponse = (io::ErrorKind, ProxyError);

impl Upstream {
    /// `socket` is the pinned socket the listener opened. A TLS failure drops the exchange.
    pub(crate) fn new(
        socket: TcpStream,
        tls: Option<ServerName<'static>>,
        state: &SharedState,
    ) -> Self {
        Self {
            socket,
            tls,
            deadline: Instant::now() + state.config.upstream_read_deadline,
        }
    }

    /// Whether the exchange runs inside a CONNECT tunnel's TLS.
    pub(crate) fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Send the serialized request, and read the whole response before the deadline.
    pub(crate) async fn send(
        self,
        state: &SharedState,
        method: &str,
        head: &[u8],
        body: &[u8],
    ) -> (EffectOutcome, Result<ParsedResponse>) {
        let Self {
            socket,
            tls,
            deadline,
        } = self;
        let writes = WriteCount::default();
        let status = Cell::new(None);
        let max_body = state.config.response_limits.max_body_bytes;
        let exchange = async {
            let lost = |what: &str, error: io::Error| {
                (error.kind(), ProxyError::Io(format!("{what}: {error}")))
            };
            let tcp = socket
                .into_async()
                .map_err(|e| lost("upstream socket", e))?;
            let request = (method, head, body);
            match tls {
                None => round_trip(tcp, &writes, request, &status, max_body).await,
                Some(name) => {
                    let tls = TlsConnector::from(state.upstream_config.clone())
                        .connect(name, tcp)
                        .await
                        .map_err(|e| lost("upstream TLS handshake", e))?;
                    round_trip(tls, &writes, request, &status, max_body).await
                }
            }
        };
        within(deadline, &writes, &status, exchange).await
    }

    /// Send the serialized request and read the response head before the deadline, and leave the
    /// body to stream. The body waits at most `upstream_read_deadline` for each piece.
    ///
    /// The request bytes are owned, because the connection outlives this call, and they are not
    /// wiped on drop, so the caller passes only a request that carries no credential.
    pub(crate) async fn send_streamed(
        self,
        state: &SharedState,
        method: &str,
        head: Vec<u8>,
        body: Vec<u8>,
    ) -> (EffectOutcome, Result<StreamedResponse>) {
        let Self {
            socket,
            tls,
            deadline,
        } = self;
        let writes = WriteCount::default();
        let status = Cell::new(None);
        let gap = state.config.upstream_read_deadline;
        let exchange = async {
            let lost = |what: &str, error: io::Error| {
                (error.kind(), ProxyError::Io(format!("{what}: {error}")))
            };
            let tcp = socket
                .into_async()
                .map_err(|e| lost("upstream socket", e))?;
            let request = (method, head, body);
            match tls {
                None => open_stream(tcp, &writes, request, &status, gap).await,
                Some(name) => {
                    let tls = TlsConnector::from(state.upstream_config.clone())
                        .connect(name, tcp)
                        .await
                        .map_err(|e| lost("upstream TLS handshake", e))?;
                    open_stream(tls, &writes, request, &status, gap).await
                }
            }
        };
        within(deadline, &writes, &status, exchange).await
    }
}

/// A response whose head has arrived and whose body streams from the upstream.
pub(crate) struct StreamedResponse {
    pub(crate) head: ResponseHead,
    pub(crate) body: UpstreamBody,
}

/// Run `exchange` until it ends or the deadline passes, and return the request's outcome with
/// the exchange's result.
async fn within<T>(
    deadline: Instant,
    writes: &WriteCount,
    status: &Cell<Option<u16>>,
    exchange: impl Future<Output = std::result::Result<T, NoResponse>>,
) -> (EffectOutcome, Result<T>) {
    let (kind, response) = match timeout_at(deadline, exchange).await {
        Ok(Ok(response)) => (None, Ok(response)),
        Ok(Err((kind, error))) => (Some(kind), Err(error)),
        Err(_) => (
            Some(io::ErrorKind::TimedOut),
            Err(ProxyError::Io("upstream deadline passed".to_string())),
        ),
    };
    let outcome = match status.get() {
        Some(status) => EffectOutcome::Replied {
            accepted_bytes: writes.get().accepted,
            status,
        },
        None => writes.get().outcome(0, kind),
    };
    (outcome, response)
}

/// Send `request` through hyper. hyper never wipes its buffers, so it gets a stand-in, and
/// [`Prepared`] writes the real bytes.
async fn round_trip<S>(
    upstream: S,
    writes: &WriteCount,
    (method, head, body): (&str, &[u8], &[u8]),
    status: &Cell<Option<u16>>,
    max_body: usize,
) -> std::result::Result<ParsedResponse, NoResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let lost = |error: hyper::Error| {
        let kind = socket::error_kind(&error);
        (kind, ProxyError::Io(format!("upstream exchange: {error}")))
    };
    let stand_in = stand_in_request(method)?;
    let upstream = Prepared::new(Counted::new(upstream, writes.clone(), None), head, body);
    let (mut sender, connection) = client_builder()
        .handshake(TokioIo::new(upstream))
        .await
        .map_err(lost)?;
    let exchange = async move {
        let response = sender.send_request(stand_in).await.map_err(lost)?;
        status.set(Some(response.status().as_u16()));
        http1::read_response(response, max_body)
            .await
            .map_err(|error| (io::ErrorKind::Other, error))
    };
    // Drive the connection until the response is read; dropping it closes the upstream.
    let connection = async {
        let _ = connection.await;
        std::future::pending::<()>().await
    };
    tokio::select! {
        response = exchange => response,
        () = connection => unreachable!("the connection future never completes"),
    }
}

/// hyper's stand-in for the box's request. [`Prepared`] writes the real bytes in its place.
fn stand_in_request(method: &str) -> std::result::Result<Request<Empty<Bytes>>, NoResponse> {
    Request::builder()
        .method(method)
        .uri("/")
        .body(Empty::<Bytes>::new())
        .map_err(|e| {
            let error = ProxyError::Intercept(format!("upstream request: {e}"));
            (io::ErrorKind::InvalidInput, error)
        })
}

/// hyper's client, set up as the gateway reads every upstream.
fn client_builder() -> hyper::client::conn::http1::Builder {
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder
        .preserve_header_case(true)
        .max_headers(64)
        .max_buf_size(MAX_HEAD_BYTES);
    builder
}

/// Send `request` through hyper and read the response head, and return the body unread, with
/// the connection that delivers it.
async fn open_stream<S>(
    upstream: S,
    writes: &WriteCount,
    (method, head, body): (&str, Vec<u8>, Vec<u8>),
    status: &Cell<Option<u16>>,
    gap: Duration,
) -> std::result::Result<StreamedResponse, NoResponse>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let lost = |error: hyper::Error| {
        let kind = socket::error_kind(&error);
        (kind, ProxyError::Io(format!("upstream exchange: {error}")))
    };
    let stand_in = stand_in_request(method)?;
    let upstream = Prepared::new(Counted::new(upstream, writes.clone(), None), head, body);
    let (mut sender, connection) = client_builder()
        .handshake(TokioIo::new(upstream))
        .await
        .map_err(lost)?;
    let mut connection = Driver::new(connection);
    let response = {
        let mut send = std::pin::pin!(sender.send_request(stand_in));
        std::future::poll_fn(|cx| {
            connection.poll(cx);
            send.as_mut().poll(cx)
        })
        .await
        .map_err(lost)?
    };
    status.set(Some(response.status().as_u16()));
    let (head, body) =
        http1::read_response_head(response).map_err(|error| (io::ErrorKind::Other, error))?;
    let body = UpstreamBody {
        body,
        connection,
        _sender: sender,
        gap,
        idle: Box::pin(tokio::time::sleep(gap)),
    };
    Ok(StreamedResponse { head, body })
}

/// Writes the box's request bytes in place of hyper's stand-in, and holds reads until they are
/// flushed, because hyper treats early bytes on an idle connection as an error.
struct Prepared<'a, S> {
    inner: S,
    head: Cow<'a, [u8]>,
    body: Cow<'a, [u8]>,
    sent: usize,
    flushed: bool,
    reader: Option<Waker>,
}

impl<'a, S> Prepared<'a, S> {
    /// `head` and `body` are borrowed for an exchange that ends before its caller returns, and
    /// owned for a streamed one, whose connection outlives its caller.
    fn new(inner: S, head: impl Into<Cow<'a, [u8]>>, body: impl Into<Cow<'a, [u8]>>) -> Self {
        Self {
            inner,
            head: head.into(),
            body: body.into(),
            sent: 0,
            flushed: false,
            reader: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prepared<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.flushed {
            this.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prepared<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        stand_in: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        while !this.flushed {
            let rest = match this.sent.checked_sub(this.head.len()) {
                None => &this.head[this.sent..],
                Some(at) => &this.body[at..],
            };
            if rest.is_empty() {
                ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
                this.flushed = true;
                if let Some(reader) = this.reader.take() {
                    reader.wake();
                }
                break;
            }
            let written = ready!(Pin::new(&mut this.inner).poll_write(cx, rest))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            this.sent += written;
        }
        Poll::Ready(Ok(stand_in.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The upstream connection, driven by whoever waits on its exchange, until it ends.
struct Driver(Option<Pin<Box<dyn Future<Output = ()> + Send>>>);

impl Driver {
    fn new<F: Future + Send + 'static>(connection: F) -> Self {
        Self(Some(Box::pin(async move {
            let _ = connection.await;
        })))
    }

    fn poll(&mut self, cx: &mut Context<'_>) {
        if let Some(connection) = self.0.as_mut()
            && connection.as_mut().poll(cx).is_ready()
        {
            self.0 = None;
        }
    }
}

/// A response body read from the upstream as the workload takes it.
///
/// It drives the upstream connection itself, so the upstream is read only while the workload
/// reads, and it fails when the upstream sends nothing for `gap`.
pub(crate) struct UpstreamBody {
    body: Incoming,
    connection: Driver,
    /// Held so the connection keeps serving this exchange until its body ends.
    _sender: SendRequest<Empty<Bytes>>,
    gap: Duration,
    idle: Pin<Box<Sleep>>,
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        this.connection.poll(cx);
        loop {
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    this.idle.as_mut().reset(Instant::now() + this.gap);
                    match frame.into_data() {
                        Ok(data) => return Poll::Ready(Some(Ok(Frame::data(data)))),
                        // Refused as the buffered read refuses them: hyper would drop them.
                        Err(frame)
                            if frame
                                .trailers_ref()
                                .is_some_and(|trailers| !trailers.is_empty()) =>
                        {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "chunked trailers are not supported",
                            ))));
                        }
                        Err(_) => {}
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Some(Err(io::Error::other(error))));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {
                    if this.idle.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the upstream sent nothing within the gap limit",
                        ))));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const HEAD: &[u8] =
        b"POST /v1 HTTP/1.1\r\nAuthorization: Bearer real\r\nConnection: close\r\nContent-Length: 2\r\n\r\n";

    /// Run one exchange against an upstream that answers `response`.
    fn answered_with(
        response: &[u8],
    ) -> (
        Vec<u8>,
        std::result::Result<ParsedResponse, NoResponse>,
        Option<u16>,
        usize,
    ) {
        socket::block_on(async {
            let (gateway, mut upstream) = tokio::io::duplex(256 * 1024);
            let status = Cell::new(None);
            let writes = WriteCount::default();
            let server = async {
                let mut seen = vec![0u8; HEAD.len() + 2];
                upstream.read_exact(&mut seen).await.unwrap();
                let _ = upstream.write_all(response).await;
                let _ = upstream.shutdown().await;
                let mut rest = Vec::new();
                let _ = upstream.read_to_end(&mut rest).await;
                seen.extend(rest);
                seen
            };
            let client = round_trip(gateway, &writes, ("POST", HEAD, b"ok"), &status, 1024);
            let (result, seen) = tokio::join!(client, server);
            (seen, result, status.get(), writes.get().accepted)
        })
        .unwrap()
    }

    /// The upstream receives the box's bytes and never hyper's stand-in.
    #[test]
    fn the_upstream_receives_the_box_bytes_not_the_stand_in() {
        let (seen, result, status, accepted) =
            answered_with(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nyes");
        assert_eq!(seen, [HEAD, b"ok"].concat(), "exactly the box's bytes");
        assert_eq!(accepted, HEAD.len() + 2);
        assert_eq!(status, Some(200));
        assert_eq!(result.unwrap().response.body, b"yes");
    }

    #[test]
    fn a_response_that_fails_after_its_head_keeps_its_status() {
        let (_, result, status, _) =
            answered_with(b"HTTP/1.1 500 Internal\r\nContent-Length: 100\r\n\r\nshort");
        assert!(result.is_err());
        assert_eq!(status, Some(500));

        let (_, result, status, _) = answered_with(b"HTTP/1.1 5");
        assert!(result.is_err());
        assert_eq!(status, None);
    }

    #[test]
    fn an_upgrade_response_is_refused() {
        let (_, result, _, _) = answered_with(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
        );
        assert!(result.is_err());
    }

    /// A head can pass [`MAX_HEAD_BYTES`] by one read, so twice the limit is refused.
    #[test]
    fn an_oversized_response_head_is_refused() {
        let mut response = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
        response.extend(std::iter::repeat_n(b'a', 2 * MAX_HEAD_BYTES));
        response.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let (_, result, status, _) = answered_with(&response);
        assert!(result.is_err());
        assert_eq!(status, None);
    }

    /// hyper keeps every framing header of a response, so the box's rules see them and refuse.
    #[test]
    fn a_response_that_states_two_framings_is_refused() {
        for response in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
        ] {
            let (_, result, status, _) = answered_with(response);
            assert!(matches!(result, Err((_, ProxyError::Intercept(_)))));
            assert_eq!(status, Some(200));
        }
    }
}
