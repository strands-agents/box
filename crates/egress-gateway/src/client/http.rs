//! The upstream side: TLS to the pinned upstream, and hyper's client.

use std::cell::Cell;
use std::io;
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker, ready};

use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, timeout_at};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::effect::{ClaimedEffectPermit, EffectOutcome};
use crate::error::{ProxyError, Result};
use crate::intercept::mitm::SharedState;
use crate::intercept::mitm::http1::{self, ResponseHead};
use crate::transport::socket::{self, Counted, MAX_HEAD_BYTES, Socket, WriteCount};

/// The pinned upstream socket, and the deadline of the one exchange on it.
pub(crate) struct Upstream<'a> {
    socket: TcpStream,
    /// The name to verify, when the exchange runs inside TLS.
    tls: Option<ServerName<'static>>,
    deadline: Instant,
    completion: &'a ResponseCompletion,
}

/// Why an exchange got no response head, and the I/O kind to record.
type NoResponse = (io::ErrorKind, ProxyError);

impl<'a> Upstream<'a> {
    /// `socket` is the pinned socket the listener opened. A TLS failure drops the exchange.
    pub(crate) fn new(
        socket: TcpStream,
        tls: Option<ServerName<'static>>,
        state: &SharedState,
        completion: &'a ResponseCompletion,
    ) -> Self {
        Self {
            socket,
            tls,
            deadline: Instant::now() + state.config.upstream_read_deadline,
            completion,
        }
    }

    /// Whether the exchange runs inside a CONNECT tunnel's TLS.
    pub(crate) fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Send the serialized request and receive the response head under the exchange deadline.
    pub(crate) async fn send(
        self,
        state: &SharedState,
        method: &str,
        head: Zeroizing<String>,
        body: Zeroizing<Vec<u8>>,
    ) -> (EffectOutcome, Result<UpstreamResponse>) {
        let Self {
            socket,
            tls,
            deadline,
            completion,
        } = self;
        let writes = WriteCount::default();
        let status = Cell::new(None);
        let exchange = async {
            let lost = |what: &str, error: io::Error| {
                (error.kind(), ProxyError::Io(format!("{what}: {error}")))
            };
            let tcp = socket
                .into_async()
                .map_err(|e| lost("upstream socket", e))?;
            let request = (method, head, body);
            match tls {
                None => round_trip(tcp, &writes, request, &status, deadline).await,
                Some(name) => {
                    let tls = TlsConnector::from(state.upstream_config.clone())
                        .connect(name, tcp)
                        .await
                        .map_err(|e| lost("upstream TLS handshake", e))?;
                    round_trip(tls, &writes, request, &status, deadline).await
                }
            }
        };
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
        if let Ok(response) = &response {
            completion.body.set(Some(response.body.clone()));
        }
        (outcome, response)
    }
}

/// An upstream response whose body retains the connection and its absolute deadline.
pub(crate) struct UpstreamResponse {
    pub(crate) head: ResponseHead,
    pub(crate) body: UpstreamBody,
}

/// The connection's upstream response, retained until receipt ends even if delivery stops.
#[derive(Default)]
pub(crate) struct ResponseCompletion {
    body: Cell<Option<UpstreamBody>>,
}

impl ResponseCompletion {
    pub(crate) async fn finish(&self) -> io::Result<()> {
        if let Some(mut body) = self.body.take() {
            while let Some(frame) = body.frame().await {
                frame?;
            }
        }
        Ok(())
    }
}

/// Whether the upstream body finished or failed independently of downstream writes.
#[derive(Clone, Copy)]
pub(crate) enum ResponseState {
    Receiving,
    Received,
    Failed(io::ErrorKind),
}

/// The upstream receipt state shared by its body and the workload connection.
#[derive(Clone)]
pub(crate) struct ResponseProgress {
    pub(crate) deadline: Instant,
    state: Arc<Mutex<ResponseState>>,
}

impl ResponseProgress {
    fn new(deadline: Instant, received: bool) -> Self {
        Self {
            deadline,
            state: Arc::new(Mutex::new(if received {
                ResponseState::Received
            } else {
                ResponseState::Receiving
            })),
        }
    }

    pub(crate) fn state(&self) -> ResponseState {
        *self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn received(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if matches!(*state, ResponseState::Receiving) {
            *state = ResponseState::Received;
        }
    }

    pub(crate) fn fail(&self, kind: io::ErrorKind) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !matches!(*state, ResponseState::Failed(_)) {
            *state = ResponseState::Failed(kind);
        }
    }
}

/// Send `request` through hyper. hyper never wipes its buffers, so it gets a stand-in, and
/// [`Prepared`] writes the real bytes.
async fn round_trip<S>(
    upstream: S,
    writes: &WriteCount,
    (method, head, body): (&str, Zeroizing<String>, Zeroizing<Vec<u8>>),
    status: &Cell<Option<u16>>,
    deadline: Instant,
) -> std::result::Result<UpstreamResponse, NoResponse>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let lost = |error: hyper::Error| {
        let kind = socket::error_kind(&error);
        (kind, ProxyError::Io(format!("upstream exchange: {error}")))
    };
    let stand_in = Request::builder()
        .method(method)
        .uri("/")
        .body(Empty::<Bytes>::new())
        .map_err(|e| {
            let error = ProxyError::Intercept(format!("upstream request: {e}"));
            (io::ErrorKind::InvalidInput, error)
        })?;
    let upstream = Prepared::new(Counted::new(upstream, writes.clone(), None), head, body);
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .max_headers(64)
        .max_buf_size(MAX_HEAD_BYTES)
        .handshake(TokioIo::new(upstream))
        .await
        .map_err(lost)?;
    let mut driver = ConnectionDriver(Some(Box::pin(async move {
        let _ = connection.await;
    })));
    let response = {
        let mut response = std::pin::pin!(sender.send_request(stand_in));
        std::future::poll_fn(|cx| {
            driver.poll(cx);
            response.as_mut().poll(cx)
        })
        .await
        .map_err(lost)?
    };
    status.set(Some(response.status().as_u16()));
    let (head, body) =
        http1::read_response_head(response).map_err(|error| (io::ErrorKind::InvalidData, error))?;
    let progress = ResponseProgress::new(deadline, body.is_end_stream());
    Ok(UpstreamResponse {
        head,
        body: UpstreamBody(Arc::new(Mutex::new(ResponseReader {
            body,
            driver,
            _sender: sender,
            progress,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            request: None,
        }))),
    })
}

/// The upstream connection future, polled only when its response is requested.
struct ConnectionDriver(Option<Pin<Box<dyn Future<Output = ()> + Send>>>);

impl ConnectionDriver {
    fn poll(&mut self, cx: &mut Context<'_>) {
        if let Some(driver) = &mut self.0
            && driver.as_mut().poll(cx).is_ready()
        {
            self.0 = None;
        }
    }
}

/// A response reader shared with the connection that must finish it.
#[derive(Clone)]
pub(crate) struct UpstreamBody(Arc<Mutex<ResponseReader>>);

impl UpstreamBody {
    pub(crate) fn progress(&self) -> ResponseProgress {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .progress
            .clone()
    }

    pub(crate) fn track_request(
        &mut self,
        permit: ClaimedEffectPermit,
        outcome: EffectOutcome,
    ) -> io::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .track_request(permit, outcome)
    }
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        Pin::new(&mut *self.0.lock().unwrap_or_else(|e| e.into_inner())).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).size_hint()
    }
}

/// The upstream connection and the permit whose outcome follows response receipt.
struct ResponseReader {
    body: Incoming,
    driver: ConnectionDriver,
    _sender: SendRequest<Empty<Bytes>>,
    pub(crate) progress: ResponseProgress,
    deadline: Pin<Box<Sleep>>,
    request: Option<(ClaimedEffectPermit, EffectOutcome)>,
}

impl ResponseReader {
    fn track_request(
        &mut self,
        permit: ClaimedEffectPermit,
        outcome: EffectOutcome,
    ) -> io::Result<()> {
        self.request = Some((permit, outcome));
        if matches!(self.progress.state(), ResponseState::Received) {
            self.record_request_outcome()?;
        }
        Ok(())
    }

    fn record_request_outcome(&mut self) -> io::Result<()> {
        if let Some((permit, outcome)) = self.request.take() {
            permit.record_outcome(outcome).map_err(|error| {
                io::Error::other(format!("recording upstream request outcome: {error}"))
            })?;
        }
        Ok(())
    }
}

impl Drop for ResponseReader {
    fn drop(&mut self) {
        if self.record_request_outcome().is_err() {
            eprintln!("strands-box: warning: recording upstream request outcome failed");
        }
    }
}

impl Body for ResponseReader {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        let frame = if let ResponseState::Failed(kind) = this.progress.state() {
            Some(Err(io::Error::from(kind)))
        } else if matches!(this.progress.state(), ResponseState::Receiving)
            && this.deadline.as_mut().poll(cx).is_ready()
        {
            this.progress.fail(io::ErrorKind::TimedOut);
            Some(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "upstream deadline passed",
            )))
        } else {
            this.driver.poll(cx);
            match ready!(Pin::new(&mut this.body).poll_frame(cx)) {
                Some(Err(error)) => {
                    this.progress.fail(socket::error_kind(&error));
                    Some(Err(io::Error::other(error)))
                }
                Some(Ok(frame))
                    if frame
                        .trailers_ref()
                        .is_some_and(|trailers| !trailers.is_empty()) =>
                {
                    this.progress.fail(io::ErrorKind::InvalidData);
                    Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "chunked trailers are not supported",
                    )))
                }
                frame => {
                    if frame.is_none() || this.body.is_end_stream() {
                        this.progress.received();
                    }
                    frame.map(|frame| frame.map_err(io::Error::other))
                }
            }
        };
        if !matches!(this.progress.state(), ResponseState::Receiving)
            && let Err(error) = this.record_request_outcome()
        {
            this.progress.fail(error.kind());
            return Poll::Ready(Some(Err(error)));
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// The owned request bytes written in place of hyper's stand-in and wiped after flushing.
struct Prepared<S> {
    inner: S,
    head: Zeroizing<String>,
    body: Zeroizing<Vec<u8>>,
    sent: usize,
    flushed: bool,
    reader: Option<Waker>,
}

impl<S> Prepared<S> {
    fn new(inner: S, head: Zeroizing<String>, body: Zeroizing<Vec<u8>>) -> Self {
        Self {
            inner,
            head,
            body,
            sent: 0,
            flushed: false,
            reader: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prepared<S> {
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

impl<S: AsyncWrite + Unpin> AsyncWrite for Prepared<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        stand_in: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        while !this.flushed {
            let rest = match this.sent.checked_sub(this.head.len()) {
                None => &this.head.as_bytes()[this.sent..],
                Some(at) => &this.body[at..],
            };
            if rest.is_empty() {
                ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
                this.flushed = true;
                this.head = Zeroizing::default();
                this.body = Zeroizing::default();
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
        std::result::Result<Vec<u8>, NoResponse>,
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
            let client = async {
                let response = round_trip(
                    gateway,
                    &writes,
                    (
                        "POST",
                        Zeroizing::new(std::str::from_utf8(HEAD).unwrap().to_string()),
                        Zeroizing::new(b"ok".to_vec()),
                    ),
                    &status,
                    Instant::now() + std::time::Duration::from_secs(5),
                )
                .await?;
                http1::collect(response.body, 1024)
                    .await
                    .map_err(|error| (io::ErrorKind::InvalidData, error))
            };
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
        assert_eq!(result.unwrap(), b"yes");
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
