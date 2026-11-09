//! The workload side: hyper reads each request and writes each response.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::io;
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use hyper::body::{Body, Incoming};
use hyper::header::{HeaderName, HeaderValue, PROXY_AUTHORIZATION};
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Sleep;
use tokio_rustls::TlsAcceptor;

use crate::audit::RequestId;
use crate::client::http::{ResponseCompletion, ResponseProgress, ResponseState};
use crate::error::{ProxyError, Result};
use crate::intercept::mitm::body::ResponseBody;
use crate::intercept::mitm::connect::{self, ConnectRequest};
use crate::intercept::mitm::l7::{self, WorkloadResponse};
use crate::intercept::mitm::listener::open_governed_upstream;
use crate::intercept::mitm::{SharedState, http1, tls};
use crate::transport::socket::{self, Counted, HeadCopy, MAX_HEAD_BYTES, Socket, WriteCount};

/// Serve one connection. `connect_only` refuses plain HTTP, for the AF_UNIX transport.
pub(crate) fn serve_connection<C: Socket>(
    client: C,
    state: &SharedState,
    connect_only: bool,
) -> Result<()> {
    socket::block_on(async {
        let client = client
            .into_async()
            .map_err(|e| ProxyError::Io(format!("client socket: {e}")))?;
        let tunnel = Cell::new(None);
        let completion = ResponseCompletion::default();
        serve(client, &completion, |request, head| {
            first_request(request, head, state, connect_only, &tunnel, &completion)
        })
        .await?;
        match tunnel.take() {
            Some(tunnel) => intercept_tls(tunnel, state).await,
            None => Ok(()),
        }
    })?
}

/// An admitted CONNECT: the pending upgrade, and the open upstream.
struct Tunnel {
    upgrade: OnUpgrade,
    connect: ConnectRequest,
    upstream: TcpStream,
    correlation: RequestId,
}

/// Answer the first request on a connection: a CONNECT, or a plain-HTTP absolute-form request.
async fn first_request(
    mut request: Request<Incoming>,
    head: Vec<u8>,
    state: &SharedState,
    connect_only: bool,
    tunnel: &Cell<Option<Tunnel>>,
    completion: &ResponseCompletion,
) -> Result<WorkloadResponse> {
    // Read before `read_request` strips this hop-by-hop header.
    let token = request
        .headers()
        .get(PROXY_AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string());
    if request.method() == Method::CONNECT {
        let Some((host, port)) = request
            .uri()
            .authority()
            .and_then(|authority| connect::parse_authority(authority.as_str(), None))
        else {
            return Ok(WorkloadResponse::bare(400));
        };
        let connect = ConnectRequest { host, port };
        let correlation = RequestId::unique();
        // Open the upstream before the CONNECT ack, so a denial opens no socket.
        let upstream = match admit(state, &connect, token.as_deref(), &correlation) {
            Ok(upstream) => upstream,
            Err(refusal) => return Ok(*refusal),
        };

        // Every tunnel is terminated and inspected. A TLS failure drops it, never a downgrade.
        tunnel.set(Some(Tunnel {
            upgrade: hyper::upgrade::on(&mut request),
            connect,
            upstream,
            correlation,
        }));
        // The upstream is open; acknowledge the CONNECT.
        return Ok(WorkloadResponse::connected());
    }
    if connect_only {
        return Ok(WorkloadResponse::bare(400));
    }

    // A plain `http://` request: the same decisions, with no TLS and no CONNECT ack.
    let max_body = state.config.response_limits.max_body_bytes;
    let Ok(parsed) = http1::read_request(&head, request.into_body(), max_body).await else {
        return Ok(WorkloadResponse::bare(400));
    };
    // Only an absolute-form target names a destination.
    let Some((host, port, origin_target)) = connect::parse_absolute_target(&parsed.target) else {
        return Ok(WorkloadResponse::bare(400));
    };
    let connect = ConnectRequest { host, port };
    let correlation = RequestId::unique().with_headers(&parsed.headers);
    let upstream = match admit(state, &connect, token.as_deref(), &correlation) {
        Ok(upstream) => upstream,
        Err(refusal) => return Ok(*refusal),
    };
    l7::forward_plain(
        upstream,
        &connect,
        parsed,
        origin_target,
        state,
        correlation,
        completion,
    )
    .await
}

/// The token check, then the connect decisions and the pinned upstream socket.
fn admit(
    state: &SharedState,
    connect: &ConnectRequest,
    token: Option<&str>,
    correlation: &RequestId,
) -> std::result::Result<TcpStream, Box<WorkloadResponse>> {
    if !connect::token_ok(state.config.expected_token.as_deref(), token) {
        return Err(Box::new(WorkloadResponse::bare(407)));
    }
    open_governed_upstream(state, connect, correlation).map_err(|error| Box::new(error.response()))
}

/// Terminate the workload's TLS in the tunnel, and serve its request.
async fn intercept_tls(tunnel: Tunnel, state: &SharedState) -> Result<()> {
    let server_config = tls::server_config_for_host(&state.ca, &tunnel.connect.host)?;
    let raw = tunnel
        .upgrade
        .await
        .map_err(|e| ProxyError::Io(format!("CONNECT upgrade: {e}")))?;
    let client = TlsAcceptor::from(Arc::new(server_config))
        .accept(TokioIo::new(raw))
        .await
        .map_err(|e| ProxyError::Intercept(format!("server TLS handshake: {e}")))?;
    let Tunnel {
        connect,
        upstream,
        correlation,
        ..
    } = tunnel;
    let completion = ResponseCompletion::default();
    let completion = &completion;
    serve(client, completion, |request, head| async move {
        let max_body = state.config.response_limits.max_body_bytes;
        let parsed = http1::read_request(&head, request.into_body(), max_body).await?;
        l7::forward_tls(parsed, upstream, &connect, state, correlation, completion).await
    })
    .await
}

/// Serve one request with hyper, and record the release outcome once the response is written.
async fn serve<S, H, F>(client: S, completion: &ResponseCompletion, handle: H) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: FnOnce(Request<Incoming>, Vec<u8>) -> F,
    F: Future<Output = Result<WorkloadResponse>>,
{
    let writes = WriteCount::default();
    let head = HeadCopy::default();
    let stream = Counted::new(client, writes.clone(), Some(head.clone()));
    let handle = Cell::new(Some(handle));
    let release = Cell::new(None);
    let progress = RefCell::new(None::<(ResponseProgress, Pin<Box<Sleep>>)>);
    let progress = &progress;
    let (handle, release, writes, head) = (&handle, &release, &writes, &head);
    let service = hyper::service::service_fn(move |request| async move {
        let handle = handle
            .take()
            .ok_or_else(|| ProxyError::Intercept("one request per connection".to_string()))?;
        let head = head
            .take()
            .ok_or_else(|| ProxyError::Intercept("HTTP head exceeds limit".to_string()))?;
        let mut response = handle(request, head).await?;
        if let Some(permit) = response.release.take() {
            release.set(Some((permit, writes.get().accepted)));
        }
        if let Some(receipt) = response.progress.take() {
            let deadline = Box::pin(tokio::time::sleep_until(receipt.deadline));
            *progress.borrow_mut() = Some((receipt, deadline));
        }
        Ok::<_, ProxyError>(hyper_response(response))
    });
    let mut connection = Box::pin(
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .half_close(true)
            .auto_date_header(false)
            .max_headers(64)
            .max_buf_size(MAX_HEAD_BYTES)
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades(),
    );
    let mut shutdown_failed = false;
    let served = std::future::poll_fn(|cx| {
        if let Poll::Ready(result) = connection.as_mut().poll(cx) {
            shutdown_failed = result.as_ref().is_err_and(hyper::Error::is_shutdown);
            return Poll::Ready(
                result.map_err(|error| io::Error::new(socket::error_kind(&error), error)),
            );
        }
        if let Some((receipt, deadline)) = progress.borrow_mut().as_mut()
            && matches!(receipt.state(), ResponseState::Receiving)
            && deadline.as_mut().poll(cx).is_ready()
        {
            receipt.fail(io::ErrorKind::TimedOut);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "upstream deadline passed",
            )));
        }
        Poll::Pending
    })
    .await;
    drop(connection);
    let release = release.take().map(|(permit, start)| {
        let mut error = served.as_ref().err().map(io::Error::kind);
        let mut complete = served.is_ok() || shutdown_failed;
        if let Some((receipt, _)) = progress.borrow().as_ref() {
            match receipt.state() {
                ResponseState::Received => {}
                ResponseState::Receiving => complete = false,
                ResponseState::Failed(kind) => {
                    complete = false;
                    error = Some(kind);
                }
            }
        }
        (
            permit,
            writes.get().response_outcome(start, error, complete),
        )
    });
    let drained = completion.finish().await;
    if let Some((permit, outcome)) = release {
        permit.record_outcome(outcome).map_err(|error| {
            ProxyError::Io(format!(
                "recording governed response outcome after I/O: {error}"
            ))
        })?;
    }
    served
        .and(drained)
        .map_err(|error| ProxyError::Io(format!("serving the workload: {error}")))
}

/// The response as hyper writes it. hyper frames a body itself, so a stale length is dropped.
fn hyper_response(response: WorkloadResponse) -> Response<ResponseBody> {
    let keep_length = response.body.is_end_stream() && response.status != 204;
    let mut out = Response::new(response.body);
    *out.status_mut() = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    *out.extensions_mut() = response.header_case;
    if let Some(reason) = response.reason {
        out.extensions_mut()
            .insert(hyper::ext::ReasonPhrase::from_static(reason.as_bytes()));
    }
    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("content-length") && !keep_length {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out.headers_mut().append(name, value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::task::Context;

    use tokio::io::ReadBuf;

    use super::*;
    use crate::boundary::HeaderMap;
    use crate::effect::{ClaimedEffectPermit, EffectOutcome, EffectPermit};

    fn response(status: u16, body: &[u8]) -> WorkloadResponse {
        let mut headers = HeaderMap::new();
        headers.set("Content-Length", "42");
        WorkloadResponse {
            status,
            reason: None,
            headers,
            body: body.to_vec().into(),
            release: None,
            header_case: Default::default(),
            progress: None,
        }
    }

    /// An empty body keeps the length a `HEAD` response states; any other length goes.
    #[test]
    fn an_empty_body_keeps_the_stated_length() {
        let length = |status, body: &[u8]| {
            hyper_response(response(status, body))
                .headers()
                .get("content-length")
                .map(|value| value.to_str().unwrap().to_string())
        };
        assert_eq!(length(200, b"").as_deref(), Some("42"));
        assert_eq!(length(200, b"abc"), None);
        assert_eq!(length(204, b""), None);
    }

    #[test]
    fn a_shutdown_error_after_a_full_flush_keeps_the_release_completed() {
        struct ShutdownFails {
            request: &'static [u8],
            written: Arc<Mutex<Vec<u8>>>,
            flushed: bool,
        }

        impl AsyncRead for ShutdownFails {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buffer: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let length = self.request.len().min(buffer.remaining());
                buffer.put_slice(&self.request[..length]);
                self.request = &self.request[length..];
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for ShutdownFails {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.written.lock().unwrap().extend_from_slice(bytes);
                self.flushed = false;
                Poll::Ready(Ok(bytes.len()))
            }

            fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.flushed = true;
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                assert!(self.flushed, "HTTP delivery must flush before shutdown");
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
        }

        struct RecordingPermit(Arc<Mutex<Vec<EffectOutcome>>>);

        impl EffectPermit for RecordingPermit {
            fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
                self.0.lock().unwrap().push(outcome);
                Ok(())
            }

            fn mark_indeterminate(self: Box<Self>) {
                self.0
                    .lock()
                    .unwrap()
                    .push(EffectOutcome::Indeterminate { accepted_bytes: 0 });
            }
        }

        let written = Arc::new(Mutex::new(Vec::new()));
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let permit = ClaimedEffectPermit::new(Box::new(RecordingPermit(outcomes.clone())));
        let transport = ShutdownFails {
            request: b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            written: written.clone(),
            flushed: false,
        };
        let completion = ResponseCompletion::default();
        let error = socket::block_on(serve(transport, &completion, |_, _| async move {
            let mut reply = response(200, b"complete body");
            reply.release = Some(permit);
            Ok(reply)
        }))
        .unwrap()
        .unwrap_err();

        assert!(
            matches!(error, ProxyError::Io(ref message) if message.contains("shutting down")),
            "the shutdown failure must still reach the caller: {error}"
        );
        let written = written.lock().unwrap();
        assert!(written.starts_with(b"HTTP/1.1 200 "));
        assert!(written.ends_with(b"\r\n\r\ncomplete body"));
        assert_eq!(
            *outcomes.lock().unwrap(),
            vec![EffectOutcome::Completed(written.len())]
        );
    }
}
