//! The workload side: hyper reads each request and writes each response.

use std::cell::Cell;
use std::future::Future;
use std::net::TcpStream;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue, PROXY_AUTHORIZATION};
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

use crate::audit::RequestId;
use crate::error::{ProxyError, Result};
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
        serve(client, |request, head| {
            first_request(request, head, state, connect_only, &tunnel)
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
            Err(refusal) => return Ok(refusal),
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
        Err(refusal) => return Ok(refusal),
    };
    l7::forward_plain(
        upstream,
        &connect,
        parsed,
        origin_target,
        state,
        correlation,
    )
    .await
}

/// The token check, then the connect decisions and the pinned upstream socket.
fn admit(
    state: &SharedState,
    connect: &ConnectRequest,
    token: Option<&str>,
    correlation: &RequestId,
) -> std::result::Result<TcpStream, WorkloadResponse> {
    if !connect::token_ok(state.expected_token.as_deref(), token) {
        return Err(WorkloadResponse::bare(407));
    }
    open_governed_upstream(state, connect, correlation).map_err(|error| error.response())
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
    serve(client, |request, head| async move {
        let max_body = state.config.response_limits.max_body_bytes;
        let parsed = http1::read_request(&head, request.into_body(), max_body).await?;
        l7::forward_tls(parsed, upstream, &connect, state, correlation).await
    })
    .await
}

/// Serve one request with hyper, and record the release outcome once the response is written.
async fn serve<S, H, F>(client: S, handle: H) -> Result<()>
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
        Ok::<_, ProxyError>(hyper_response(response))
    });
    let served = hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .half_close(true)
        .auto_date_header(false)
        .max_headers(64)
        .max_buf_size(MAX_HEAD_BYTES)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await;
    if let Some((permit, start)) = release.take() {
        let error = served.as_ref().err().map(|error| socket::error_kind(error));
        permit
            .record_outcome(writes.get().outcome(start, error))
            .map_err(|error| {
                ProxyError::Io(format!(
                    "recording governed response outcome after I/O: {error}"
                ))
            })?;
    }
    served.map_err(|error| ProxyError::Io(format!("serving the workload: {error}")))
}

/// The response as hyper writes it. hyper frames a body itself, so a stale length is dropped.
fn hyper_response(response: WorkloadResponse) -> Response<Full<Bytes>> {
    let keep_length = response.body.is_empty() && response.status != 204;
    let mut out = Response::new(Full::new(Bytes::from(response.body)));
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
    use super::*;
    use crate::boundary::HeaderMap;

    fn response(status: u16, body: &[u8]) -> WorkloadResponse {
        let mut headers = HeaderMap::new();
        headers.set("Content-Length", "42");
        WorkloadResponse {
            status,
            reason: None,
            headers,
            body: body.to_vec(),
            release: None,
            header_case: Default::default(),
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
}
