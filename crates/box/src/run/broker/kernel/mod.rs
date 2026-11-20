//! The hosted Shell's network: HTTP through this box's egress gateway
//! (docs/design/decisions.md#shell-network-goes-through-the-egress-gateway).

use std::io;

use strands_shell::os::{HttpRequest, HttpResponse};

use crate::run::broker::shell::EgressRouting;

mod tunnel;

#[cfg(test)]
mod tests;

/// One Call's route to the egress gateway, carrying the Call's trace context.
pub(super) struct GatewayNetwork {
    egress: EgressRouting,
    correlation: telemetry::Correlation,
}

impl GatewayNetwork {
    pub(super) fn new(egress: EgressRouting, correlation: telemetry::Correlation) -> Self {
        Self {
            egress,
            correlation,
        }
    }
}

#[async_trait::async_trait]
impl box_shell::Network for GatewayNetwork {
    async fn send(&self, mut request: HttpRequest) -> io::Result<HttpResponse> {
        self.correlation.inject_http(&mut request.headers);
        self.correlation.scope(send(&self.egress, request)).await
    }
}

/// Refuse a gateway CA that no client can trust.
pub(super) fn verify_gateway_ca(egress: &EgressRouting) -> io::Result<()> {
    gateway_client(egress)
        .and_then(|_| tunnel::tls_connector(egress))
        .map(drop)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// A client that dials only the gateway, trusts only its CA, and follows no redirect.
fn gateway_client(egress: &EgressRouting) -> io::Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .proxy(reqwest::Proxy::all(&egress.proxy_target).map_err(io::Error::other)?)
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&egress.ca_pem).map_err(io::Error::other)?,
        )
        .build()
        .map_err(io::Error::other)
}

/// Send one request through the gateway, which alone decides it; `req.insecure` is not read.
async fn send(egress: &EgressRouting, req: HttpRequest) -> io::Result<HttpResponse> {
    let method: reqwest::Method = req.method.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bad HTTP method: {}", req.method),
        )
    })?;
    if let Ok(url) = url::Url::parse(&req.url)
        && url.scheme() == "https"
    {
        return tunnel::send(egress, method, &url, req).await;
    }
    let mut request = gateway_client(egress)?.request(method, &req.url);
    for (name, value) in &req.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if needs_zero_length(&req) {
        request = request.header(hyper::header::CONTENT_LENGTH, "0");
    }
    if let Some(body) = req.body {
        request = request.body(body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    shell_response(response.into(), req.max_response).await
}

/// Whether `req` carries an empty body that no header states the length of.
fn needs_zero_length(req: &HttpRequest) -> bool {
    req.body.as_ref().is_some_and(Vec::is_empty)
        && !req
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
}

/// The Shell's view of a gateway `response`; a response the gateway wrote becomes an error.
async fn shell_response<B>(
    response: hyper::Response<B>,
    max_response: usize,
) -> io::Result<HttpResponse>
where
    B: hyper::body::Body<Data = bytes::Bytes>,
    B::Error: std::fmt::Display,
{
    if let Some(kind) = gateway_error_kind(response.headers()) {
        return Err(read_gateway_error(kind, response.into_body()).await);
    }
    let status = response.status();
    let version = match response.version() {
        hyper::Version::HTTP_2 => "2",
        hyper::Version::HTTP_11 => "1.1",
        _ => "1.0",
    };
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();
    let body = read_body(response.into_body(), max_response).await?;
    Ok(HttpResponse {
        status: status.as_u16(),
        headers,
        body,
        version: version.to_string(),
        reason: status.canonical_reason().unwrap_or("").to_string(),
    })
}

/// The error kind of a response the gateway wrote, or `None` for one it relayed: `PermissionDenied`
/// for a refusal, so `curl` exits 1, and `Other` for a failure, so `curl` exits 6.
fn gateway_error_kind(headers: &hyper::HeaderMap) -> Option<io::ErrorKind> {
    let origin = headers.get(egress_gateway::PROXY_ORIGIN_HEADER)?;
    Some(if origin == egress_gateway::PROXY_ORIGIN_VALUE {
        io::ErrorKind::PermissionDenied
    } else {
        io::ErrorKind::Other
    })
}

/// The most bytes of a gateway-originated body read before its first line is reported.
const MAX_GATEWAY_ERROR: usize = 16 * 1024;

/// The `kind` error a gateway-originated `body` states, read to `MAX_GATEWAY_ERROR` bytes at most.
async fn read_gateway_error<B>(kind: io::ErrorKind, body: B) -> io::Error
where
    B: hyper::body::Body<Data = bytes::Bytes>,
{
    use http_body_util::BodyExt as _;
    let mut body = std::pin::pin!(body);
    let mut read = Vec::new();
    while read.len() < MAX_GATEWAY_ERROR
        && let Some(Ok(frame)) = body.frame().await
    {
        if let Ok(chunk) = frame.into_data() {
            let room = MAX_GATEWAY_ERROR - read.len();
            read.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
    }
    gateway_error(kind, &String::from_utf8_lossy(&read))
}

/// Read `body`, refusing one longer than `limit` bytes when `limit` is not zero.
async fn read_body<B>(body: B, limit: usize) -> io::Result<Vec<u8>>
where
    B: hyper::body::Body<Data = bytes::Bytes>,
    B::Error: std::fmt::Display,
{
    use http_body_util::BodyExt as _;
    let mut body = std::pin::pin!(body);
    let mut read = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| io::Error::other(error.to_string()))?;
        if let Ok(chunk) = frame.into_data() {
            if limit > 0 && read.len() + chunk.len() > limit {
                return Err(io::Error::other("response body too large"));
            }
            read.extend_from_slice(&chunk);
        }
    }
    Ok(read)
}

/// The `kind` error a gateway-originated `body` states, as the workload reads it.
fn gateway_error(kind: io::ErrorKind, body: &str) -> io::Error {
    let fallback = if kind == io::ErrorKind::PermissionDenied {
        "the egress gateway refused this request"
    } else {
        "the egress gateway could not complete this request"
    };
    let reason = body
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or(fallback);
    io::Error::new(kind, reason)
}
