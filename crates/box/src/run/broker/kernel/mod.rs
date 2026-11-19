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
    if let Some(body) = req.body {
        request = request.body(body);
    }
    let mut response = request
        .send()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;

    if response
        .headers()
        .contains_key(egress_gateway::PROXY_ORIGIN_HEADER)
    {
        return Err(refusal(&response.text().await.unwrap_or_default()));
    }

    let status = response.status();
    let version = match response.version() {
        reqwest::Version::HTTP_2 => "2",
        reqwest::Version::HTTP_11 => "1.1",
        _ => "1.0",
    };
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
        if req.max_response > 0 && body.len() + chunk.len() > req.max_response {
            return Err(io::Error::other("response body too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(HttpResponse {
        status: status.as_u16(),
        headers,
        body,
        version: version.to_string(),
        reason: status.canonical_reason().unwrap_or("").to_string(),
    })
}

/// The refusal a gateway-originated `body` states, as the workload reads it.
fn refusal(body: &str) -> io::Error {
    let reason = body
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("the egress gateway refused this request");
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
