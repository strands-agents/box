//! An `https://` request through the gateway's CONNECT tunnel, keeping the gateway's refusal.

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use strands_shell::os::{HttpRequest, HttpResponse};
use tokio::net::TcpStream;

use crate::run::broker::shell::EgressRouting;

/// A TLS client that trusts only the gateway's intercept CA.
pub(super) fn tls_connector(egress: &EgressRouting) -> io::Result<tokio_rustls::TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&egress.ca_pem) {
        roots
            .add(certificate.map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
    }
    if roots.is_empty() {
        return Err(io::Error::other("the gateway CA holds no certificate"));
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// Send `req` to `url` inside one CONNECT tunnel, so one `net:connect` decision covers it.
pub(super) async fn send(
    egress: &EgressRouting,
    method: reqwest::Method,
    url: &url::Url,
    req: HttpRequest,
) -> io::Result<HttpResponse> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the URL names no host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let named = match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        _ => host.to_string(),
    };
    let authority = format!("{named}:{port}");
    let server_name = ServerName::try_from(host.trim_matches(['[', ']']).to_string())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let connector = tls_connector(egress)?;

    let tunnel = open(egress, &authority).await?;
    let tls = connector
        .connect(server_name, TokioIo::new(tunnel))
        .await
        .map_err(refused_connection)?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(refused_connection)?;
    drop(tokio::spawn(connection));

    let target = &url[url::Position::BeforePath..url::Position::AfterQuery];
    let mut request = hyper::Request::builder()
        .method(method)
        .uri(if target.is_empty() { "/" } else { target });
    if !req
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        let host_header = match url.port() {
            Some(port) => format!("{named}:{port}"),
            None => named.clone(),
        };
        request = request.header(hyper::header::HOST, host_header);
    }
    let has_header = |wanted: &str| {
        req.headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(wanted))
    };
    if !has_header("accept") {
        request = request.header(hyper::header::ACCEPT, "*/*");
    }
    if !has_header("authorization")
        && let Some(credentials) = basic_credentials(url)
    {
        request = request.header(hyper::header::AUTHORIZATION, credentials);
    }
    for (name, value) in &req.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if super::needs_zero_length(&req) {
        request = request.header(hyper::header::CONTENT_LENGTH, "0");
    }
    let request = request
        .body(Full::new(Bytes::from(req.body.unwrap_or_default())))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(refused_connection)?;
    super::shell_response(response, req.max_response).await
}

/// Open a CONNECT tunnel to `authority`; a refusal the gateway wrote keeps its reason.
async fn open(egress: &EgressRouting, authority: &str) -> io::Result<hyper::upgrade::Upgraded> {
    let proxy = url::Url::parse(&egress.proxy_target).map_err(io::Error::other)?;
    let address = format!(
        "{}:{}",
        proxy.host_str().unwrap_or("127.0.0.1"),
        proxy.port_or_known_default().unwrap_or(80)
    );
    let stream = TcpStream::connect(address)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(refused_connection)?;
    drop(tokio::spawn(connection.with_upgrades()));

    let connect = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(authority)
        .header(hyper::header::HOST, authority)
        .body(Full::new(Bytes::new()))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let response = sender
        .send_request(connect)
        .await
        .map_err(refused_connection)?;
    if response.status().is_success() {
        return hyper::upgrade::on(response)
            .await
            .map_err(refused_connection);
    }
    let kind = super::gateway_error_kind(response.headers());
    let status = response.status();
    if let Some(kind) = kind {
        return Err(super::read_gateway_error(kind, response.into_body()).await);
    }
    Err(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        format!("the egress gateway did not open a tunnel to {authority}: {status}"),
    ))
}

/// The `Basic` credentials a URL's user information names, as an HTTP client sends them.
fn basic_credentials(url: &url::Url) -> Option<String> {
    use base64::Engine as _;
    let decode = |part: &str| {
        percent_encoding::percent_decode_str(part)
            .decode_utf8()
            .ok()
            .map(String::from)
    };
    let username = decode(url.username())?;
    let password = url.password().map(decode);
    if username.is_empty() && password.is_none() {
        return None;
    }
    let pair = format!("{username}:{}", password.flatten().unwrap_or_default());
    Some(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    ))
}

fn refused_connection(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string())
}
