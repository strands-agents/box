//! Selective TLS termination for the MITM adapter.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use super::ca::EphemeralCa;
use crate::error::{ProxyError, Result};

/// Build a rustls [`ServerConfig`] presenting the per-host leaf minted under `ca` for `host`.
/// This is the server side of interception: what the workload's client sees.
pub(super) fn server_config_for_host(
    ca: &EphemeralCa,
    host: &str,
    enable_h2: bool,
) -> Result<ServerConfig> {
    let leaf = ca.leaf_for(host)?;
    let cert_chain: Vec<CertificateDer<'static>> = leaf
        .cert_chain_der
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_der.to_vec()));

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| ProxyError::Intercept(format!("server TLS config for {host}: {e}")))?;
    if enable_h2 {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    } else {
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    Ok(config)
}

/// Build the upstream (client) rustls [`ClientConfig`] with the additive trust bundle:
/// system roots (via `webpki-roots`) plus any PEM certs supplied in `extra_ca_pems` (e.g. a route's
/// custom CA). The upstream must present a cert the box legitimately trusts — a pin rejection here
/// surfaces as a handshake error the caller treats as a hard-fail drop.
pub(super) fn upstream_client_config(extra_ca_pems: &[String]) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    // System roots — the base of the additive bundle.
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Additive: any extra CA PEMs (a route's custom CA bundle).
    for pem in extra_ca_pems {
        for cert in parse_pem_certs(pem)? {
            roots
                .add(cert)
                .map_err(|e| ProxyError::Intercept(format!("adding extra CA: {e}")))?;
        }
    }

    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Parse PEM-encoded certificates into DER, for the additive trust bundle.
fn parse_pem_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            b64.clear();
        } else if line.contains("END CERTIFICATE") {
            in_cert = false;
            use base64::Engine;
            let der = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|e| ProxyError::Intercept(format!("bad PEM base64: {e}")))?;
            certs.push(CertificateDer::from(der));
        } else if in_cert {
            b64.push_str(line.trim());
        }
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_presents_minted_leaf() {
        let ca = EphemeralCa::generate(None, None).unwrap();
        let config = server_config_for_host(&ca, "api.example.com", false);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn server_config_offers_h2_when_enabled() {
        let ca = EphemeralCa::generate(None, None).unwrap();
        let config = server_config_for_host(&ca, "api.example.com", true).unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn upstream_config_builds_with_system_roots() {
        let config = upstream_client_config(&[]);
        assert!(config.is_ok());
    }

    #[test]
    fn upstream_config_accepts_extra_ca() {
        // The ephemeral CA's own public PEM is a valid extra CA to add.
        let ca = EphemeralCa::generate(None, None).unwrap();
        let config = upstream_client_config(&[ca.ca_cert_pem().to_string()]);
        assert!(config.is_ok());
    }
}
