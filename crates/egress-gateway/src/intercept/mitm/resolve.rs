//! Resolve-once + IP pin — the DNS-rebind defense.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use crate::error::{ProxyError, Result};

/// A resolved-and-pinned destination: the IPs `host:port` resolved to, once.
#[derive(Debug, Clone)]
pub(super) struct PinnedDestination {
    /// The port to connect on.
    pub(super) port: u16,
    /// The IPs `host` resolved to — pinned; the connect uses only these.
    pub(super) ips: Vec<IpAddr>,
}

impl PinnedDestination {
    /// Resolve `host:port` **once** to its IPs. An empty resolution or a resolver error is
    /// a fail-closed [`UpstreamConnect`](ProxyError::UpstreamConnect) — never a silent retry that
    /// could re-resolve to a different address.
    #[cfg(test)]
    pub(super) fn resolve(host: &str, port: u16) -> Result<Self> {
        Self::resolve_with_override(host, port, None)
    }

    /// Resolve with an optional pinned IP override for `host` (a supervisor-provided static host→IP
    /// mapping — e.g. a split-horizon endpoint, or a test upstream). When `override_ip` is `Some`,
    /// resolution is that exact IP with no DNS lookup; the DNS-rebind pin still holds because
    /// the connect uses only the pinned address.
    pub(super) fn resolve_with_override(
        host: &str,
        port: u16,
        override_ip: Option<IpAddr>,
    ) -> Result<Self> {
        // An explicit override or a literal IP resolves without a lookup; a name goes through the
        // resolver once.
        let ips: Vec<IpAddr> = if let Some(ip) = override_ip {
            vec![ip]
        } else if let Ok(ip) = host.parse::<IpAddr>() {
            vec![ip]
        } else {
            (host, port)
                .to_socket_addrs()
                .map_err(|e| ProxyError::UpstreamConnect(format!("resolving {host}: {e}")))?
                .map(|sa| sa.ip())
                .collect()
        };
        if ips.is_empty() {
            return Err(ProxyError::UpstreamConnect(format!(
                "{host} resolved to no addresses"
            )));
        }
        Ok(Self { port, ips })
    }

    /// A [`PinnedDestination`] built from already-known IPs (e.g. in a test) without a lookup.
    #[cfg(test)]
    pub(super) fn from_ips(port: u16, ips: Vec<IpAddr>) -> Self {
        Self { port, ips }
    }

    /// The exact pinned `SocketAddr`s the connect must use — never re-resolved.
    pub(super) fn pinned_addrs(&self) -> Vec<SocketAddr> {
        self.ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.port))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_ip_resolves_to_itself() {
        let pinned = PinnedDestination::resolve("93.184.216.34", 443).unwrap();
        assert_eq!(pinned.ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            pinned.pinned_addrs(),
            vec!["93.184.216.34:443".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn localhost_resolves() {
        // `localhost` should resolve to at least one loopback address on any dev host.
        let pinned = PinnedDestination::resolve("localhost", 80).unwrap();
        assert!(!pinned.ips.is_empty());
        assert!(pinned.pinned_addrs().iter().all(|sa| sa.port() == 80));
    }

    #[test]
    fn pinned_addrs_reuses_fixed_ips_without_relookup() {
        let ips = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        let pinned = PinnedDestination::from_ips(443, ips.clone());
        let addrs = pinned.pinned_addrs();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], SocketAddr::new(ips[0], 443));
    }
}
