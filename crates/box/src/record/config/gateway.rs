//! `[gateway]`: settings that apply to every request through the box's egress gateway.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// The box-wide egress gateway settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Gateway {
    /// The hosts whose plain `http://` request to port 80 the gateway decides and sends as
    /// `https://` on port 443.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) upgrade_http: Vec<String>,
}

impl Gateway {
    pub(super) fn is_default(&self) -> bool {
        self.upgrade_http.is_empty()
    }

    /// Refuse an `upgrade_http` entry that is not one host name.
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        for entry in &self.upgrade_http {
            if let Some(reason) = not_a_host_name(entry) {
                return Err(ConfigError::Contract {
                    reason: format!(
                        "`[gateway] upgrade_http` entry {entry:?} is not a host name: {reason}; \
                         write a host name alone, such as \"static.rust-lang.org\""
                    ),
                });
            }
        }
        Ok(())
    }
}

/// Why `entry` is not a host name the gateway can upgrade, or `None` when it is one.
fn not_a_host_name(entry: &str) -> Option<&'static str> {
    if entry.contains("://") {
        return Some("it names a scheme");
    }
    if entry.contains('*') {
        return Some("it is a wildcard");
    }
    let bare = entry
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(entry);
    if bare.parse::<IpAddr>().is_ok() {
        return Some("it is an IP address");
    }
    if entry.contains(':') {
        return Some("it names a port");
    }
    if entry.contains('/') {
        return Some("it names a path");
    }
    let host = egress_gateway::normalize_host(entry);
    if host.is_empty() {
        return Some("it is empty");
    }
    if !egress_gateway::is_bindable_host(&host) {
        return Some("it holds a character other than a letter, a digit, '.', '-', or '_'");
    }
    if host.split('.').any(str::is_empty) {
        return Some("it has an empty label");
    }
    if host.parse::<IpAddr>().is_ok()
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Some("it is an IP address");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(entries: &[&str]) -> Gateway {
        Gateway {
            upgrade_http: entries.iter().map(|entry| entry.to_string()).collect(),
        }
    }

    #[test]
    fn a_host_name_is_accepted() {
        for entry in [
            "static.rust-lang.org",
            "Static.Rust-Lang.Org",
            "static.rust-lang.org.",
            "localhost",
            "my_host.internal",
        ] {
            assert!(gateway(&[entry]).validate().is_ok(), "{entry:?}");
        }
        assert!(gateway(&[]).validate().is_ok());
        assert!(gateway(&[]).is_default());
    }

    #[test]
    fn an_entry_that_is_not_a_host_name_is_refused_with_its_reason() {
        for (entry, reason) in [
            ("http://static.rust-lang.org", "it names a scheme"),
            ("https://static.rust-lang.org", "it names a scheme"),
            ("static.rust-lang.org:80", "it names a port"),
            ("static.rust-lang.org:443", "it names a port"),
            ("*.rust-lang.org", "it is a wildcard"),
            ("*", "it is a wildcard"),
            ("127.0.0.1", "it is an IP address"),
            ("::1", "it is an IP address"),
            ("[::1]", "it is an IP address"),
            ("2001:db8::1", "it is an IP address"),
            ("10.0.0", "it is an IP address"),
            ("static.rust-lang.org/dist", "it names a path"),
            ("", "it is empty"),
            ("...", "it is empty"),
            ("static rust", "a character other than"),
            ("bücher.example", "a character other than"),
            ("static..rust-lang.org", "an empty label"),
        ] {
            let error = gateway(&["static.rust-lang.org", entry])
                .validate()
                .expect_err(entry)
                .to_string();
            assert!(error.contains(reason), "{entry:?}: {error}");
            assert!(error.contains("`[gateway] upgrade_http`"), "{error}");
        }
    }
}
