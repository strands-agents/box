//! The one spelling of a destination host.

use std::net::IpAddr;

/// `host` without a trailing dot and in lowercase, the spelling the policy decision, the DNS
/// resolve, and the audit record agree on.
pub fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether the gateway binds `host`, which it does for an IP literal and for an ASCII name of
/// letters, digits, `.`, `-`, and `_`.
pub fn is_bindable_host(host: &str) -> bool {
    !host.is_empty()
        && (host.parse::<IpAddr>().is_ok()
            || (host.is_ascii()
                && host.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_loses_its_trailing_dot_and_case() {
        assert_eq!(
            normalize_host("Metadata.Google.Internal."),
            "metadata.google.internal"
        );
        assert_eq!(normalize_host("169.254.169.254."), "169.254.169.254");
        assert_eq!(normalize_host("api.example.com"), "api.example.com");
    }

    /// Every trailing dot goes, so a judge that compares against this form agrees with the parser.
    #[test]
    fn a_host_loses_every_trailing_dot() {
        assert_eq!(normalize_host("api.example.com.."), "api.example.com");
        assert_eq!(normalize_host("..."), "");
    }

    /// Normalization is idempotent, so the bindable canonical forms are the fixed points.
    #[test]
    fn normalization_is_idempotent() {
        for host in [
            "API.Example.com.",
            "api.example.com",
            "",
            "...",
            "bücher.example",
            "2001:DB8::1",
        ] {
            let once = normalize_host(host);
            assert_eq!(normalize_host(&once), once, "{host:?}");
        }
    }

    #[test]
    fn a_name_an_ip_and_an_underscore_bind() {
        for host in [
            "api.example.com",
            ".api.example.com",
            "api_internal.example",
            "api-internal.example",
            "xn--bcher-kva.example",
            "localhost",
            "1.2.3.4",
            "2001:db8::1",
            "::ffff:1.2.3.4",
        ] {
            assert!(is_bindable_host(host), "{host:?}");
        }
    }

    #[test]
    fn an_empty_a_non_ascii_and_a_punctuated_host_do_not_bind() {
        for host in [
            "",
            "bücher.example",
            "ＡＰＩ.example.com",
            "api.example.com:443",
            "https://api.example.com",
            "api.example.com/path",
            "api example.com",
            "*.example.com",
            "fe80::1%eth0",
        ] {
            assert!(!is_bindable_host(host), "{host:?}");
        }
    }
}
