//! The one spelling of a destination host.

/// `host` without a trailing dot and in lowercase, the spelling the policy decision, the DNS
/// resolve, and the audit record agree on.
pub(crate) fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
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
}
