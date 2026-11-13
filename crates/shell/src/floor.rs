use std::io;

/// Refuse a URL whose scheme is not HTTP or whose host is a private address or `localhost`.
///
/// Deny-only, and it resolves no name.
pub fn check_url_safe(url: &str) -> io::Result<()> {
    strands_shell::vfs_kernel::check_url_safe(url)?;
    if let Ok(parsed) = url::Url::parse(url)
        && let Some(url::Host::Domain(domain)) = parsed.host()
    {
        let name = domain.trim_end_matches('.').to_ascii_lowercase();
        if name == "localhost" || name.ends_with(".localhost") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("access denied: {domain}"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spelling_of_localhost_is_refused() {
        for url in [
            "http://localhost/",
            "http://localhost./",
            "http://localhost../",
            "http://x.localhost./",
            "http://LOCALHOST/",
            "http://LocalHost./",
            "http://127.0.0.1/",
            "http://169.254.169.254/",
        ] {
            assert!(check_url_safe(url).is_err(), "{url}");
        }
        assert!(check_url_safe("https://example.com/").is_ok());
    }
}
