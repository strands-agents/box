//! [`AwsSessionCredentials`] — the structured material the AWS source produces for SigV4.

use zeroize::Zeroize;

/// The AWS secret fields SigV4 needs, plus a non-secret `region` hint.
#[derive(Clone)]
pub(crate) struct AwsSessionCredentials {
    /// AWS access key id (secret material — redacted in logs, zeroized on drop).
    pub access_key_id: String,
    /// AWS secret access key (secret material — redacted in logs, zeroized on drop).
    pub secret_access_key: String,
    /// AWS session token, if any (secret material — redacted in logs, zeroized on drop). `Some` for
    /// STS / assumed-role credentials; `None` for a long-lived IAM user key with no session token.
    pub session_token: Option<String>,
    /// Non-secret region hint. Not zeroized; may print in the clear. The signing region comes from
    /// the route, not this field.
    pub region: Option<String>,
}

impl Zeroize for AwsSessionCredentials {
    fn zeroize(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        // Wipe the token string in place when present; the non-secret region hint is left untouched.
        if let Some(token) = self.session_token.as_mut() {
            token.zeroize();
        }
    }
}

impl std::fmt::Debug for AwsSessionCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Every secret field renders [REDACTED]; only the non-secret region prints in the clear. The
        // session token prints as its presence (Some → redacted, None → absent) without leaking the
        // value or treating a bare `None` as a secret.
        let session_token = self.session_token.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("AwsSessionCredentials")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &session_token)
            .field("region", &self.region)
            .finish()
    }
}

impl std::fmt::Display for AwsSessionCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.region {
            Some(region) => write!(f, "AWS session credentials (region: {region}) [REDACTED]"),
            None => f.write_str("AWS session credentials [REDACTED]"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> AwsSessionCredentials {
        AwsSessionCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: Some("FQoGZXIvYXdzEBcaEXAMPLESESSIONTOKEN".to_string()),
            region: Some("us-east-1".to_string()),
        }
    }

    /// Every secret field is redacted in Debug/Display; the non-secret region prints in the clear.
    #[test]
    fn debug_and_display_redact_secrets_but_show_region() {
        let credentials = example();
        let debug = format!("{credentials:?}");
        let display = format!("{credentials}");

        // Region (non-secret) survives in both renderings.
        assert!(
            debug.contains("us-east-1"),
            "region hint missing from {debug:?}"
        );
        assert!(
            display.contains("us-east-1"),
            "region hint missing from {display:?}"
        );

        // Every secret field is redacted and none of the plaintext leaks.
        for rendered in [&debug, &display] {
            assert!(
                rendered.contains("[REDACTED]"),
                "no redaction marker in {rendered:?}"
            );
            for secret in [
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "FQoGZXIvYXdzEBcaEXAMPLESESSIONTOKEN",
            ] {
                assert!(
                    !rendered.contains(secret),
                    "{secret} leaked in {rendered:?}"
                );
            }
        }
    }

    /// A `None` region must not render the missing-hint case as a leak or a panic.
    #[test]
    fn display_without_region_still_redacts() {
        let credentials = AwsSessionCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
            region: None,
        };
        assert_eq!(
            format!("{credentials}"),
            "AWS session credentials [REDACTED]"
        );
        assert!(!format!("{credentials:?}").contains("AKIAIOSFODNN7EXAMPLE"));
    }

    /// Clone is required so resolved credentials can be held in `Zeroizing` and handed to the signer;
    /// confirm it preserves the payload while `Debug` still redacts the clone.
    #[test]
    fn clone_preserves_the_payload_and_stays_redacted() {
        let cloned = example().clone();
        assert_eq!(cloned.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(cloned.region.as_deref(), Some("us-east-1"));
        assert!(!format!("{cloned:?}").contains("AKIAIOSFODNN7EXAMPLE"));
    }

    /// The wipe walks into the `Some` session token and leaves the non-secret region untouched.
    #[test]
    fn zeroize_wipes_every_secret_including_the_optional_token() {
        let mut credentials = example();
        credentials.zeroize();
        assert!(credentials.access_key_id.is_empty());
        assert!(credentials.secret_access_key.is_empty());
        assert_eq!(credentials.session_token.as_deref(), Some(""));
        assert_eq!(
            credentials.region.as_deref(),
            Some("us-east-1"),
            "the region is a non-secret hint and is deliberately not wiped"
        );
    }
}
