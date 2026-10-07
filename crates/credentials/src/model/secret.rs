//! [`Secret`] — one resolved opaque plaintext, which cannot hold a value that could not
//! authenticate (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).

use zeroize::Zeroizing;

use crate::{CredentialError, Result, redact_credential_ref};

/// One resolved opaque secret, wiped on drop and redacted in `Debug`.
pub(crate) struct Secret(Zeroizing<String>);

impl Secret {
    /// Wrap `raw`, or refuse it as unusable.
    pub(crate) fn new(raw: Zeroizing<String>, reference: &str) -> Result<Self> {
        // The reason is named, but never the value: the message goes to an operator's terminal and
        // a diagnostic record, and a partial secret in either is the leak this crate exists to
        // prevent.
        let unusable = if raw.is_empty() {
            Some("is empty")
        } else if raw.trim().is_empty() {
            Some("is only whitespace")
        } else if raw.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            Some("contains a control character, which would forge a header boundary on the wire")
        } else {
            None
        };

        match unusable {
            Some(reason) => Err(CredentialError::Credential(format!(
                "the secret named in {:?} {reason}",
                redact_credential_ref(reference)
            ))),
            None => Ok(Self(raw)),
        }
    }

    /// The plaintext, for the vault's own attach and redact legs.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Give up the wrapper, for the one public signature that predates this type.
    pub(crate) fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A tuple struct with a redacted field, matching `AwsSessionCredentials` and `OpaqueBinding`:
        // the shape prints, the value never does, and a `{:?}` of any enclosing value stays safe.
        f.debug_tuple("Secret").field(&"[REDACTED]").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(raw: &str) -> Result<Secret> {
        Secret::new(Zeroizing::new(raw.to_string()), "env://TOKEN")
    }

    /// A usable value wraps, and reads back byte-identical.
    #[test]
    fn a_usable_value_wraps() {
        let secret = secret("ghp_real_github").expect("a real token is usable");
        assert_eq!(secret.as_str(), "ghp_real_github");
    }

    /// Every unusable spelling is a hard error, never a soft skip.
    #[test]
    fn every_unusable_spelling_fails_closed() {
        for raw in [
            "",
            " ",
            "   ",
            "\n",
            "\t ",
            "tok\r\nX-Evil: y",
            "tok\nmore",
            "a\0b",
            "a\u{7f}",
        ] {
            let err = secret(raw).expect_err("{raw:?} is unusable");
            assert!(!err.is_soft(), "{raw:?} must fail closed, not skip");
        }
    }

    /// The error names the redacted reference and no byte of the value.
    #[test]
    fn the_error_names_the_reference_and_never_the_value() {
        let err = Secret::new(
            Zeroizing::new("tok\r\nX-Evil: yes".to_string()),
            "env://GITHUB_TOKEN",
        )
        .expect_err("a control character is refused");

        let message = err.to_string();
        assert!(message.contains("[REDACTED]"), "got {message}");
        assert!(!message.contains("X-Evil"), "the value leaked: {message}");
        assert!(
            !message.contains("GITHUB_TOKEN"),
            "the reference body leaked: {message}"
        );
    }

    /// A short printable value is deliberately accepted — see the module doc.
    #[test]
    fn a_short_printable_value_is_accepted() {
        assert!(secret("a").is_ok(), "no length floor is imposed");
    }

    /// `Debug` redacts, including through a `{:?}` of an enclosing value.
    #[test]
    fn debug_redacts_the_value() {
        let secret = secret("sk-live-REALSECRET").expect("usable");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("REALSECRET"), "got {rendered}");
        assert!(rendered.contains("[REDACTED]"), "got {rendered}");

        let rendered = format!("{:?}", Some(&secret));
        assert!(!rendered.contains("REALSECRET"), "got {rendered}");
    }
}
