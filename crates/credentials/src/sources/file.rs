//! `file:///path` — read a secret from the contents of a local file.

use std::fs;
use std::io::ErrorKind;

use zeroize::Zeroizing;

use crate::sources::SecretSource;
use crate::sources::uri_reference;
use crate::{CredentialError, Locator, Result, Secret, redact_credential_ref};

/// The scheme this source claims.
const SCHEME: &str = "file";

/// Reads secrets from local files (`file:///path`).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct FileSource;

impl FileSource {
    /// Construct the source.
    pub(crate) fn new() -> Self {
        Self
    }

    /// Strip a single trailing newline (`\n` or `\r\n`) from a read file body.
    fn strip_trailing_newline(mut s: String) -> String {
        if s.ends_with('\n') {
            s.truncate(s.len() - 1);
            if s.ends_with('\r') {
                s.truncate(s.len() - 1);
            }
        }
        s
    }
}

impl SecretSource for FileSource {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn fetch(&self, loc: &Locator) -> Result<Secret> {
        // Own the parse: file:// takes a URI-form reference whose body is an absolute path.
        // The canonical form is `file:///path`, so after the scheme the remaining `/path` is the
        // filesystem path; a non-empty body is required.
        let reference = uri_reference(loc, SCHEME)?;
        let path = reference
            .strip_prefix("file://")
            .filter(|p| !p.is_empty())
            .ok_or_else(|| {
                CredentialError::Credential(format!(
                    "malformed file:// reference (expected `file:///path`): {:?}",
                    redact_credential_ref(reference)
                ))
            })?;

        match fs::read_to_string(path) {
            // The trailing-newline strip is unchanged; what changes is that its *result* must
            // still be usable, so an empty file or a bare newline is refused rather than bound
            // (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
            Ok(contents) => Secret::new(
                Zeroizing::new(Self::strip_trailing_newline(contents)),
                reference,
            ),
            // Absent or unreadable → soft miss: this one route is skipped, the vault still comes up.
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::PermissionDenied) => Err(
                CredentialError::SecretNotFound(redact_credential_ref(reference)),
            ),
            // A present-but-non-UTF-8 file (InvalidData) or any other I/O failure is hard: the
            // secret exists but can't be produced, so fail closed rather than silently skipping.
            Err(e) => Err(CredentialError::Credential(format!(
                "failed to read the file named in {:?}: {}",
                redact_credential_ref(reference),
                e.kind()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn locator(uri: &str) -> Locator {
        Locator::Uri(uri.to_string())
    }

    /// Write `contents` to a uniquely-named temp file and return its path. Uses the process id so
    /// parallel test binaries don't collide; each test uses a distinct suffix.
    fn temp_file(suffix: &str, contents: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("strands-file-src-{}-{suffix}", std::process::id()));
        let mut f = fs::File::create(&path).expect("create temp file");
        f.write_all(contents).expect("write temp file");
        path
    }

    #[test]
    fn reads_file_contents() {
        let path = temp_file("present", b"file-token-value");
        let uri = format!("file://{}", path.display());
        let got = FileSource::new().fetch(&locator(&uri)).unwrap();
        assert_eq!(got.as_str(), "file-token-value");
        fs::remove_file(&path).ok();
    }

    #[test]
    fn strips_a_single_trailing_newline() {
        let path = temp_file("newline", b"file-token-value\n");
        let uri = format!("file://{}", path.display());
        let got = FileSource::new().fetch(&locator(&uri)).unwrap();
        assert_eq!(got.as_str(), "file-token-value");
        fs::remove_file(&path).ok();
    }

    #[test]
    fn strips_crlf_and_then_refuses_an_interior_newline() {
        // The CRLF *terminator* is still stripped as one line ending — `strip_trailing_newline`'s own
        // test covers that directly. What changed is the value that remains: `line1\nline2` carries
        // an interior newline, and a multi-line value cannot be an HTTP header value, so `Secret`
        // refuses it rather than letting it forge a header boundary on the wire
        // (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
        let path = temp_file("crlf", b"line1\nline2\r\n");
        let uri = format!("file://{}", path.display());
        let err = FileSource::new()
            .fetch(&locator(&uri))
            .expect_err("an interior newline cannot ride in a header value");
        assert!(!err.is_soft(), "a control character fails closed");
        assert!(
            !err.to_string().contains("line2"),
            "the refusal must not echo the value"
        );
        fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_file_is_a_soft_miss() {
        let uri = format!(
            "file://{}/strands-file-src-does-not-exist-{}",
            std::env::temp_dir().display(),
            std::process::id()
        );
        let err = FileSource::new().fetch(&locator(&uri)).unwrap_err();
        assert!(
            err.is_soft(),
            "an unreadable file must be a soft SecretNotFound"
        );
        assert_eq!(
            err.to_string(),
            "no secret found for credential reference: file://[REDACTED]"
        );
    }

    #[test]
    fn empty_path_is_rejected_hard() {
        let err = FileSource::new().fetch(&locator("file://")).unwrap_err();
        assert!(!err.is_soft());
    }

    #[test]
    fn structured_reference_is_refused() {
        let fields = [("source", "file"), ("path", "/etc/token")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let loc = Locator::structured(fields).unwrap();
        let err = FileSource::new().fetch(&loc).unwrap_err();
        assert!(
            !err.is_soft(),
            "a structured block to file:// is a hard config error"
        );
    }

    #[test]
    fn strip_trailing_newline_edge_cases() {
        // Empty stays empty; a bare newline becomes empty; no trailing newline is untouched.
        assert_eq!(FileSource::strip_trailing_newline(String::new()), "");
        assert_eq!(FileSource::strip_trailing_newline("\n".to_string()), "");
        assert_eq!(FileSource::strip_trailing_newline("abc".to_string()), "abc");
        // Only one line ending is removed.
        assert_eq!(
            FileSource::strip_trailing_newline("abc\n\n".to_string()),
            "abc\n"
        );
    }

    #[test]
    fn scheme_is_file() {
        assert_eq!(FileSource::new().scheme(), "file");
    }
}
