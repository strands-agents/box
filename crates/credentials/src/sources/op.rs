//! `op://vault/item/field` — read a secret from 1Password via the authenticated `op` CLI.

use zeroize::Zeroizing;

use crate::sources::SecretSource;
use crate::sources::uri_reference;
use crate::{CredentialError, Locator, Result, Secret, redact_credential_ref};

/// The scheme this source claims.
const SCHEME: &str = "op";

/// How long to wait for the `op` CLI before giving up.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How often the wait loop polls the child for exit while counting down [`TIMEOUT`].
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Characters an `op://` reference may not contain.
const DISALLOWED: &[char] = &[
    // shell metacharacters
    ';', '&', '|', '$', '`', '(', ')', '<', '>', '{', '}', '[', ']', '!', '*', '\\', '"', '\'',
    // whitespace / control
    ' ', '\t', '\n', '\r', '\0', // URI query/fragment — an op reference is a bare path
    '?', '#',
];

/// The subprocess seam: run the `op` CLI for a validated reference and return its raw stdout bytes.
trait OpCommandRunner: Send + Sync {
    /// Run `op read -- <reference>` (or the mock equivalent) and return raw stdout on success.
    /// `reference` has already been validated by the caller. Failures are the crate's hard
    /// [`CredentialError`] taxonomy.
    fn run(&self, reference: &str) -> Result<Vec<u8>>;
}

/// Reads secrets from 1Password (`op://vault/item/field`) via the authenticated `op` CLI.
pub(crate) struct OnePasswordSource {
    runner: Box<dyn OpCommandRunner>,
}

impl OnePasswordSource {
    /// Construct the source backed by the real `op` CLI.
    pub(crate) fn new() -> Self {
        Self {
            runner: Box::new(OpCliRunner),
        }
    }

    /// Construct the source backed by a custom runner — the test seam for exercising the
    /// validate/convert/zeroize/trim path without a real `op` binary.
    #[cfg(test)]
    fn with_runner(runner: Box<dyn OpCommandRunner>) -> Self {
        Self { runner }
    }

    /// Validate an `op://` reference *before* any process is spawned.
    fn validate(reference: &str) -> Result<()> {
        let reject = |why: &str| {
            Err(CredentialError::Credential(format!(
                "malformed op:// reference ({why}): {:?}",
                redact_credential_ref(reference)
            )))
        };

        let body = match reference.strip_prefix("op://").filter(|b| !b.is_empty()) {
            Some(body) => body,
            None => return reject("expected `op://vault/item/field`"),
        };
        if body.contains(DISALLOWED) {
            return reject("contains a disallowed character");
        }
        let mut segments = 0usize;
        for segment in body.split('/') {
            if segment.is_empty() {
                return reject("has an empty path segment");
            }
            segments += 1;
        }
        if segments < 3 {
            return reject("must have at least 3 segments (vault/item/field)");
        }
        Ok(())
    }
}

impl Default for OnePasswordSource {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for OnePasswordSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The runner holds no secret material; keep the output a stable audit line.
        f.debug_struct("OnePasswordSource").finish_non_exhaustive()
    }
}

impl SecretSource for OnePasswordSource {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn fetch(&self, loc: &Locator) -> Result<Secret> {
        // Own the parse: op:// takes a URI-form reference. A structured block is a hard
        // config mistake, handled by the shared guard.
        let reference = uri_reference(loc, SCHEME)?;

        // Reject a malformed or hostile reference before spawning anything.
        Self::validate(reference)?;

        // Shell out (or hit the mock). The raw stdout bytes carry the secret.
        let stdout = self.runner.run(reference)?;

        // Convert the stdout buffer straight into a Zeroizing<String> — String::from_utf8 reuses
        // the Vec's allocation, so the secret lives in exactly one buffer and that buffer is wiped
        // on drop. On non-UTF-8, wipe the bytes the error still owns before failing closed.
        let mut secret = match String::from_utf8(stdout) {
            Ok(s) => Zeroizing::new(s),
            Err(e) => {
                let _wipe = Zeroizing::new(e.into_bytes());
                return Err(CredentialError::Credential(format!(
                    "the 1Password CLI (`op`) returned non-UTF-8 output for {:?}",
                    redact_credential_ref(reference)
                )));
            }
        };

        // Trim the single trailing newline the CLI appends (in place, so no un-wiped copy).
        trim_trailing_newline(&mut secret);
        // A zero-exit `op` with empty stdout is refused here rather than bound as a credential
        // (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable),
        // the third of C1's three spellings.
        Secret::new(secret, reference)
    }
}

/// Strip a single trailing newline (`\n` or `\r\n`) in place, wiping nothing else.
fn trim_trailing_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.truncate(s.len() - 1);
        if s.ends_with('\r') {
            s.truncate(s.len() - 1);
        }
    }
}

/// The production runner: shells out to the user's authenticated `op` CLI.
struct OpCliRunner;

impl OpCommandRunner for OpCliRunner {
    fn run(&self, reference: &str) -> Result<Vec<u8>> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        use std::time::Instant;

        // No shell: argv goes straight to `op`, so the reference can't inject a command. `--`
        // stops `op` from parsing the reference as a flag. Null stdin so a prompt can't block;
        // stderr discarded so `op`'s diagnostics never land in this process's output.
        let mut child = Command::new("op")
            .arg("read")
            .arg("--")
            .arg(reference)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                CredentialError::Credential(format!(
                    "failed to run the 1Password CLI (`op`): {}",
                    e.kind()
                ))
            })?;

        // Read stdout on a thread so a large secret can't deadlock the pipe while we poll for exit.
        let mut stdout = child.stdout.take();
        let reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(ref mut out) = stdout {
                let _ = out.read_to_end(&mut buf);
            }
            buf
        });

        // Poll for exit, enforcing the 30-second timeout: a hung `op` is killed, not waited on
        // forever.
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        // Wipe whatever partial output was captured before failing closed.
                        let _wipe = Zeroizing::new(reader.join().unwrap_or_default());
                        return Err(CredentialError::Credential(
                            "the 1Password CLI (`op`) did not respond within 30s".to_string(),
                        ));
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _wipe = Zeroizing::new(reader.join().unwrap_or_default());
                    return Err(CredentialError::Credential(format!(
                        "failed while waiting for the 1Password CLI (`op`): {}",
                        e.kind()
                    )));
                }
            }
        };

        let stdout = reader.join().unwrap_or_default();
        if !status.success() {
            // `op` failed: item not found, not signed in, no access, … We can't distinguish
            // "genuinely absent" from "exists but unavailable" without parsing stderr, so fail
            // closed rather than soft-skipping the route. Wipe any bytes read before erroring.
            let _wipe = Zeroizing::new(stdout);
            return Err(CredentialError::Credential(format!(
                "the 1Password CLI (`op`) exited unsuccessfully ({status})"
            )));
        }
        Ok(stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator(uri: &str) -> Locator {
        Locator::Uri(uri.to_string())
    }

    /// A runner that panics if invoked — proves a reference was rejected *before* any spawn.
    struct PanicRunner;
    impl OpCommandRunner for PanicRunner {
        fn run(&self, _reference: &str) -> Result<Vec<u8>> {
            panic!("runner must not be invoked: an invalid URI must be rejected before spawning");
        }
    }

    /// A runner that returns canned stdout bytes, standing in for `op`.
    struct CannedRunner(Vec<u8>);
    impl OpCommandRunner for CannedRunner {
        fn run(&self, _reference: &str) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    /// A runner that records the reference it was handed, to prove the validated URI is forwarded.
    struct RecordingRunner(std::sync::Mutex<Vec<String>>);
    impl OpCommandRunner for RecordingRunner {
        fn run(&self, reference: &str) -> Result<Vec<u8>> {
            self.0.lock().unwrap().push(reference.to_string());
            Ok(b"recorded-secret".to_vec())
        }
    }

    fn source_with(runner: impl OpCommandRunner + 'static) -> OnePasswordSource {
        OnePasswordSource::with_runner(Box::new(runner))
    }

    #[test]
    fn scheme_is_op() {
        assert_eq!(OnePasswordSource::new().scheme(), "op");
    }

    #[test]
    fn reads_a_well_formed_reference() {
        let src = source_with(CannedRunner(b"op-token-value".to_vec()));
        let got = src.fetch(&locator("op://Private/GitHub/token")).unwrap();
        assert_eq!(got.as_str(), "op-token-value");
    }

    #[test]
    fn accepts_more_than_three_segments() {
        let src = source_with(CannedRunner(b"v".to_vec()));
        // op supports an optional section: op://vault/item/section/field.
        assert!(src.fetch(&locator("op://vault/item/section/field")).is_ok());
    }

    #[test]
    fn strips_a_single_trailing_newline() {
        let src = source_with(CannedRunner(b"op-token-value\n".to_vec()));
        let got = src.fetch(&locator("op://Private/GitHub/token")).unwrap();
        assert_eq!(got.as_str(), "op-token-value");
    }

    #[test]
    fn strips_crlf_and_then_refuses_an_interior_newline() {
        // The CRLF terminator is stripped (see `trim_trailing_newline`'s own tests); the remaining
        // `line1\nline2` is refused, because a multi-line value cannot be an HTTP header value
        // (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
        let src = source_with(CannedRunner(b"line1\nline2\r\n".to_vec()));
        let err = src
            .fetch(&locator("op://Private/GitHub/token"))
            .expect_err("an interior newline cannot ride in a header value");
        assert!(!err.is_soft(), "a control character fails closed");
    }

    /// The validated reference is forwarded verbatim to the runner (`op read -- <uri>`).
    #[test]
    fn runner_receives_full_reference() {
        let runner = std::sync::Arc::new(RecordingRunner(std::sync::Mutex::new(Vec::new())));
        // Wrap the Arc in a thin forwarder so the source owns a Box while we keep the Arc.
        struct Forward(std::sync::Arc<RecordingRunner>);
        impl OpCommandRunner for Forward {
            fn run(&self, reference: &str) -> Result<Vec<u8>> {
                self.0.run(reference)
            }
        }
        let src = OnePasswordSource::with_runner(Box::new(Forward(runner.clone())));
        let _ = src.fetch(&locator("op://Private/GitHub/token")).unwrap();
        let seen = runner.0.lock().unwrap();
        assert_eq!(seen.as_slice(), ["op://Private/GitHub/token".to_string()]);
    }

    #[test]
    fn non_utf8_output_is_hard_and_does_not_leak() {
        let src = source_with(CannedRunner(vec![0xff, 0xfe, 0xfd]));
        let err = src
            .fetch(&locator("op://Private/GitHub/token"))
            .unwrap_err();
        assert!(!err.is_soft(), "non-UTF-8 op output must fail closed");
        // The reference is redacted; the raw bytes never appear.
        assert!(err.to_string().contains("op://[REDACTED]"));
        assert!(!err.to_string().contains("Private"));
    }

    #[test]
    fn structured_reference_is_refused() {
        let fields = [("source", "op"), ("item", "GitHub")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let loc = Locator::structured(fields).unwrap();
        let err = source_with(PanicRunner).fetch(&loc).unwrap_err();
        assert!(
            !err.is_soft(),
            "a structured block to op:// is a hard config error"
        );
    }

    /// Every malformed form is rejected *before* the runner is invoked — the `PanicRunner` proves
    /// no process is ever spawned for an invalid reference.
    #[test]
    fn invalid_references_are_rejected_before_spawning() {
        let bad = [
            "op://",                      // empty body
            "op://vault",                 // 1 segment
            "op://vault/item",            // 2 segments (need >= 3)
            "op://vault//field",          // empty segment
            "op://vault/item/field/",     // trailing empty segment
            "op://vault/item/field?x=1",  // query marker
            "op://vault/item/field#frag", // fragment marker
            "op://vault/item/$(whoami)",  // command substitution
            "op://vault/item/`id`",       // backtick substitution
            "op://vault/item/a;rm -rf",   // command separator + space
            "op://vault/item/a|b",        // pipe
            "op://vault/item/a&b",        // background
            "op://vault/item/a\nb",       // embedded newline
            "op://vault/item/with space", // whitespace
            "https://vault/item/field",   // wrong scheme (no op:// prefix)
        ];
        for uri in bad {
            let err = source_with(PanicRunner).fetch(&locator(uri)).unwrap_err();
            assert!(
                !err.is_soft(),
                "invalid reference {uri:?} must fail closed, not soft-skip"
            );
            // The error redacts the reference — never echoes the (possibly hostile) body.
            assert!(
                !err.to_string().contains("whoami") && !err.to_string().contains("rm -rf"),
                "reference body leaked for {uri:?}"
            );
        }
    }

    #[test]
    fn validate_accepts_canonical_and_sectioned_forms() {
        assert!(OnePasswordSource::validate("op://vault/item/field").is_ok());
        assert!(OnePasswordSource::validate("op://vault/item/section/field").is_ok());
    }

    /// 18.3 — an `op://` reference resolves to opaque material through the stubbed runner seam (no
    /// real 1Password), exactly like other opaque types — so at the store layer it takes the same
    /// static/opaque path and would be minted a Phantom_Token. The locator body stays out of any
    /// diagnostic (the redacting error path is proven in `non_utf8_output_is_hard_and_does_not_leak`).
    #[test]
    fn op_resolves_to_opaque_like_other_opaque_types() {
        let src = source_with(CannedRunner(b"op-real-secret\n".to_vec()));
        let secret = src.fetch(&locator("op://Private/GitHub/token")).unwrap();
        // Resolves to a plain opaque secret string (trailing newline stripped) — the shape the store
        // wraps as `CredentialMaterial::Opaque` and then mints a phantom for.
        assert_eq!(secret.as_str(), "op-real-secret");
    }
}
