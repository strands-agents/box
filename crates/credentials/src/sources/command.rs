//! PROTOTYPE (throwaway): a secret source that runs an operator-declared program.
//!
//! The contract `box.secret-source.v1`: Box runs `command` with `args`, where the one argument
//! `{ref}` is replaced by the secret reference. The environment is composed: `HOME`, a fixed
//! `PATH`, and only the variables `pass_env` names. Stdin is closed. Stdout is the secret.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::sources::{SecretSource, uri_reference};
use crate::{CredentialError, Locator, Result, Secret, redact_credential_ref};

/// The argument a declared program receives the secret reference in.
pub const REFERENCE_ARGUMENT: &str = "{ref}";

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(20);
const STDOUT_CAP: usize = 64 * 1024;
const STDERR_CAP: usize = 4 * 1024;
const FIXED_PATH: &str = "/usr/bin:/bin";

/// One operator-declared secret source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSourceCommand {
    /// The URI scheme this source claims, such as `op`.
    pub scheme: String,
    /// The absolute path of the program.
    pub command: PathBuf,
    /// The arguments; [`REFERENCE_ARGUMENT`] is replaced by the reference.
    pub args: Vec<String>,
    /// The variables the program inherits from the run process.
    pub pass_env: Vec<String>,
    /// The device and inode judged at configure; any other file at `command` is refused.
    pub identity: Option<(u64, u64)>,
}

pub(crate) struct CommandSource {
    scheme: &'static str,
    spec: SecretSourceCommand,
}

impl CommandSource {
    pub(crate) fn new(spec: SecretSourceCommand) -> Self {
        // PROTOTYPE: the registry keys sources by `&'static str`.
        let scheme: &'static str = Box::leak(spec.scheme.clone().into_boxed_str());
        Self { scheme, spec }
    }

    fn run(&self, reference: &str) -> Result<Vec<u8>> {
        let redacted = redact_credential_ref(reference);
        let fail = |why: String| {
            CredentialError::Credential(format!(
                "secret source `{}` ({}) failed for {redacted:?}: {why}",
                self.scheme,
                self.spec.command.display()
            ))
        };
        if let Some(expected) = self.spec.identity {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(&self.spec.command)
                .map_err(|e| fail(format!("cannot inspect the program: {e}")))?;
            if (metadata.dev(), metadata.ino()) != expected {
                return Err(fail(
                    "the program is not the file Box judged at configure; refusing to run it"
                        .to_string(),
                ));
            }
        }
        let mut command = Command::new(&self.spec.command);
        command
            .args(self.spec.args.iter().map(|arg| {
                if arg == REFERENCE_ARGUMENT {
                    reference
                } else {
                    arg.as_str()
                }
            }))
            .env_clear()
            .env("PATH", FIXED_PATH)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(home) = std::env::var_os("HOME") {
            command.env("HOME", home);
        }
        for name in &self.spec.pass_env {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let mut child = command
            .spawn()
            .map_err(|e| fail(format!("did not start: {e}")))?;
        let mut stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let out = std::thread::spawn(move || read_capped(&mut stdout, STDOUT_CAP));
        let err = std::thread::spawn(move || read_capped(&mut stderr, STDERR_CAP));
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| fail(e.to_string()))? {
                break status;
            }
            if started.elapsed() > TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail(format!("timed out after {}s", TIMEOUT.as_secs())));
            }
            std::thread::sleep(POLL);
        };
        let (stdout, overflow) = out.join().expect("stdout reader");
        let stdout = Zeroizing::new(stdout);
        let (stderr, _) = err.join().expect("stderr reader");
        if !status.success() {
            let message = String::from_utf8_lossy(&stderr);
            let first = message
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("")
                .trim()
                .replace(reference, &redacted);
            return Err(fail(format!("exited with {status}: {first}")));
        }
        if overflow {
            return Err(fail(format!("printed more than {STDOUT_CAP} bytes")));
        }
        Ok(stdout.to_vec())
    }
}

fn read_capped(reader: &mut impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut overflow = false;
    while let Ok(n) = reader.read(&mut buffer) {
        if n == 0 {
            break;
        }
        let room = cap.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..n.min(room)]);
        overflow |= n > room;
    }
    buffer.fill(0);
    (kept, overflow)
}

impl SecretSource for CommandSource {
    fn scheme(&self) -> &'static str {
        self.scheme
    }

    fn fetch(&self, loc: &Locator) -> Result<Secret> {
        let reference = uri_reference(loc, self.scheme)?;
        if reference.starts_with('-') || reference.contains(['\0', '\n']) {
            return Err(CredentialError::Credential(format!(
                "malformed reference for secret source `{}`",
                self.scheme
            )));
        }
        let stdout = self.run(reference)?;
        let mut secret = match String::from_utf8(stdout) {
            Ok(text) => Zeroizing::new(text),
            Err(error) => {
                let _wipe = Zeroizing::new(error.into_bytes());
                return Err(CredentialError::Credential(format!(
                    "secret source `{}` printed non-UTF-8 output",
                    self.scheme
                )));
            }
        };
        while secret.ends_with('\n') || secret.ends_with('\r') {
            secret.pop();
        }
        Secret::new(secret, reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ss-proto-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("in")).unwrap();
        dir.join("in")
    }

    fn program(dir: &std::path::Path, body: &str) -> PathBuf {
        let path = dir.join("source");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn spec(command: PathBuf, identity: Option<(u64, u64)>) -> SecretSourceCommand {
        SecretSourceCommand {
            scheme: "t".into(),
            command,
            args: vec![REFERENCE_ARGUMENT.into()],
            pass_env: vec![],
            identity,
        }
    }

    #[test]
    fn the_judged_program_runs_and_a_replaced_one_is_refused() {
        let dir = tempdir("swap");
        let path = program(&dir, "printf real-secret");
        let meta = std::fs::metadata(&path).unwrap();
        let source = CommandSource::new(spec(path.clone(), Some((meta.dev(), meta.ino()))));
        let locator = Locator::parse_uri("t://item").unwrap();
        assert_eq!(source.fetch(&locator).unwrap().as_str(), "real-secret");

        // Replace the file by rename, as a writer of the directory would.
        let fake = program(&dir.join(".."), "printf attacker");
        let swapped = dir.join("swap");
        std::fs::rename(&fake, &swapped).unwrap();
        std::fs::rename(&swapped, &path).unwrap();
        let error = source.fetch(&locator).unwrap_err().to_string();
        assert!(error.contains("not the file Box judged"), "{error}");
    }

    #[test]
    fn the_program_gets_a_composed_environment() {
        let dir = tempdir("env");
        let path = program(&dir, "printf '%s' \"${LEAK:-none}\"");
        // SAFETY (test): the variable is namespaced to this test.
        unsafe { std::env::set_var("LEAK", "inherited") };
        let source = CommandSource::new(spec(path, None));
        let value = source.fetch(&Locator::parse_uri("t://x").unwrap());
        // An empty secret is refused, so `none` proves the variable did not reach the program.
        assert_eq!(value.unwrap().as_str(), "none");
    }
}
