//! The `credsd` startup preflight: confirm the daemon and each declared environment before a box
//! starts its workload.

use std::path::Path;

use crate::sources::{CredsdClient, resolve_credsd_socket};
use crate::{CredentialError, Result};

/// The credsd wire protocol this box speaks.
const REQUIRED_PROTOCOL_VERSION: u32 = 1;

/// Validate every declared `credsd` environment before the workload starts.
///
/// With no environments this is a no-op and never contacts the daemon. Otherwise it sends one
/// `system/health`, then one `credential/list` per distinct environment, and confirms each
/// environment is configured — it reads no session state. The socket resolves exactly as the
/// per-request fetch resolves it. Every failure is hard, and the message names the environment
/// or the socket and never any credential material.
pub fn credsd_preflight(socket: Option<&Path>, environments: &[&str]) -> Result<()> {
    if environments.is_empty() {
        return Ok(());
    }

    let socket = resolve_credsd_socket(socket)?;
    let client = CredsdClient::new(socket);

    let version = client.health()?;
    if version != REQUIRED_PROTOCOL_VERSION {
        return Err(CredentialError::KeystoreAccess(format!(
            "credsd speaks protocol version {version}, but this box requires version \
             {REQUIRED_PROTOCOL_VERSION}; upgrade the box or the daemon so the two agree"
        )));
    }

    let mut checked: Vec<&str> = Vec::new();
    for &environment in environments {
        if checked.contains(&environment) {
            continue;
        }
        checked.push(environment);
        check_environment(&client, environment)?;
    }
    Ok(())
}

/// Confirm one environment is configured.
///
/// The check confirms the environment exists and holds at least one credential. It reads no session
/// state: `credsd` serves valid cached credentials while the login session reads spent, so a session
/// check would refuse a run whose per-request `credential/get` would in fact succeed.
fn check_environment(client: &CredsdClient, environment: &str) -> Result<()> {
    if client.list(environment)? == 0 {
        return Err(CredentialError::Credential(format!(
            "credsd has no credential for environment {environment:?}, or this box is not \
             authorized for it"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A per-test socket path, unique across concurrent tests.
    fn socket_path() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "credsd-preflight-{}-{nonce}.sock",
            std::process::id()
        ))
    }

    /// A fake daemon that serves every connection: it reads one request line and replies with the
    /// line the `reply` closure returns for that method. Runs on a detached thread until the process
    /// exits, so a test that stops connecting mid-flow does not hang on a join.
    fn spawn_daemon(path: &Path, reply: impl Fn(&str) -> String + Send + 'static) {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).expect("bind the fake credsd socket");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                if reader.read_line(&mut request).is_err() {
                    continue;
                }
                let value: serde_json::Value = match serde_json::from_str(request.trim_end()) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let method = value["method"].as_str().unwrap_or_default();
                let _ = stream.write_all(reply(method).as_bytes());
                let _ = stream.flush();
            }
        });
    }

    /// A `system/health` reply carrying protocol `version`, in the daemon's real shape.
    fn health_reply(version: u32) -> String {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"protocol\":{version},\"version\":\"0.1.0\"}}}}\n"
        )
    }

    /// A `credential/list` reply carrying one credential. Its status is `no_session` — the check
    /// ignores session state, so a configured environment passes whatever its status reads.
    fn list_reply() -> String {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"credentials\":[{\"environment\":\"dev\",\"credential\":\"login\",\"kind\":\"session_credentials\",\"status\":\"no_session\"}]}}\n".to_string()
    }

    /// A `credential/list` reply with an empty credential set.
    fn empty_list_reply() -> String {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"credentials\":[]}}\n".to_string()
    }

    /// An `ENVIRONMENT_NOT_FOUND` error reply.
    fn not_found_reply() -> String {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"x\",\"data\":{\"code\":\"ENVIRONMENT_NOT_FOUND\"}}}\n".to_string()
    }

    /// With no declared environment the preflight never contacts the daemon. The socket is
    /// never bound, so a contact attempt would fail — Ok proves it made none.
    #[test]
    fn no_environments_never_contacts_the_daemon() {
        let unbound = socket_path();
        credsd_preflight(Some(&unbound), &[]).expect("no environments is a no-op");
    }

    /// An unreachable daemon fails, and the message names the socket path.
    #[test]
    fn an_unreachable_daemon_fails_naming_the_socket() {
        let unbound = socket_path();
        let error = credsd_preflight(Some(&unbound), &["dev"])
            .expect_err("nothing is listening on the socket");
        assert!(matches!(error, CredentialError::KeystoreAccess(_)));
        assert!(
            error.to_string().contains(&unbound.display().to_string()),
            "the error names the socket: {error}"
        );
    }

    /// A protocol version other than 1 fails, naming both versions.
    #[test]
    fn a_protocol_mismatch_fails_naming_both_versions() {
        let path = socket_path();
        spawn_daemon(path.as_path(), |method| match method {
            "system/health" => health_reply(2),
            _ => list_reply(),
        });
        let error = credsd_preflight(Some(&path), &["dev"]).expect_err("version 2 is incompatible");
        assert!(matches!(error, CredentialError::KeystoreAccess(_)));
        let message = error.to_string();
        assert!(
            message.contains("version 2") && message.contains("version 1"),
            "{message}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// An absent environment fails with a credential error naming the environment.
    #[test]
    fn an_absent_environment_fails_naming_it() {
        let path = socket_path();
        spawn_daemon(path.as_path(), |method| match method {
            "system/health" => health_reply(1),
            _ => not_found_reply(),
        });
        let error = credsd_preflight(Some(&path), &["prod-inference"])
            .expect_err("the environment is absent");
        assert!(matches!(error, CredentialError::Credential(_)));
        assert!(error.to_string().contains("prod-inference"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    /// An environment the daemon lists with no credential is treated as absent.
    #[test]
    fn an_empty_credential_set_fails() {
        let path = socket_path();
        spawn_daemon(path.as_path(), |method| match method {
            "system/health" => health_reply(1),
            _ => empty_list_reply(),
        });
        let error =
            credsd_preflight(Some(&path), &["dev"]).expect_err("an empty set is not available");
        assert!(matches!(error, CredentialError::Credential(_)));
        assert!(error.to_string().contains("dev"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    /// A live daemon and a configured environment pass, and the session state is not
    /// consulted — the `credential/list` entry reads `no_session`, yet the environment passes,
    /// because `credsd` still serves valid cached credentials while the login session reads spent.
    #[test]
    fn a_configured_environment_passes_whatever_its_session_state() {
        let path = socket_path();
        spawn_daemon(path.as_path(), |method| match method {
            "system/health" => health_reply(1),
            _ => list_reply(),
        });
        credsd_preflight(Some(&path), &["dev", "dev"]).expect("a configured environment passes");
        let _ = std::fs::remove_file(&path);
    }
}
