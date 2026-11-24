//! The `credsd` startup preflight: confirm the daemon and each declared credential before a box
//! starts its workload.

use std::path::Path;

use crate::sources::{
    ACCESS_TOKEN_TYPE, CredsdClient, SESSION_CREDENTIALS_TYPE, resolve_credsd_socket,
};
use crate::{CredentialError, Result};

/// The credsd wire protocol this box speaks.
const REQUIRED_PROTOCOL_VERSION: u32 = 1;

/// Validate every declared `credsd` credential before the workload starts.
///
/// With no credentials this is a no-op and never contacts the daemon. Otherwise it sends one
/// `system/health` and one `credential/list`, and confirms each named credential is listed. It
/// reads no session state. The socket resolves exactly as the per-request fetch resolves it. Every
/// failure is hard, and the message names the credential, the list request, or the socket, and
/// never any material.
pub fn credsd_preflight(socket: Option<&Path>, credentials: &[&str]) -> Result<()> {
    if credentials.is_empty() {
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

    let listed = client.list()?;
    for &credential in credentials {
        if !listed.iter().any(|name| name == credential) {
            return Err(CredentialError::Credential(format!(
                "credsd has no credential {credential:?}, or this box is not authorized for it"
            )));
        }
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

    /// A `credential/list` reply carrying the credentials `dev` and `staging`, in the daemon's real
    /// entry shape. Each status is `no_session`: the check ignores session state.
    fn list_reply() -> String {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"credentials\":[{\"credential\":\"dev\",\"kind\":\"session_credentials\",\"source\":\"aws_idc_sso\",\"status\":\"no_session\",\"tags\":{}},{\"credential\":\"staging\",\"kind\":\"session_credentials\",\"source\":\"aws_login\",\"status\":\"no_session\",\"tags\":{}}]}}\n".to_string()
    }

    /// A `credential/list` reply with an empty credential set.
    fn empty_list_reply() -> String {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"credentials\":[]}}\n".to_string()
    }

    /// A `CREDENTIAL_NOT_FOUND` error reply, which credsd sends to an unauthorized caller.
    fn not_found_reply() -> String {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"x\",\"data\":{\"code\":\"CREDENTIAL_NOT_FOUND\"}}}\n".to_string()
    }

    /// A fake daemon that records each `credential/list` request's params.
    fn spawn_recording_daemon(path: &Path) -> std::sync::mpsc::Receiver<serde_json::Value> {
        let (sender, receiver) = std::sync::mpsc::channel();
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
                let reply = if value["method"] == "system/health" {
                    health_reply(1)
                } else {
                    let _ = sender.send(value["params"].clone());
                    list_reply()
                };
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.flush();
            }
        });
        receiver
    }

    /// With no declared credential the preflight never contacts the daemon. The socket is
    /// never bound, so a contact attempt would fail — Ok proves it made none.
    #[test]
    fn no_credentials_never_contacts_the_daemon() {
        let unbound = socket_path();
        credsd_preflight(Some(&unbound), &[]).expect("no credentials is a no-op");
    }

    /// An unreachable daemon fails, and the message names the socket path.
    #[test]
    fn an_unreachable_daemon_fails_naming_the_socket() {
        let unbound = socket_path();
        let error = credsd_preflight(Some(&unbound), &["dev"], &[])
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
        let error =
            credsd_preflight(Some(&path), &["dev"], &[]).expect_err("version 2 is incompatible");
        assert!(matches!(error, CredentialError::KeystoreAccess(_)));
        let message = error.to_string();
        assert!(
            message.contains("version 2") && message.contains("version 1"),
            "{message}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A credential the daemon does not list fails with a credential error naming it.
    #[test]
    fn an_unlisted_credential_fails_naming_it() {
        let path = socket_path();
        spawn_daemon(path.as_path(), |method| match method {
            "system/health" => health_reply(1),
            _ => list_reply(),
        });
        let error = credsd_preflight(Some(&path), &["dev", "prod-inference"])
            .expect_err("prod-inference is not listed");
        assert!(matches!(error, CredentialError::Credential(_)));
        assert!(error.to_string().contains("prod-inference"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    /// An unauthorized caller's `CREDENTIAL_NOT_FOUND` is a credential error.
    #[test]
    fn an_unauthorized_list_fails() {
        let path = socket_path();
        spawn_daemon(path.as_path(), |method| match method {
            "system/health" => health_reply(1),
            _ => not_found_reply(),
        });
        let error = credsd_preflight(Some(&path), &["dev"]).expect_err("the caller is refused");
        assert!(matches!(error, CredentialError::Credential(_)));
        assert!(
            error
                .to_string()
                .contains("credsd refused credential/list: this box is not authorized to list"),
            "{error}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The preflight sends one unfiltered `credential/list`.
    #[test]
    fn the_list_request_is_one_and_unfiltered() {
        let path = socket_path();
        let requests = spawn_recording_daemon(path.as_path());
        credsd_preflight(Some(&path), &["dev", "staging", "dev"]).expect("both are listed");
        let params = requests.try_recv().expect("one list request");
        assert_eq!(params, serde_json::json!({}));
        assert!(requests.try_recv().is_err(), "the list is sent once");
        let _ = std::fs::remove_file(&path);
    }

    /// A caller with no credentials, which credsd answers with an empty list, fails.
    #[test]
    fn an_empty_credential_set_fails() {
        let path = socket_path();
        spawn_daemon(path.as_path(), |method| match method {
            "system/health" => health_reply(1),
            _ => empty_list_reply(),
        });
        let error = credsd_preflight(Some(&path), &["dev"], &[])
            .expect_err("an empty set is not available");
        assert!(matches!(error, CredentialError::Credential(_)));
        assert!(error.to_string().contains("dev"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    /// A live daemon and a listed credential pass, and the session state is not consulted — the
    /// `credential/list` entry reads `no_session`, yet the credential passes, because `credsd`
    /// still serves valid cached credentials while the login session reads spent.
    #[test]
    fn a_listed_credential_passes_whatever_its_session_state() {
        let path = socket_path();
        spawn_daemon(path.as_path(), |method| match method {
            "system/health" => health_reply(1),
            _ => list_reply(),
        });
        credsd_preflight(Some(&path), &["dev", "dev"]).expect("a listed credential passes");
        let _ = std::fs::remove_file(&path);
    }
}
