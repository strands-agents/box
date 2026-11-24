//! The `credsd` source: `credential/get` over a Unix domain socket, naming no credential type,
//! plus the two read methods the startup preflight needs.
//!
//! `credsd` speaks line-delimited JSON-RPC 2.0. [`CredsdClient::get`] sends one `credential/get`
//! request carrying only the `credential` field and returns the tagged [`CredentialResult`];
//! [`CredsdClient::health`] and [`CredsdClient::list`] send `system/health` and `credential/list`
//! over the same request path. The client calls no bootstrap and no login method, and it reads no
//! material field: the AWS delivery adapter in [`super::aws`] and [`credsd_access_token`] are the two
//! components that do.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::{CredentialError, Result, Secret};

/// The per-request credential fetch.
const GET_METHOD: &str = "credential/get";

/// The liveness and protocol-version probe the preflight sends first.
const HEALTH_METHOD: &str = "system/health";

/// The environment-availability probe the preflight sends per declared environment.
const LIST_METHOD: &str = "credential/list";

/// The fixed JSON-RPC request id; a result whose id differs is refused.
const REQUEST_ID: u64 = 1;

/// The response-line ceiling, matching the credsd transport's 1 MiB line cap.
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// The read granularity for one socket read.
const READ_CHUNK_BYTES: usize = 8192;

/// The per-read socket timeout, bounding one `read` syscall.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The overall wall-clock bound on reading the one response, so a slow-drip peer cannot hold the
/// request hot path across many under-timeout reads.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(10);

/// The URI scheme a `credsd://<credential>` reference carries.
pub(crate) const CREDSD_SCHEME: &str = "credsd";

/// The material tag an AWS credential carries.
pub(crate) const SESSION_CREDENTIALS_TYPE: &str = "session_credentials";

/// The material tag a bearer token for a non-AWS API carries.
pub(crate) const ACCESS_TOKEN_TYPE: &str = "access_token";

/// The one `token_type` the box can attach: a plain bearer token, with no per-request proof.
const BEARER_TOKEN_TYPE: &str = "Bearer";

/// The per-user tail beneath `HOME` for the macOS user-scoped install's socket (signed `.pkg` or
/// `credsd install --user`).
#[cfg(target_os = "macos")]
const MACOS_USER_SOCKET_TAIL: &str = "Library/Application Support/credsd/credsd.sock";
/// The macOS system install's socket (`sudo credsd install`, a LaunchDaemon), shared across users.
#[cfg(target_os = "macos")]
const MACOS_SYSTEM_SOCKET: &str = "/var/run/credsd/credsd.sock";
/// The default socket path when neither the caller nor `CREDSD_SOCKET` names one.
#[cfg(not(target_os = "macos"))]
const DEFAULT_SOCKET: &str = "/run/credsd/credsd.sock";

/// The environment variable naming the socket, read once at open.
const SOCKET_VARIABLE: &str = "CREDSD_SOCKET";

/// The macOS platform default, mirroring the daemon's own client dial order: the per-user socket
/// when a socket exists beneath `HOME`, else the shared system socket. Probes the user socket, then
/// defers the choice to the pure [`default_socket_from_home`].
#[cfg(target_os = "macos")]
fn default_socket() -> Result<PathBuf> {
    let home = std::env::var_os("HOME");
    let home = home.as_deref().filter(|value| !value.is_empty());
    let user_present = home
        .map(|home| PathBuf::from(home).join(MACOS_USER_SOCKET_TAIL))
        .as_deref()
        .map(path_is_socket)
        .unwrap_or(false);
    Ok(default_socket_from_home(home, user_present))
}

/// The macOS default socket for a given `home` and user-socket presence: the per-user socket beneath
/// `home` when `user_present`, else the shared system socket. An absent or empty `home` falls back
/// to the system socket, which does not depend on `HOME`. Pure, so every row pins without host state.
#[cfg(target_os = "macos")]
fn default_socket_from_home(home: Option<&std::ffi::OsStr>, user_present: bool) -> PathBuf {
    match home.filter(|value| !value.is_empty()) {
        Some(home) if user_present => PathBuf::from(home).join(MACOS_USER_SOCKET_TAIL),
        _ => PathBuf::from(MACOS_SYSTEM_SOCKET),
    }
}

/// Whether `path` names an existing Unix domain socket, following symlinks.
#[cfg(target_os = "macos")]
fn path_is_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path)
        .map(|meta| meta.file_type().is_socket())
        .unwrap_or(false)
}

/// The platform default socket path when neither the caller nor `CREDSD_SOCKET` names one.
#[cfg(not(target_os = "macos"))]
fn default_socket() -> Result<PathBuf> {
    Ok(PathBuf::from(DEFAULT_SOCKET))
}

/// Resolve the effective credsd socket path — the caller's path, else `CREDSD_SOCKET`, else the
/// platform default — refusing a relative result with a configuration error.
pub(crate) fn resolve_credsd_socket(configured: Option<&Path>) -> Result<PathBuf> {
    let path = match configured {
        Some(path) => path.to_path_buf(),
        None => match std::env::var_os(SOCKET_VARIABLE).filter(|value| !value.is_empty()) {
            Some(value) => PathBuf::from(value),
            None => default_socket()?,
        },
    };
    if path.is_relative() {
        return Err(CredentialError::Credential(format!(
            "the credsd socket path {path} is relative; a socket the box connects to must be an \
             absolute path — set {SOCKET_VARIABLE} to an absolute path or supply one to the vault",
            path = path.display()
        )));
    }
    Ok(path)
}

/// A type-agnostic `credsd` client: one request per call.
pub(crate) struct CredsdClient {
    socket: PathBuf,
}

impl CredsdClient {
    /// A client connecting to `socket`, which must be the absolute path [`resolve_credsd_socket`] returned.
    pub(crate) fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// Fetch the credential for `environment` with one `credential/get`, returning the tagged result.
    ///
    /// Sends only the `environment` field — no `profile`, `scope`, or `claim`. Every
    /// error names the environment and never the returned material.
    pub(crate) fn get(&self, environment: &str) -> Result<CredentialResult> {
        let context = environment_context(environment);
        // credsd 0.2 serves a credential by name and refuses an `environment` member; a daemon
        // that still knows environments serves a named credential too.
        let request = build_request(GET_METHOD, serde_json::json!({ "credential": environment }));
        let stream = self.send(&request, &context)?;
        let line = read_response(&stream, &context)?;
        parse_response(&line, environment)
    }

    /// Send `system/health` and return the daemon's protocol version.
    ///
    /// An unreachable socket or a daemon that answers no result is a keystore-access failure.
    pub(crate) fn health(&self) -> Result<u32> {
        let request = build_request(HEALTH_METHOD, serde_json::json!({}));
        let stream = self.send(&request, HEALTH_METHOD)?;
        let line = read_response(&stream, HEALTH_METHOD)?;
        parse_health(&line)
    }

    /// The name and kind of each credential the daemon serves this caller, with one
    /// `credential/list`.
    ///
    /// Sends no params: credsd 0.2 lists every credential of the caller and refuses an
    /// `environment` member. The preflight uses the list to confirm each named credential exists
    /// and has the kind its route reads. It reads no session state.
    pub(crate) fn list(&self) -> Result<Vec<(String, String)>> {
        let request = build_request(LIST_METHOD, serde_json::json!({}));
        let stream = self.send(&request, LIST_METHOD)?;
        let line = read_response(&stream, LIST_METHOD)?;
        let result: ListResult = parse_response(&line, LIST_METHOD)?;
        Ok(result
            .credentials
            .into_iter()
            .map(|entry| (entry.credential, entry.kind))
            .collect())
    }

    /// Connect, set the read and write timeouts, and write one request line, returning the open
    /// stream for the caller to read the response from. `context` names the operation in every error.
    fn send(&self, request: &str, context: &str) -> Result<UnixStream> {
        let stream = UnixStream::connect(&self.socket).map_err(|source| {
            CredentialError::KeystoreAccess(format!(
                "cannot reach the credsd socket {socket} for {context}: {source}",
                socket = self.socket.display()
            ))
        })?;
        stream
            .set_read_timeout(Some(RESPONSE_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(RESPONSE_TIMEOUT)))
            .map_err(|source| {
                CredentialError::KeystoreAccess(format!(
                    "cannot set a timeout on the credsd connection for {context}: {source}"
                ))
            })?;

        let mut writer = &stream;
        writer
            .write_all(request.as_bytes())
            .and_then(|()| writer.flush())
            .map_err(|source| {
                CredentialError::KeystoreAccess(format!(
                    "cannot send the credsd request for {context}: {source}"
                ))
            })?;
        Ok(stream)
    }
}

/// The error-message label for a request that names an environment.
fn environment_context(environment: &str) -> String {
    format!("credential {environment:?}")
}

/// Build one request line for `method` carrying `params`.
fn build_request(method: &str, params: serde_json::Value) -> String {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": REQUEST_ID,
        "method": method,
        "params": params,
    });
    // One compact JSON object per newline-terminated line (credsd transport).
    format!("{request}\n")
}

/// Read one response line, bounded in bytes and in wall-clock time, and wiped on drop.
///
/// The per-read socket timeout does not bound the whole operation, because each read that receives a
/// byte resets it; `RESPONSE_DEADLINE` is the overall bound a slow-drip peer cannot reset. `take`
/// caps the total at `MAX_RESPONSE_BYTES`; the read stops at the first newline, and an EOF before a
/// newline is a dropped line rather than a complete response, so it is refused.
fn read_response(stream: &UnixStream, context: &str) -> Result<Zeroizing<Vec<u8>>> {
    let deadline = Instant::now() + RESPONSE_DEADLINE;
    let mut reader = stream.take(MAX_RESPONSE_BYTES);
    // Reserve the whole cap up front so the buffer never reallocates, whatever the response size:
    // a grown `Vec` frees its old allocation — holding credential bytes — without wiping it.
    // The 1 MiB reservation is lazily paged, so only the bytes actually read become resident.
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES as usize));
    // The read chunk holds response bytes, so it is wiped on drop like the buffer.
    let mut chunk = Zeroizing::new([0u8; READ_CHUNK_BYTES]);
    loop {
        if Instant::now() >= deadline {
            return Err(CredentialError::KeystoreAccess(format!(
                "the credsd daemon did not answer within {seconds}s for {context}",
                seconds = RESPONSE_DEADLINE.as_secs()
            )));
        }
        let read = reader.read(&mut chunk[..]).map_err(|source| {
            CredentialError::KeystoreAccess(format!(
                "the credsd daemon did not answer for {context}: {source}"
            ))
        })?;
        if read == 0 {
            // `take` returns 0 once the byte cap is exhausted, the same signal as EOF. A buffer at
            // the cap with no newline is a truncated line: refuse it rather than parse a partial
            // response, so an over-cap answer fails closed rather than through the JSON parser.
            if buffer.len() as u64 >= MAX_RESPONSE_BYTES {
                return Err(CredentialError::KeystoreAccess(format!(
                    "the credsd response for {context} exceeded the \
                     {MAX_RESPONSE_BYTES}-byte limit with no complete line"
                )));
            }
            // EOF. credsd terminates every response line with a newline (protocol v1), so a
            // complete response breaks the loop at that newline. Reaching EOF with bytes still
            // buffered is a line the connection dropped before completing: refuse it rather than
            // parse a partial response.
            if !buffer.is_empty() {
                return Err(CredentialError::KeystoreAccess(format!(
                    "the credsd daemon closed the connection mid-response for {context}"
                )));
            }
            break; // EOF with nothing buffered.
        }
        buffer.extend_from_slice(&chunk[..read]);
        if chunk[..read].contains(&b'\n') {
            break; // One line per response; stop rather than wait for the peer to close.
        }
    }
    if buffer.is_empty() {
        return Err(CredentialError::KeystoreAccess(format!(
            "the credsd daemon closed the connection with no response for {context}"
        )));
    }
    Ok(buffer)
}

/// The response bytes up to the first newline. The transport frames one JSON object per line, so
/// anything after it (a second framed line or padding) is ignored rather than fed to the parser as
/// trailing input.
fn first_line(buffer: &[u8]) -> &[u8] {
    buffer.split(|&byte| byte == b'\n').next().unwrap_or(buffer)
}

/// Parse one response line into a tagged result `R`, mapping every outcome to the crate error
/// classes. The message never carries the response bytes, which may hold credential material.
fn parse_response<R: serde::de::DeserializeOwned>(buffer: &[u8], environment: &str) -> Result<R> {
    let response: RpcResponse<R> =
        serde_json::from_slice(first_line(buffer)).map_err(|_source| {
            CredentialError::Credential(format!(
                "credsd returned a malformed response for credential {environment:?}"
            ))
        })?;
    if let Some(error) = response.error {
        return Err(map_error(&error, environment));
    }
    // A result carries credentials, so its id must match the request we sent. A crossed or
    // mismatched response must never sign with another environment's material.
    if response.id != Some(REQUEST_ID) {
        return Err(CredentialError::Credential(format!(
            "credsd returned a response with an unexpected id for credential {environment:?}"
        )));
    }
    response.result.ok_or_else(|| {
        CredentialError::Credential(format!(
            "credsd returned neither a result nor an error for credential {environment:?}"
        ))
    })
}

/// Parse one `system/health` line into the reported protocol version. Every failure is a
/// keystore-access error, because a daemon that cannot report its version is not usable.
fn parse_health(buffer: &[u8]) -> Result<u32> {
    let response: RpcResponse<HealthResult> =
        serde_json::from_slice(first_line(buffer)).map_err(|_source| {
            CredentialError::KeystoreAccess(
                "credsd returned a malformed system/health response".to_string(),
            )
        })?;
    if let Some(error) = response.error {
        return Err(CredentialError::KeystoreAccess(format!(
            "credsd rejected system/health (protocol code {code})",
            code = error.code
        )));
    }
    response
        .result
        .map(|health| health.protocol)
        .ok_or_else(|| {
            CredentialError::KeystoreAccess("credsd returned no system/health result".to_string())
        })
}

/// Map a JSON-RPC error to a keystore-access or credential failure by its `error.data.code`, naming
/// the environment and never `error.message`.
fn map_error(error: &RpcError, environment: &str) -> CredentialError {
    match error.data.as_ref().and_then(|data| data.code.as_deref()) {
        Some("ENVIRONMENT_NOT_FOUND") => CredentialError::Credential(format!(
            "credsd has no environment {environment:?}, or this box is not authorized for it"
        )),
        Some("CREDENTIAL_NOT_FOUND") => CredentialError::Credential(format!(
            "credsd has no credential {environment:?}, or this box is not authorized for it"
        )),
        Some("REAUTH_REQUIRED") => CredentialError::Credential(format!(
            "credsd needs re-authentication for credential {environment:?}; run `creds login`"
        )),
        Some("WRONG_CREDENTIAL_TYPE") => CredentialError::Credential(format!(
            "credsd credential {environment:?} does not project to session credentials"
        )),
        Some("PROVIDER_UNAVAILABLE") => CredentialError::KeystoreAccess(format!(
            "the credsd provider is unavailable for credential {environment:?}"
        )),
        Some("INTERNAL") => CredentialError::KeystoreAccess(format!(
            "credsd reported an internal error for credential {environment:?}"
        )),
        Some(_) => CredentialError::KeystoreAccess(format!(
            "credsd reported an unrecognised failure for credential {environment:?}"
        )),
        None => CredentialError::Credential(format!(
            "credsd rejected the request for credential {environment:?} (protocol code {code})",
            code = error.code
        )),
    }
}

/// One `credential/get` result. The material and its expiry are read here; `credential` and
/// `provenance` are audit-only and ignored.
#[derive(Deserialize)]
pub(crate) struct CredentialResult {
    /// The credential material, tagged on `type`.
    pub(crate) material: Material,
    /// When the material stops working, as the daemon wrote it, or `None` for one that never expires.
    #[serde(default)]
    pub(crate) expires_at: Option<String>,
}

impl std::fmt::Debug for CredentialResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialResult")
            .field("material", &self.material)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A credsd access token, read once for an opaque route.
pub(crate) struct AccessToken {
    /// The token, validated as an attachable secret.
    pub(crate) token: Secret,
    /// When the token stops working, as the daemon wrote it, or `None` for one that never expires.
    pub(crate) expires_at: Option<String>,
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Fetch the access token of one `credsd` environment for an opaque route.
///
/// The token delivery adapter, beside the AWS one in [`super::aws`]. A material tag other than
/// `access_token`, a `token_type` other than `Bearer`, or an empty or unusable token is a hard
/// credential failure that names the environment and never the material.
pub(crate) fn credsd_access_token(client: &CredsdClient, environment: &str) -> Result<AccessToken> {
    access_token_from(client.get(environment)?, environment)
}

/// Map a `credsd` result onto an [`AccessToken`], asserting the material tag and the token type.
fn access_token_from(result: CredentialResult, environment: &str) -> Result<AccessToken> {
    let CredentialResult {
        mut material,
        expires_at,
    } = result;
    if material.kind != ACCESS_TOKEN_TYPE {
        return Err(CredentialError::Credential(format!(
            "credsd credential {environment:?} returned {kind:?} material, but a token route \
             needs {ACCESS_TOKEN_TYPE}",
            kind = material.kind
        )));
    }
    // A DPoP-bound token needs a proof the box cannot make, so attaching it as a bearer token would
    // send a request the API refuses.
    if material.token_type != BEARER_TOKEN_TYPE {
        return Err(CredentialError::Credential(format!(
            "credsd credential {environment:?} returned a {token_type:?} token, and the box \
             attaches only {BEARER_TOKEN_TYPE} tokens",
            token_type = material.token_type
        )));
    }
    let raw = Zeroizing::new(std::mem::take(&mut material.token.0));
    let token = Secret::new(raw, &format!("{CREDSD_SCHEME}://{environment}"))?;
    Ok(AccessToken { token, expires_at })
}

/// The tagged credential material. The AWS delivery adapter branches on [`kind`](Self::kind),
/// never on which fields are present. The credential fields are wiped on drop, so no parsed
/// copy survives an error path.
#[derive(Deserialize)]
pub(crate) struct Material {
    /// The material tag, e.g. `session_credentials`.
    #[serde(rename = "type")]
    pub(crate) kind: String,
    /// AWS access key id, present for `session_credentials`.
    #[serde(default)]
    pub(crate) access_key_id: String,
    /// AWS secret access key, present for `session_credentials`.
    #[serde(default)]
    pub(crate) secret_access_key: String,
    /// AWS session token, present for `session_credentials`.
    #[serde(default)]
    pub(crate) session_token: String,
    /// The bearer token, present for `access_token`. Wiped on drop by its own type, so a result
    /// whose later fields fail to parse leaves no unwiped copy.
    #[serde(default)]
    pub(crate) token: WipedString,
    /// The OAuth2 token type, such as `Bearer`, present for `access_token`. Not secret.
    #[serde(default)]
    pub(crate) token_type: String,
}

impl zeroize::Zeroize for Material {
    fn zeroize(&mut self) {
        // The tag and the token type are non-secret routing data; every credential field is wiped.
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
        self.token.0.zeroize();
    }
}

/// A deserialized secret field that is wiped on drop, also when the object around it fails to
/// parse before the object exists.
#[derive(Default)]
pub(crate) struct WipedString(pub(crate) String);

impl<'de> Deserialize<'de> for WipedString {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

impl Drop for WipedString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Material {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The tag is non-secret routing data; every credential field renders `[REDACTED]`.
        f.debug_struct("Material")
            .field("type", &self.kind)
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .field("token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// The response envelope: exactly one of `result` or `error` is present. A missing `Option` field
/// deserializes to `None`, so these need no `#[serde(default)]` — and a field-level default would
/// force a spurious `R: Default` bound on the generic result.
#[derive(Deserialize)]
struct RpcResponse<R> {
    id: Option<u64>,
    result: Option<R>,
    error: Option<RpcError>,
}

/// The `system/health` result. The daemon reports the wire protocol version in `protocol` (an
/// integer) and its own software version in a separate `version` string, which is ignored. A
/// daemon that omits `protocol` fails the parse, which refuses the run — fail-closed.
#[derive(Deserialize)]
struct HealthResult {
    protocol: u32,
}

/// The `credential/list` result. The preflight reads each credential's name and kind: source, status
/// and tags are discarded.
#[derive(Debug, Deserialize)]
struct ListResult {
    #[serde(default)]
    credentials: Vec<ListEntry>,
}

/// One `credential/list` entry, read for its name and kind.
#[derive(Debug, Deserialize)]
struct ListEntry {
    /// The credential's name, which a `credsd://<credential>` reference names.
    #[serde(default)]
    credential: String,
    /// The credential's kind, such as `session_credentials` or `access_token`.
    #[serde(default)]
    kind: String,
}

/// A JSON-RPC error object.
#[derive(Deserialize)]
struct RpcError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    data: Option<RpcErrorData>,
}

/// The domain-code carrier: `error.data.code` says what went wrong.
#[derive(Deserialize)]
struct RpcErrorData {
    #[serde(default)]
    code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU32, Ordering};

    // --- request shape -------------------------------------------------------

    /// The request `get` sends for `credential`.
    fn build_credential_request(method: &str, credential: &str) -> String {
        build_request(method, serde_json::json!({ "credential": credential }))
    }

    /// The request names the credential in the `credential` field and calls `credential/get`.
    #[test]
    fn the_request_names_the_credential_and_the_get_method() {
        let request = build_credential_request(GET_METHOD, "prod-inference");
        let value: serde_json::Value = serde_json::from_str(request.trim_end()).unwrap();
        assert_eq!(value["method"], "credential/get");
        assert_eq!(value["params"]["credential"], "prod-inference");
        assert!(
            value["params"].get("environment").is_none(),
            "credsd 0.2 refuses it"
        );
        assert_eq!(value["jsonrpc"], "2.0");
        assert!(request.ends_with('\n'), "the transport is line-delimited");
    }

    /// The request sends no `profile`, `scope`, or `claim`.
    #[test]
    fn the_request_omits_profile_scope_and_claim() {
        let request = build_credential_request(GET_METHOD, "dev");
        let value: serde_json::Value = serde_json::from_str(request.trim_end()).unwrap();
        let params = &value["params"];
        assert!(params.get("profile").is_none(), "no legacy profile field");
        assert!(params.get("scope").is_none(), "scope is reserved, not sent");
        assert!(params.get("claim").is_none(), "no claim field");
    }

    /// A special-character environment is JSON-escaped rather than breaking the line.
    #[test]
    fn the_request_escapes_the_environment() {
        let request = build_credential_request(GET_METHOD, "a\"b\nc");
        assert_eq!(
            request.matches('\n').count(),
            1,
            "only the terminator is a raw newline"
        );
        let value: serde_json::Value = serde_json::from_str(request.trim_end()).unwrap();
        assert_eq!(value["params"]["credential"], "a\"b\nc");
    }

    // --- response parsing ----------------------------------------------------

    fn ok_response() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"credential":"login","material":{"type":"session_credentials","access_key_id":"ASIAEXAMPLE","secret_access_key":"secretkey","session_token":"token"},"expires_at":"2027-01-01T00:00:00Z","provenance":"minted_for_request"}}"#.to_vec()
    }

    /// A `session_credentials` result parses to its three material fields.
    #[test]
    fn a_session_credentials_result_parses() {
        let result = parse_response::<CredentialResult>(&ok_response(), "dev")
            .expect("a well-formed result parses");
        assert_eq!(result.material.kind, "session_credentials");
        assert_eq!(result.material.access_key_id.as_str(), "ASIAEXAMPLE");
        assert_eq!(result.material.secret_access_key.as_str(), "secretkey");
        assert_eq!(result.material.session_token.as_str(), "token");
    }

    /// A `credential/get` result carrying `access_token` material of `token_type`.
    fn token_result(token: &str, token_type: &str, expires_at: &str) -> CredentialResult {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"credential":"gh","material":{{"type":"access_token","token":"{token}","token_type":"{token_type}"}},"expires_at":{expires_at}}}}}"#
        );
        parse_response::<CredentialResult>(line.as_bytes(), "github").expect("the result parses")
    }

    /// An `access_token` result maps to its token, and keeps the expiry the daemon wrote.
    #[test]
    fn an_access_token_result_maps_to_its_token_and_expiry() {
        let token = access_token_from(
            token_result("ghp_example", "Bearer", r#""2027-01-01T00:00:00Z""#),
            "github",
        )
        .expect("a bearer access token maps");
        assert_eq!(token.token.as_str(), "ghp_example");
        assert_eq!(token.expires_at.as_deref(), Some("2027-01-01T00:00:00Z"));

        let never = access_token_from(token_result("ghp_example", "Bearer", "null"), "github")
            .expect("a token with no expiry maps");
        assert_eq!(never.expires_at, None, "null means the token never expires");
    }

    /// Neither the parsed material nor the token the adapter returns prints the token in `Debug`.
    #[test]
    fn token_material_prints_no_token() {
        let result = token_result("ghp_debug_example", "Bearer", "null");
        let printed = format!("{result:?}");
        assert!(!printed.contains("ghp_debug_example"), "{printed}");
        assert!(
            printed.contains("Bearer"),
            "the token type is not secret: {printed}"
        );
        let token = access_token_from(result, "github").expect("a bearer token maps");
        let printed = format!("{token:?}");
        assert!(!printed.contains("ghp_debug_example"), "{printed}");
    }

    /// The token adapter refuses AWS material, naming the environment and both kinds.
    #[test]
    fn the_token_adapter_refuses_session_credentials() {
        let result = parse_response::<CredentialResult>(&ok_response(), "github").unwrap();
        let error = access_token_from(result, "github").expect_err("AWS material is no token");
        let message = error.to_string();
        assert!(matches!(error, CredentialError::Credential(_)));
        assert!(
            message.contains("\"github\"")
                && message.contains("session_credentials")
                && message.contains("access_token"),
            "{message}"
        );
        assert!(!message.contains("secretkey"), "no material: {message}");
    }

    /// A token that is not a plain bearer token, such as a DPoP-bound one, is refused: the box makes
    /// no per-request proof.
    #[test]
    fn a_token_that_is_not_bearer_is_refused() {
        let error = access_token_from(token_result("ghp_example", "DPoP", "null"), "github")
            .expect_err("a DPoP token cannot be attached");
        let message = error.to_string();
        assert!(
            message.contains("DPoP") && message.contains("Bearer"),
            "{message}"
        );
        assert!(!message.contains("ghp_example"), "no material: {message}");
    }

    /// An empty token is refused as unusable rather than attached.
    #[test]
    fn an_empty_access_token_is_refused() {
        access_token_from(token_result("", "Bearer", "null"), "github")
            .expect_err("an empty token is unusable");
    }

    /// Bytes after the first newline (a second framed line, or padding) are ignored: only the first
    /// line is parsed, so a valid response is not misread as malformed trailing input.
    #[test]
    fn trailing_bytes_after_the_first_line_are_ignored() {
        let mut buffer = ok_response();
        buffer.push(b'\n');
        buffer.extend_from_slice(br#"{"jsonrpc":"2.0","id":2,"result":{}}"#);
        let result =
            parse_response::<CredentialResult>(&buffer, "dev").expect("the first line parses");
        assert_eq!(result.material.access_key_id.as_str(), "ASIAEXAMPLE");
    }

    /// A result whose JSON-RPC id does not match the request is refused, so a crossed response never
    /// signs with another environment's material.
    #[test]
    fn a_mismatched_response_id_is_refused() {
        let line = br#"{"jsonrpc":"2.0","id":99,"result":{"material":{"type":"session_credentials","access_key_id":"AKIAOTHER","secret_access_key":"other","session_token":"tok"}}}"#;
        let error = parse_response::<CredentialResult>(line, "prod-inference")
            .expect_err("a mismatched id must fail");
        assert!(matches!(error, CredentialError::Credential(_)));
        assert!(
            error.to_string().contains("prod-inference"),
            "names the environment: {error}"
        );
    }

    /// Each domain code maps to its class, and the message names the environment but no material.
    #[test]
    fn domain_codes_map_to_their_classes() {
        let case = |code: &str| {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32000,"message":"x","data":{{"code":"{code}"}}}}}}"#
            );
            parse_response::<CredentialResult>(line.as_bytes(), "prod-inference")
                .expect_err("an error result fails")
        };
        for code in [
            "ENVIRONMENT_NOT_FOUND",
            "REAUTH_REQUIRED",
            "WRONG_CREDENTIAL_TYPE",
        ] {
            let error = case(code);
            assert!(
                matches!(error, CredentialError::Credential(_)),
                "{code} is a credential error"
            );
            assert!(
                error.to_string().contains("prod-inference"),
                "{code} names the environment"
            );
        }
        for code in ["PROVIDER_UNAVAILABLE", "INTERNAL"] {
            assert!(
                matches!(case(code), CredentialError::KeystoreAccess(_)),
                "{code} is a keystore-access error"
            );
        }
        // An unrecognised domain code is treated like INTERNAL.
        assert!(matches!(
            case("SOMETHING_NEW"),
            CredentialError::KeystoreAccess(_)
        ));
    }

    /// An envelope error with no domain code (e.g. an older daemon rejecting the request) is a hard
    /// credential failure that names the environment.
    #[test]
    fn an_envelope_error_is_a_hard_credential_failure() {
        let line =
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unknown member"}}"#;
        let error =
            parse_response::<CredentialResult>(line, "dev").expect_err("an envelope error fails");
        assert!(matches!(error, CredentialError::Credential(_)));
        assert!(error.to_string().contains("dev"));
    }

    /// Malformed JSON is a credential error naming the environment, never echoing the bytes.
    #[test]
    fn malformed_json_is_a_credential_error() {
        let error = parse_response::<CredentialResult>(b"{not json", "dev")
            .expect_err("malformed json fails");
        assert!(matches!(error, CredentialError::Credential(_)));
        assert!(error.to_string().contains("dev"));
        assert!(
            !error.to_string().contains("not json"),
            "the bytes are never echoed"
        );
    }

    // --- socket resolution ---------------------------------------------------

    /// A caller-supplied absolute path wins over the default.
    #[test]
    fn a_configured_absolute_socket_wins() {
        let path = resolve_credsd_socket(Some(Path::new("/tmp/custom.sock"))).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/custom.sock"));
    }

    /// A relative configured path is refused at open, naming the path.
    #[test]
    fn a_relative_configured_socket_is_refused() {
        let error =
            resolve_credsd_socket(Some(Path::new("relative/credsd.sock"))).expect_err("relative");
        assert!(
            matches!(error, CredentialError::Credential(_)),
            "a config error, not KeystoreAccess"
        );
        assert!(
            error.to_string().contains("relative/credsd.sock"),
            "the refusal names the path"
        );
    }

    /// With no configured path and `CREDSD_SOCKET` unset, the non-macOS default is absolute.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn the_default_socket_is_absolute() {
        let path = default_socket().expect("the platform default");
        assert!(path.is_absolute(), "the platform default must be absolute");
    }

    /// On macOS a present per-user socket wins, resolving beneath `HOME`.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_default_prefers_a_present_user_socket() {
        let path = default_socket_from_home(Some(std::ffi::OsStr::new("/Users/example")), true);
        assert_eq!(
            path,
            PathBuf::from("/Users/example/Library/Application Support/credsd/credsd.sock"),
        );
        assert!(path.is_absolute(), "the user socket is an absolute path");
    }

    /// On macOS an absent per-user socket falls back to the shared system socket.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_default_falls_back_to_the_system_socket() {
        let path = default_socket_from_home(Some(std::ffi::OsStr::new("/Users/example")), false);
        assert_eq!(path, PathBuf::from("/var/run/credsd/credsd.sock"));
    }

    /// On macOS an absent or empty `HOME` falls back to the system socket, which needs no `HOME`,
    /// even when a user socket is claimed present.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_default_without_home_uses_the_system_socket() {
        for home in [None, Some(std::ffi::OsStr::new(""))] {
            let path = default_socket_from_home(home, true);
            assert_eq!(path, PathBuf::from("/var/run/credsd/credsd.sock"));
        }
    }

    /// On macOS the probe recognises a bound socket, and rejects a regular file and a missing path,
    /// so a stray file at the user path cannot be mistaken for a live user install.
    #[cfg(target_os = "macos")]
    #[test]
    fn path_is_socket_recognises_only_a_bound_socket() {
        let socket = socket_path();
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind a socket");
        assert!(path_is_socket(&socket), "a bound socket is a socket");

        let regular = socket_path().with_extension("file");
        std::fs::write(&regular, b"not a socket").expect("write a regular file");
        assert!(!path_is_socket(&regular), "a regular file is not a socket");

        let missing = socket_path().with_extension("missing");
        assert!(!path_is_socket(&missing), "a missing path is not a socket");

        drop(listener);
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&regular);
    }

    // --- the socket round trip -----------------------------------------------

    /// A per-test socket path under the temp dir, unique across concurrent tests.
    fn socket_path() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("credsd-test-{}-{nonce}.sock", std::process::id()))
    }

    /// A fake daemon that accepts one connection, records the request, and replies `response`.
    fn fake_daemon(
        path: &Path,
        response: Vec<u8>,
    ) -> (
        std::sync::mpsc::Receiver<Vec<u8>>,
        std::thread::JoinHandle<()>,
    ) {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).expect("bind the fake credsd socket");
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept one connection");
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = Vec::new();
            reader
                .read_until(b'\n', &mut request)
                .expect("read the request line");
            let _ = tx.send(request);
            // A client that stops at the byte cap drops its end mid-write, so a large response
            // ends in a broken pipe here; that is the client refusing, not a test failure.
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        });
        (rx, handle)
    }

    /// The client connects, sends `credential/get` with the environment, and returns the material.
    #[test]
    fn a_round_trip_sends_the_request_and_returns_the_material() {
        let path = socket_path();
        let mut response = ok_response();
        response.push(b'\n'); // credsd newline-terminates every response line (protocol v1).
        let (rx, handle) = fake_daemon(path.as_path(), response);

        let client = CredsdClient::new(path.clone());
        let result = client.get("dev").expect("the fake daemon answers");
        assert_eq!(result.material.access_key_id.as_str(), "ASIAEXAMPLE");

        let request = rx.recv().expect("the daemon recorded the request");
        let value: serde_json::Value =
            serde_json::from_slice(request.trim_ascii_end()).expect("the request is one JSON line");
        assert_eq!(value["method"], "credential/get");
        assert_eq!(value["params"]["credential"], "dev");

        handle.join().expect("the daemon thread joins");
        let _ = std::fs::remove_file(&path);
    }

    /// A newline-terminated response is read to the newline and returned, so the read stops at the
    /// line boundary rather than waiting for the peer to close.
    #[test]
    fn a_newline_terminated_response_is_read() {
        let path = socket_path();
        let mut response = ok_response();
        response.push(b'\n');
        let (_rx, handle) = fake_daemon(path.as_path(), response);

        let result = CredsdClient::new(path.clone())
            .get("dev")
            .expect("a newline-terminated response is read");
        assert_eq!(result.material.access_key_id.as_str(), "ASIAEXAMPLE");

        handle.join().expect("the daemon thread joins");
        let _ = std::fs::remove_file(&path);
    }

    /// A response that fills the byte cap with no newline is refused as truncated, rather than
    /// parsed as a partial line: the over-cap answer fails closed with a keystore-access error.
    #[test]
    fn a_response_exceeding_the_byte_cap_is_refused() {
        let path = socket_path();
        let oversized = vec![b'x'; MAX_RESPONSE_BYTES as usize + READ_CHUNK_BYTES];
        let (_rx, handle) = fake_daemon(path.as_path(), oversized);

        let error = CredsdClient::new(path.clone())
            .get("prod-inference")
            .expect_err("an over-cap response with no line must be refused");
        assert!(matches!(error, CredentialError::KeystoreAccess(_)));
        assert!(
            error.to_string().contains("prod-inference") && error.to_string().contains("limit"),
            "the refusal names the environment and the cap: {error}"
        );

        let _ = handle.join();
        let _ = std::fs::remove_file(&path);
    }

    /// A response the daemon drops before its terminating newline is refused, not parsed as a
    /// partial line: credsd newline-terminates every line (protocol v1), so an EOF with bytes
    /// buffered is a dropped connection and a hard keystore-access failure.
    #[test]
    fn a_connection_dropped_mid_response_is_refused() {
        let path = socket_path();
        // A well-formed JSON object with no terminating newline, then the daemon closes.
        let (_rx, handle) = fake_daemon(path.as_path(), ok_response());

        let error = CredsdClient::new(path.clone())
            .get("prod-inference")
            .expect_err("a response with no terminating newline is a dropped line");
        assert!(matches!(error, CredentialError::KeystoreAccess(_)));
        assert!(
            error.to_string().contains("prod-inference")
                && error.to_string().contains("mid-response"),
            "the refusal names the environment and the dropped connection: {error}"
        );

        let _ = handle.join();
        let _ = std::fs::remove_file(&path);
    }

    /// An absent socket is a keystore-access failure naming the environment.
    #[test]
    fn an_unreachable_socket_is_a_keystore_access_error() {
        let path = socket_path(); // never bound
        let error = CredsdClient::new(path)
            .get("prod-inference")
            .expect_err("nothing is listening");
        assert!(matches!(error, CredentialError::KeystoreAccess(_)));
        assert!(error.to_string().contains("prod-inference"));
    }

    // --- system/health -------------------------------------------------------

    /// `health` sends `system/health` with no environment and returns the reported protocol version,
    /// using the daemon's real response shape (`protocol` int plus a `version` software string).
    #[test]
    fn health_sends_the_probe_and_returns_the_protocol_version() {
        let path = socket_path();
        let (rx, handle) = fake_daemon(
            path.as_path(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"protocol":1,"version":"0.1.0"}}
"#
            .to_vec(),
        );

        let version = CredsdClient::new(path.clone())
            .health()
            .expect("the fake daemon answers system/health");
        assert_eq!(version, 1);

        let request = rx.recv().expect("the daemon recorded the request");
        let value: serde_json::Value =
            serde_json::from_slice(request.trim_ascii_end()).expect("one JSON line");
        assert_eq!(value["method"], "system/health");
        assert!(
            value["params"].get("environment").is_none(),
            "system/health names no environment"
        );

        handle.join().expect("the daemon thread joins");
        let _ = std::fs::remove_file(&path);
    }

    /// The protocol version is read from `protocol`, and the daemon's separate `version` software
    /// string is ignored. A response missing `protocol` fails the parse rather than binding the
    /// software `version`, so the compatibility gate is fail-closed.
    #[test]
    fn health_reads_protocol_and_ignores_the_software_version() {
        assert_eq!(
            parse_health(br#"{"jsonrpc":"2.0","id":1,"result":{"protocol":1,"version":"0.1.0"}}"#)
                .expect("the real daemon shape parses"),
            1
        );
        // The software version alone (no `protocol`) is not a protocol version, and its string value
        // must never bind: the parse fails closed.
        let error = parse_health(br#"{"jsonrpc":"2.0","id":1,"result":{"version":"0.1.0"}}"#)
            .expect_err("a response without `protocol` must fail closed");
        assert!(matches!(error, CredentialError::KeystoreAccess(_)));
    }

    /// A daemon that answers no health result is a keystore-access failure, never a silent pass.
    #[test]
    fn health_without_a_result_is_a_keystore_access_error() {
        let error = parse_health(br#"{"jsonrpc":"2.0","id":1}"#).expect_err("no result must fail");
        assert!(matches!(error, CredentialError::KeystoreAccess(_)));
    }

    // --- credential/list -----------------------------------------------------

    /// `list` sends `credential/list` with no params, which credsd 0.2 requires, and returns each
    /// credential's name and kind, ignoring its session status.
    #[test]
    fn list_sends_no_params_and_returns_each_name_and_kind() {
        let path = socket_path();
        let (rx, handle) = fake_daemon(
            path.as_path(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"credentials":[{"credential":"dev","kind":"session_credentials","source":"aws_login","status":"no_session","tags":{}}]}}
"#
            .to_vec(),
        );

        let listed = CredsdClient::new(path.clone())
            .list()
            .expect("the fake daemon answers credential/list");
        assert_eq!(
            listed,
            [("dev".to_string(), "session_credentials".to_string())]
        );

        let request = rx.recv().expect("the daemon recorded the request");
        let value: serde_json::Value =
            serde_json::from_slice(request.trim_ascii_end()).expect("one JSON line");
        assert_eq!(value["method"], "credential/list");
        assert_eq!(
            value["params"],
            serde_json::json!({}),
            "credsd 0.2 refuses an environment member"
        );

        handle.join().expect("the daemon thread joins");
        let _ = std::fs::remove_file(&path);
    }

    /// `ENVIRONMENT_NOT_FOUND` on a list reuses the get path's mapping: a credential failure naming
    /// the environment, never the material.
    #[test]
    fn list_maps_environment_not_found_to_a_credential_error() {
        let line = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x","data":{"code":"ENVIRONMENT_NOT_FOUND"}}}"#;
        let error =
            parse_response::<ListResult>(line, "prod-inference").expect_err("not found must fail");
        assert!(matches!(error, CredentialError::Credential(_)));
        assert!(error.to_string().contains("prod-inference"));
    }

    /// An environment the daemon lists with no credential counts as zero, which the preflight treats
    /// as absent.
    #[test]
    fn an_empty_list_counts_as_zero() {
        let count = parse_response::<ListResult>(
            br#"{"jsonrpc":"2.0","id":1,"result":{"credentials":[]}}"#,
            "dev",
        )
        .expect("an empty result parses")
        .credentials
        .len();
        assert_eq!(count, 0);
    }
}
