//! PROTOTYPE(content-inspection): the client for a content inspector, speaking the egress
//! classification protocol draft 0.2 over stdio, unix, or https.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use policy::{
    ContentInspector, InspectionLabels, InspectionRequest, InspectionVerdict, NameInspection,
    NameSubjectKind,
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

use crate::record::config::prototype_inspection::{Binding, InspectionConfig};

const PROTOCOL_VERSION: &str = "0.2";
const CACHE_ENTRIES: usize = 4096;
const MAX_MESSAGE_BYTES: usize = 16 << 20;
const REDACTED_HEADERS: [&str; 3] = ["authorization", "proxy-authorization", "cookie"];
const KNOWN_ERRORS: [&str; 7] = [
    "invalid_request",
    "unsupported_version",
    "unsupported_subject",
    "unauthorized",
    "too_large",
    "rate_limited",
    "internal",
];

type Reply = std::sync::mpsc::Sender<Result<Value, String>>;
type Pending = (String, String, Reply);

/// PROTOTYPE(content-inspection): what `capabilities` reported, per subject kind.
#[derive(Debug)]
struct Capabilities {
    name: String,
    http: Option<HttpSubject>,
    dns: Option<BTreeSet<String>>,
    connect: Option<BTreeSet<String>>,
}

#[derive(Debug)]
struct HttpSubject {
    labels: BTreeSet<String>,
    max_body_bytes: usize,
}

/// PROTOTYPE(content-inspection): one cached `dns` or `connect` answer.
struct Cached {
    expires: Instant,
    labels: Vec<String>,
}

/// PROTOTYPE(content-inspection): the bearer token, held by a Box credential vault.
struct Bearer {
    vault: credentials::Vault,
    phantom: String,
    host: String,
    port: u16,
    path: String,
}

enum Transport {
    /// stdio or unix: one long-lived line stream multiplexed by `id`.
    Lines {
        sender: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Pending>>>,
        reconnect: Option<PathBuf>,
    },
    Https {
        client: reqwest::Client,
        url: String,
        bearer: Bearer,
    },
}

struct Started {
    runtime: tokio::runtime::Handle,
    transport: Transport,
}

/// PROTOTYPE(content-inspection): the box's one content inspector.
pub(crate) struct PrototypeInspector {
    config: InspectionConfig,
    box_name: String,
    requested: InspectionLabels,
    timeout: Duration,
    cache: Mutex<HashMap<String, Cached>>,
    next_id: AtomicU64,
    started: OnceLock<Started>,
    capabilities: OnceLock<Capabilities>,
    leaf: Mutex<Option<LeafHold>>,
}

struct LeafHold {
    child: tokio::process::Child,
    _retention: crate::run::contain::supervise::StreamingLeafRetention,
}

impl Drop for LeafHold {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl PrototypeInspector {
    /// PROTOTYPE(content-inspection): the inspector the record declares; `start` connects it.
    pub(crate) fn from_config(
        config: &InspectionConfig,
        box_name: &str,
        requested: InspectionLabels,
    ) -> Arc<Self> {
        Arc::new(Self {
            config: config.clone(),
            box_name: box_name.to_string(),
            requested,
            timeout: Duration::from_millis(config.timeout_ms),
            cache: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            started: OnceLock::new(),
            capabilities: OnceLock::new(),
            leaf: Mutex::new(None),
        })
    }

    /// PROTOTYPE(content-inspection): connect the binding, then run `capabilities`, or refuse.
    pub(crate) async fn start(
        self: &Arc<Self>,
        leaf: Option<crate::run::contain::supervise::StreamingLeafParts>,
    ) -> Result<(), String> {
        let runtime = tokio::runtime::Handle::current();
        let binding = self.config.binding();
        let transport = match (&binding, leaf) {
            (Binding::Stdio, Some(parts)) => {
                let sender = spawn_lines(&runtime, parts.stdout, parts.stdin);
                eprintln!(
                    "strands-box: inspection: inspector leaf started (pid {})",
                    parts.leader
                );
                if let Ok(mut leaf) = self.leaf.lock() {
                    *leaf = Some(LeafHold {
                        child: parts.child,
                        _retention: parts.retention,
                    });
                }
                Transport::Lines {
                    sender: Mutex::new(Some(sender)),
                    reconnect: None,
                }
            }
            (Binding::Stdio, None) => return Err("the inspector leaf did not start".to_string()),
            (Binding::Unix(path), _) => Transport::Lines {
                sender: Mutex::new(Some(connect_unix(&runtime, path)?)),
                reconnect: Some(path.clone()),
            },
            (Binding::Https(url), _) => Transport::Https {
                client: https_client(&self.config)?,
                url: url.clone(),
                bearer: open_bearer(&self.config, url)?,
            },
        };
        let _ = self.started.set(Started { runtime, transport });
        let this = Arc::clone(self);
        let capabilities = tokio::task::spawn_blocking(move || this.fetch_capabilities())
            .await
            .map_err(|error| format!("capabilities task: {error}"))??;
        let show = |labels: Option<&BTreeSet<String>>| {
            labels.map_or_else(|| "absent".to_string(), |labels| format!("{labels:?}"))
        };
        eprintln!(
            "strands-box: inspection: inspector {} via {} http labels={} max_body_bytes={} dns labels={} connect labels={}",
            capabilities.name,
            describe(&binding),
            show(capabilities.http.as_ref().map(|http| &http.labels)),
            capabilities
                .http
                .as_ref()
                .map_or(0, |http| http.max_body_bytes),
            show(capabilities.dns.as_ref()),
            show(capabilities.connect.as_ref()),
        );
        let subjects = [
            (
                "Inspection::Content",
                "http",
                self.requested.content.as_ref(),
                capabilities.http.as_ref().map(|http| &http.labels),
            ),
            (
                "Inspection::Domain",
                "dns",
                self.requested.domain.as_ref(),
                capabilities.dns.as_ref(),
            ),
            (
                "Inspection::Address",
                "connect",
                self.requested.address.as_ref(),
                capabilities.connect.as_ref(),
            ),
        ];
        for (provider, kind, requested, supported) in subjects {
            let Some(requested) = requested else { continue };
            let Some(supported) = supported else {
                return Err(format!(
                    "the policy uses {provider}, and the inspector does not list the `{kind}` subject"
                ));
            };
            let missing: Vec<&String> = requested.difference(supported).collect();
            if !missing.is_empty() {
                eprintln!(
                    "strands-box: inspection: warning: the policy asks for {missing:?}, which the \
                     inspector does not list for {kind}; those labels are never found"
                );
            }
        }
        let _ = self.capabilities.set(capabilities);
        Ok(())
    }

    fn fetch_capabilities(&self) -> Result<Capabilities, String> {
        let deadline = Instant::now() + self.timeout;
        let result = self
            .call("capabilities", json!({}), deadline)
            .map_err(|error| format!("capabilities: {error}"))?;
        let versions: Vec<&str> = result
            .get("versions")
            .and_then(Value::as_array)
            .ok_or("capabilities: no `versions`")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        if !versions.iter().any(|version| major(version) == Some("0")) {
            return Err(format!(
                "capabilities: the inspector speaks {versions:?}, and Box speaks major 0"
            ));
        }
        let inspector = result.get("inspector");
        let field = |key: &str| {
            inspector
                .and_then(|i| i.get(key))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string()
        };
        let subjects = result
            .get("subjects")
            .and_then(Value::as_object)
            .ok_or("capabilities: `subjects` is absent")?;
        let labels_of = |kind: &str| -> Result<Option<BTreeSet<String>>, String> {
            let Some(subject) = subjects.get(kind) else {
                return Ok(None);
            };
            Ok(Some(
                subject
                    .get("labels")
                    .and_then(Value::as_array)
                    .ok_or(format!("capabilities: `subjects.{kind}.labels` is absent"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            ))
        };
        let http = match labels_of("http")? {
            None => None,
            Some(labels) => {
                let max_body_bytes = subjects["http"]
                    .get("max_body_bytes")
                    .and_then(Value::as_u64)
                    .ok_or("capabilities: `subjects.http.max_body_bytes` is absent")?;
                Some(HttpSubject {
                    labels,
                    max_body_bytes: usize::try_from(max_body_bytes).unwrap_or(usize::MAX),
                })
            }
        };
        let dns = labels_of("dns")?;
        let connect = labels_of("connect")?;
        if http.is_none() && dns.is_none() && connect.is_none() {
            return Err("capabilities: the inspector lists no subject Box sends".to_string());
        }
        Ok(Capabilities {
            name: format!("{} {}", field("name"), field("version")),
            http,
            dns,
            connect,
        })
    }

    /// One request and its response's `result`, or the reason the decision failed.
    fn call(&self, op: &str, params: Value, deadline: Instant) -> Result<Value, String> {
        let started = self.started.get().ok_or("the inspector is not started")?;
        let id = format!("box-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let message = json!({ "v": PROTOCOL_VERSION, "id": id, "op": op, "params": params });
        let mut line = message.to_string();
        if line.len() > MAX_MESSAGE_BYTES {
            return Err("the request is over the 16 MiB message limit".to_string());
        }
        let (reply, wait) = std::sync::mpsc::channel();
        match &started.transport {
            Transport::Lines { sender, reconnect } => {
                line.push('\n');
                let mut guard = sender.lock().map_err(|_| "inspector lock poisoned")?;
                if guard.as_ref().is_none_or(|s| s.is_closed()) {
                    *guard = None;
                    match reconnect {
                        Some(path) => *guard = Some(connect_unix(&started.runtime, path)?),
                        None => return Err("the inspector leaf is gone".to_string()),
                    }
                }
                guard
                    .as_ref()
                    .expect("set above")
                    .send((id.clone(), line, reply))
                    .map_err(|_| "the inspector connection is gone".to_string())?;
            }
            Transport::Https {
                client,
                url,
                bearer,
            } => {
                let authorization = bearer.authorization(url, line.as_bytes())?;
                let request = client
                    .post(url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .header(reqwest::header::AUTHORIZATION, authorization)
                    .timeout(deadline.saturating_duration_since(Instant::now()))
                    .body(line);
                started.runtime.spawn(async move {
                    let outcome = async {
                        let response = request.send().await.map_err(|e| format!("POST: {e}"))?;
                        let status = response.status();
                        let body = response.bytes().await.map_err(|e| format!("read: {e}"))?;
                        serde_json::from_slice::<Value>(&body)
                            .map_err(|_| format!("HTTP {status} without a valid message body"))
                    }
                    .await;
                    let _ = reply.send(outcome);
                });
            }
        }
        let response = wait
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| format!("no response within {} ms", self.timeout.as_millis()))??;
        result_of(response, &id)
    }
}

impl Bearer {
    /// The `Authorization` value, with the vault's real secret in place of the phantom.
    fn authorization(&self, url: &str, body: &[u8]) -> Result<String, String> {
        let headers = vec![(
            "authorization".to_string(),
            format!("Bearer {}", self.phantom),
        )];
        let attachment = self
            .vault
            .attach_for(credentials::Outbound {
                destination: credentials::Destination {
                    host: &self.host,
                    port: self.port,
                    path: &self.path,
                },
                method: "POST",
                url,
                query: "",
                headers: &headers,
                body,
            })
            .map_err(|error| format!("inspector credential: {error}"))?
            .ok_or("inspector credential: the vault governs no credential for the endpoint")?;
        attachment
            .set_headers()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.to_string())
            .ok_or_else(|| "inspector credential: the vault set no authorization".to_string())
    }
}

impl ContentInspector for PrototypeInspector {
    fn inspect(&self, request: &InspectionRequest<'_>) -> Result<InspectionVerdict, String> {
        let begun = Instant::now();
        let deadline = begun + self.timeout;
        let capabilities = self
            .capabilities
            .get()
            .ok_or("the inspector is not started")?;
        let http = capabilities
            .http
            .as_ref()
            .ok_or("the inspector does not list the `http` subject")?;
        let labels: Vec<&String> = request
            .labels
            .iter()
            .filter(|label| http.labels.contains(*label))
            .collect();
        if labels.is_empty() {
            return Ok(InspectionVerdict {
                labels: Vec::new(),
                backend: capabilities.name.clone(),
                ..InspectionVerdict::default()
            });
        }
        let headers: Vec<[String; 2]> = request
            .headers
            .iter()
            .map(|(name, value)| {
                let lower = name.to_ascii_lowercase();
                let value = if REDACTED_HEADERS.contains(&lower.as_str()) {
                    "[redacted]".to_string()
                } else {
                    value.clone()
                };
                [lower, value]
            })
            .collect();
        let mut subject = json!({
            "kind": "http",
            "method": request.method,
            "url": request.url,
            "headers": headers,
        });
        if !request.body.is_empty() {
            subject["body_b64"] =
                Value::String(base64::engine::general_purpose::STANDARD.encode(request.body));
        }
        let params = json!({
            "subject": subject,
            "labels": labels,
            "context": { "gateway": "strands-box", "box": self.box_name, "caller": "agent" },
        });
        let result = self.call("classify", params, deadline)?;
        let found = found_labels(&result, &labels)?;
        Ok(InspectionVerdict {
            labels: found,
            backend: capabilities.name.clone(),
            latency_ms: elapsed_ms(begun),
            cached: false,
        })
    }

    fn max_body_bytes(&self) -> usize {
        self.capabilities
            .get()
            .and_then(|capabilities| capabilities.http.as_ref())
            .map_or(0, |http| http.max_body_bytes)
    }

    fn inspect_name(&self, request: &NameInspection<'_>) -> Result<InspectionVerdict, String> {
        let begun = Instant::now();
        let deadline = begun + self.timeout;
        let capabilities = self
            .capabilities
            .get()
            .ok_or("the inspector is not started")?;
        let (kind, supported) = match request.kind {
            NameSubjectKind::Dns => ("dns", capabilities.dns.as_ref()),
            NameSubjectKind::Connect => ("connect", capabilities.connect.as_ref()),
        };
        let supported =
            supported.ok_or_else(|| format!("the inspector does not list the `{kind}` subject"))?;
        let mut labels: Vec<&String> = request
            .labels
            .iter()
            .filter(|label| supported.contains(*label))
            .collect();
        labels.sort_unstable();
        labels.dedup();
        let backend = capabilities.name.clone();
        if labels.is_empty() {
            return Ok(InspectionVerdict {
                backend,
                ..InspectionVerdict::default()
            });
        }
        let name = normalize_name(request.name)?;
        let mut subject = json!({ "kind": kind, "name": name, "port": request.port });
        if let Some(ip) = request.ip {
            subject["ip"] = Value::String(ip.to_string());
        }
        let key = format!("{subject}|{labels:?}");
        if let Some(found) = self.cached(&key) {
            return Ok(InspectionVerdict {
                labels: found,
                backend,
                latency_ms: elapsed_ms(begun),
                cached: true,
            });
        }
        let params = json!({
            "subject": subject,
            "labels": labels,
            "context": { "gateway": "strands-box", "box": self.box_name, "caller": "agent" },
        });
        let result = self.call("classify", params, deadline)?;
        let found = found_labels(&result, &labels)?;
        if let Some(ttl) = result.get("cache_ttl_s").and_then(Value::as_u64)
            && ttl > 0
        {
            self.remember(key, found.clone(), Duration::from_secs(ttl));
        }
        Ok(InspectionVerdict {
            labels: found,
            backend,
            latency_ms: elapsed_ms(begun),
            cached: false,
        })
    }
}

impl PrototypeInspector {
    fn cached(&self, key: &str) -> Option<Vec<String>> {
        let mut cache = self.cache.lock().ok()?;
        match cache.get(key) {
            Some(entry) if entry.expires > Instant::now() => Some(entry.labels.clone()),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    fn remember(&self, key: String, labels: Vec<String>, ttl: Duration) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.len() >= CACHE_ENTRIES {
            let now = Instant::now();
            cache.retain(|_, entry| entry.expires > now);
            if cache.len() >= CACHE_ENTRIES {
                cache.clear();
            }
        }
        cache.insert(
            key,
            Cached {
                expires: Instant::now() + ttl,
                labels,
            },
        );
    }
}

/// The `name` of a `dns` or `connect` subject: lower case, no trailing dot, IDN in `xn--` form.
fn normalize_name(host: &str) -> Result<String, String> {
    let trimmed = host.trim_end_matches('.');
    if let Ok(ip) = trimmed
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
    {
        return Ok(ip.to_string());
    }
    let url = reqwest::Url::parse(&format!("http://{trimmed}/"))
        .map_err(|error| format!("host {host:?} is not a valid name: {error}"))?;
    let name = url
        .host_str()
        .ok_or_else(|| format!("host {host:?} has no name"))?;
    Ok(name.trim_end_matches('.').to_ascii_lowercase())
}

/// The requested labels a classify `result` found, or the reason the decision failed.
fn found_labels(result: &Value, asked: &[&String]) -> Result<Vec<String>, String> {
    result
        .get("labels")
        .and_then(Value::as_array)
        .ok_or("result has no `labels` array")?
        .iter()
        .map(|label| {
            let label = label.as_str().ok_or("a label is not a string")?;
            if asked.iter().any(|asked| asked.as_str() == label) {
                Ok(label.to_string())
            } else {
                Err(format!(
                    "the inspector returned {label:?}, which was not requested"
                ))
            }
        })
        .collect()
}

fn elapsed_ms(begun: Instant) -> u64 {
    u64::try_from(begun.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn major(version: &str) -> Option<&str> {
    version.split_once('.').map(|(major, _)| major)
}

fn describe(binding: &Binding) -> String {
    match binding {
        Binding::Stdio => "stdio".to_string(),
        Binding::Unix(path) => format!("unix {}", path.display()),
        Binding::Https(url) => format!("https {url}"),
    }
}

/// The `result` of a response to `id`, or the failed decision it stands for.
fn result_of(response: Value, id: &str) -> Result<Value, String> {
    let version = response
        .get("v")
        .and_then(Value::as_str)
        .ok_or("response has no string `v`")?;
    if major(version) != Some("0") {
        return Err(format!("response version {version:?} is not major 0"));
    }
    if response.get("id").and_then(Value::as_str) != Some(id) {
        return Err("response id does not match".to_string());
    }
    match (response.get("result"), response.get("error")) {
        (Some(result), None) if result.is_object() => Ok(result.clone()),
        (None, Some(error)) => {
            let code = error.get("code").and_then(Value::as_str).unwrap_or("");
            let message = error.get("message").and_then(Value::as_str).unwrap_or("");
            if KNOWN_ERRORS.contains(&code) {
                Err(format!("inspector error {code}: {message}"))
            } else {
                Err(format!(
                    "inspector error internal (unknown code {code:?}): {message}"
                ))
            }
        }
        _ => Err("response has neither exactly one `result` object nor an `error`".to_string()),
    }
}

/// A task that writes queued requests and pairs each response line with its request by `id`.
fn spawn_lines<R, W>(
    runtime: &tokio::runtime::Handle,
    reader: R,
    mut writer: W,
) -> tokio::sync::mpsc::UnboundedSender<Pending>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<Pending>();
    let mut lines = tokio::io::BufReader::new(reader).lines();
    runtime.spawn(async move {
        let mut waiting: HashMap<String, Reply> = HashMap::new();
        loop {
            tokio::select! {
                queued = receiver.recv() => {
                    let Some((id, line, reply)) = queued else { break };
                    let written = async {
                        writer.write_all(line.as_bytes()).await?;
                        writer.flush().await
                    }
                    .await;
                    if let Err(error) = written {
                        let _ = reply.send(Err(format!("write to inspector: {error}")));
                        break;
                    }
                    waiting.insert(id, reply);
                }
                read = lines.next_line() => {
                    let Ok(Some(line)) = read else { break };
                    if line.len() > MAX_MESSAGE_BYTES {
                        continue;
                    }
                    let Ok(value) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    if let Some(reply) = value
                        .get("id")
                        .and_then(Value::as_str)
                        .and_then(|id| waiting.remove(id))
                    {
                        let _ = reply.send(Ok(value));
                    }
                }
            }
        }
        for (_, reply) in waiting.drain() {
            let _ = reply.send(Err("the inspector stream closed".to_string()));
        }
    });
    sender
}

/// Check the socket's owner and mode (spec 3.2), then connect.
fn connect_unix(
    runtime: &tokio::runtime::Handle,
    path: &std::path::Path,
) -> Result<tokio::sync::mpsc::UnboundedSender<Pending>, String> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("stat {shown}: {e}"))?;
    if !meta.file_type().is_socket() {
        return Err(format!("{shown} is not a socket"));
    }
    // SAFETY: `geteuid` has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        return Err(format!("{shown} is owned by uid {}, not {uid}", meta.uid()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{shown} is writable by group or others (mode {:o})",
            meta.mode() & 0o777
        ));
    }
    let stream = std::os::unix::net::UnixStream::connect(path)
        .map_err(|e| format!("connect {shown}: {e}"))?;
    stream.set_nonblocking(true).map_err(|e| e.to_string())?;
    let _entered = runtime.enter();
    let stream = tokio::net::UnixStream::from_std(stream).map_err(|e| e.to_string())?;
    let (reader, writer) = stream.into_split();
    Ok(spawn_lines(runtime, reader, writer))
}

fn https_client(config: &InspectionConfig) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(ca_file) = &config.ca_file {
        let pem = std::fs::read(ca_file).map_err(|e| format!("read {}: {e}", ca_file.display()))?;
        let ca = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| format!("ca_file {}: {e}", ca_file.display()))?;
        builder = builder.add_root_certificate(ca);
    }
    builder.build().map_err(|e| format!("https client: {e}"))
}

/// Resolve `secret.ref` through a Box credential vault bound to the endpoint.
fn open_bearer(config: &InspectionConfig, url: &str) -> Result<Bearer, String> {
    let reference = &config
        .secret
        .as_ref()
        .ok_or("an https endpoint needs `secret.ref`")?
        .reference;
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("endpoint: {e}"))?;
    let host = parsed.host_str().ok_or("endpoint has no host")?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let destination = credentials::DestinationPattern::parse(&format!("{host}:{port}"))
        .map_err(|e| format!("endpoint destination: {e}"))?;
    let locator = credentials::Locator::parse_uri(reference).map_err(|e| e.to_string())?;
    let inject = credentials::InjectMode::header("Bearer {}", None).map_err(|e| e.to_string())?;
    let opened = credentials::Vault::open(
        credentials::VaultConfig::new(
            credentials::Backend::local(),
            format!("strands-box-inspector-{}", std::process::id()),
        )
        .route(credentials::RouteSpec::opaque(destination, locator, inject))
        .require_every_route(),
    )
    .map_err(|e| format!("`secret.ref` did not resolve: {e}"))?;
    let phantom = match opened.phantoms() {
        [phantom] => phantom.token().to_string(),
        other => {
            return Err(format!(
                "`secret.ref` minted {} placeholders, expected one bearer token",
                other.len()
            ));
        }
    };
    Ok(Bearer {
        vault: opened.into_vault(),
        phantom,
        host,
        port,
        path: parsed.path().to_string(),
    })
}
