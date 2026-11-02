//! One target, and the two ways a batch leaves it.

use std::os::unix::fs::OpenOptionsExt as _;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::transform::common::tonic::ResourceAttributesWithSchema;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::logs::LogBatch;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::Mutex;

use crate::config::{Payload, Target, TargetKind, TargetSecret};
use crate::error::{Result, TelemetryError};

/// The box a record belongs to, so a merged store stays attributable.
pub(crate) const BOX_ATTRIBUTE: &str = "strands.box.name";

/// The one invocation of `run` a record belongs to.
pub(crate) const RUN_ATTRIBUTE: &str = "strands.box.run.id";

/// What a span does not repeat, because a span field already states it.
pub(crate) const SPAN_OMITS: [&str; 1] = ["strands.box.trace.parent_span_id"];

/// Who produced a record.
pub(crate) const SOURCE_ATTRIBUTE: &str = "strands.box.source";

/// The value the box's own records carry.
pub(crate) const SOURCE_BOX: &str = "box";

/// The value an agent's own spans carry.
pub(crate) const SOURCE_AGENT: &str = "agent";

/// The longest one export to an endpoint may take. Shorter than the drain's budget, which
/// `collector.rs` asserts.
pub(crate) const REQUEST_DEADLINE: Duration = Duration::from_secs(4);

/// Where one target's batches go.
#[derive(Debug)]
enum Wire {
    /// One OTLP-JSON request per line, appended through one handle held open.
    File(Mutex<tokio::fs::File>),
    /// OTLP over HTTP, protobuf.
    Otlp {
        base: String,
        client: reqwest::Client,
        secret: Option<TargetSecret>,
        headers: Vec<(String, String)>,
        vault: Option<std::sync::Arc<credentials::Vault>>,
    },
}

/// One declared target, as the SDK's exporter.
#[derive(Debug)]
pub(crate) struct TargetExporter {
    wire: Wire,
    /// The payloads the destination takes. A batch of any other payload is not sent.
    accepts: Vec<Payload>,
    /// Set once when the provider is built.
    resource: std::sync::OnceLock<ResourceAttributesWithSchema>,
    /// Bumped for every batch a target refused, so a failing endpoint is not silent.
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Whether a failed batch is also printed to stderr, set by `STRANDS_BOX_TELEMETRY_DEBUG`.
    reports_failures: bool,
}

impl TargetExporter {
    /// Open the exporter `target` names, refusing what cannot work.
    pub(crate) fn open(
        target: &Target,
        dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<Self> {
        Self::open_with(target, dropped, reqwest::Client::builder())
    }

    /// [`open`](Self::open) over a caller's client builder, so a test can pin name resolution.
    fn open_with(
        target: &Target,
        dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
        client: reqwest::ClientBuilder,
    ) -> Result<Self> {
        let accepts = target.accepts();
        let wire = match target.kind() {
            TargetKind::File => {
                if let Some(file) = target.file() {
                    let file = file.try_clone().map_err(|source| TelemetryError::Config {
                        reason: format!("{} could not be cloned: {source}", target.destination()),
                    })?;
                    return Ok(Self {
                        wire: Wire::File(Mutex::new(tokio::fs::File::from_std(file))),
                        accepts,
                        resource: std::sync::OnceLock::new(),
                        dropped,
                        reports_failures: reports_failures(),
                    });
                }
                // Only the parent chain; `O_NOFOLLOW` still guards the final component.
                if let Some(parent) = std::path::Path::new(target.destination())
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                {
                    std::fs::create_dir_all(parent).map_err(|source| TelemetryError::Config {
                        reason: format!(
                            "{} could not be created to hold {}: {source}",
                            parent.display(),
                            target.destination()
                        ),
                    })?;
                }
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(target.destination())
                    .map_err(|source| TelemetryError::Config {
                        reason: format!("{} could not be opened: {source}", target.destination()),
                    })?;
                Wire::File(Mutex::new(tokio::fs::File::from_std(file)))
            }
            TargetKind::Otlp => Wire::Otlp {
                base: crate::config::dialed(target.destination())
                    .trim_end_matches('/')
                    .to_string(),
                client: client
                    .timeout(REQUEST_DEADLINE)
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .build()
                    .map_err(|source| TelemetryError::Config {
                        reason: format!("the OTLP client could not be built: {source}"),
                    })?,
                secret: target.secret().cloned(),
                headers: target.headers().to_vec(),
                vault: target.vault().cloned(),
            },
        };
        Ok(Self {
            wire,
            accepts,
            resource: std::sync::OnceLock::new(),
            dropped,
            reports_failures: reports_failures(),
        })
    }

    /// Take the provider's resource. Later calls are ignored.
    pub(crate) fn set_resource_once(&self, resource: &Resource) {
        let _ = self
            .resource
            .set(ResourceAttributesWithSchema::from(resource));
    }

    /// Encode and send one log batch, stamped with the provider's resource.
    pub(crate) async fn export_logs(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let resource = self
            .resource
            .get_or_init(ResourceAttributesWithSchema::default);
        let request = ExportLogsServiceRequest {
            resource_logs:
                opentelemetry_proto::transform::logs::tonic::group_logs_by_resource_and_scope(
                    &batch, resource,
                ),
        };
        let traces = if self.accepts.contains(&Payload::Traces) {
            box_spans(&request)
        } else {
            ExportTraceServiceRequest {
                resource_spans: Vec::new(),
            }
        };
        if traces.resource_spans.is_empty() {
            return self.deliver(Payload::Logs, &request).await;
        }
        let (logs, spans) = tokio::join!(
            self.deliver(Payload::Logs, &request),
            self.deliver(Payload::Traces, &traces)
        );
        logs.and(spans)
    }

    /// Relay one span batch the agent already encoded.
    pub(crate) async fn relay_trace(&self, request: &ExportTraceServiceRequest) -> OTelSdkResult {
        self.deliver(Payload::Traces, request).await
    }

    /// Relay one log batch the agent already encoded.
    ///
    /// Separate from [`Self::export_logs`], which encodes the box's own records and derives their
    /// spans. An agent's batch is relayed unchanged, so no `box_spans` pass runs over it.
    pub(crate) async fn relay_logs(&self, request: &ExportLogsServiceRequest) -> OTelSdkResult {
        self.deliver(Payload::Logs, request).await
    }

    /// Relay one metric batch the agent already encoded.
    pub(crate) async fn relay_metrics(
        &self,
        request: &ExportMetricsServiceRequest,
    ) -> OTelSdkResult {
        self.deliver(Payload::Metrics, request).await
    }

    /// Send one batch, counting it when it does not go. A payload the destination does not take is
    /// not sent and not counted.
    async fn deliver<T>(&self, payload: Payload, request: &T) -> OTelSdkResult
    where
        T: serde::Serialize + prost::Message,
    {
        if !self.accepts.contains(&payload) {
            return Ok(());
        }
        let outcome = self.attempt(payload.route(), request).await;
        if let Err(error) = &outcome {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.reports_failures {
                eprintln!("strands-box: telemetry export failed: {error}");
            }
        }
        outcome
    }

    /// Send one batch, or report why it did not go.
    async fn attempt<T>(&self, route: &str, request: &T) -> OTelSdkResult
    where
        T: serde::Serialize + prost::Message,
    {
        match &self.wire {
            Wire::File(handle) => {
                let line = one_line(request)?;
                let mut file = handle.lock().await;
                file.write_all(&line)
                    .await
                    .map_err(|source| OTelSdkError::InternalFailure(source.to_string()))?;
                file.sync_all()
                    .await
                    .map_err(|source| OTelSdkError::InternalFailure(source.to_string()))
            }
            Wire::Otlp {
                base,
                client,
                secret,
                headers,
                vault,
            } => {
                let url = format!("{base}{route}");
                let body = request.encode_to_vec();
                let mut fixed: Vec<(String, String)> =
                    vec![("content-type".to_string(), PROTOBUF.to_string())];
                fixed.extend(headers.iter().cloned());
                let attachment = match vault {
                    Some(vault) => attachment_for(vault, &url, &fixed, &body).await?,
                    None => None,
                };
                if let Some(attachment) = &attachment {
                    fixed.retain(|(name, _)| {
                        !attachment
                            .strip_headers()
                            .any(|stripped| stripped.eq_ignore_ascii_case(name))
                    });
                }
                let mut sending = client.post(&url).body(body);
                for (name, value) in &fixed {
                    sending = sending.header(name, value);
                }
                if let Some(secret) = secret {
                    sending = sending.header(secret.header(), secret.value());
                }
                if let Some(attachment) = &attachment {
                    for (name, value) in attachment.set_headers() {
                        let mut value = reqwest::header::HeaderValue::from_str(value.as_str())
                            .map_err(|_| {
                                OTelSdkError::InternalFailure(format!(
                                    "the credential for {url} is not a valid {name} header value"
                                ))
                            })?;
                        value.set_sensitive(true);
                        sending = sending.header(name, value);
                    }
                }
                let response = sending.send().await.map_err(|source| {
                    OTelSdkError::InternalFailure(format!(
                        "{url} did not answer: {}",
                        with_causes(&source)
                    ))
                })?;
                let status = response.status();
                if status.is_success() {
                    Ok(())
                } else {
                    let detail = if self.reports_failures {
                        let body = response.text().await.unwrap_or_default();
                        let body: String = body.chars().take(FAILURE_DETAIL_CHARS).collect();
                        format!(": {}", body.trim())
                    } else {
                        String::new()
                    };
                    Err(OTelSdkError::InternalFailure(format!(
                        "{url} answered {status}{detail}"
                    )))
                }
            }
        }
    }
}

/// The variable that turns on a stderr line for each failed batch.
const FAILURE_REPORT_VARIABLE: &str = "STRANDS_BOX_TELEMETRY_DEBUG";

/// How much of a refusing endpoint's answer a failure report quotes.
const FAILURE_DETAIL_CHARS: usize = 300;

fn reports_failures() -> bool {
    std::env::var_os(FAILURE_REPORT_VARIABLE).is_some_and(|value| !value.is_empty())
}

/// An error and each cause beneath it, on one line.
fn with_causes(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        text.push_str(": ");
        text.push_str(&next.to_string());
        cause = next.source();
    }
    text
}

/// The OTLP/HTTP body encoding every request carries.
const PROTOBUF: &str = "application/x-protobuf";

/// What the vault attaches to one request, asked off the runtime thread because a signing resolve
/// may read a file or a socket.
async fn attachment_for(
    vault: &std::sync::Arc<credentials::Vault>,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> std::result::Result<Option<credentials::Attachment>, OTelSdkError> {
    let vault = std::sync::Arc::clone(vault);
    let url = url.to_string();
    let headers = headers.to_vec();
    let body = body.to_vec();
    let attachment = tokio::task::spawn_blocking(move || {
        let parsed =
            url::Url::parse(&url).map_err(|_| format!("{url} is not a URL the vault can match"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("{url} names no host"))?;
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| format!("{url} names no port"))?;
        vault
            .attach_for(credentials::Outbound {
                destination: credentials::Destination {
                    host,
                    port,
                    path: parsed.path(),
                },
                method: "POST",
                url: &url,
                query: parsed.query().unwrap_or(""),
                headers: &headers,
                body: &body,
            })
            .map_err(|error| format!("the credential for {url} did not attach: {error}"))
    })
    .await
    .map_err(|error| OTelSdkError::InternalFailure(error.to_string()))?
    .map_err(OTelSdkError::InternalFailure)?;
    match attachment {
        Some(attachment)
            if attachment.rewrite_path_to().is_some()
                || attachment.set_query().next().is_some() =>
        {
            Err(OTelSdkError::InternalFailure(
                "a telemetry credential attaches in a header, never in the path or the query"
                    .to_string(),
            ))
        }
        // The vault was opened for this destination alone, so an empty answer is a defect, and a
        // request without its credential is not sent.
        None => Err(OTelSdkError::InternalFailure(
            "the target's vault governs no credential for its own destination".to_string(),
        )),
        attached => Ok(attached),
    }
}

/// One string attribute, or nothing when the key is absent or holds another type.
fn text<'a>(
    attributes: &'a [opentelemetry_proto::tonic::common::v1::KeyValue],
    key: &str,
) -> Option<&'a str> {
    use opentelemetry_proto::tonic::common::v1::any_value;
    attributes.iter().find_map(|attribute| {
        if attribute.key != key {
            return None;
        }
        match attribute.value.as_ref()?.value.as_ref()? {
            any_value::Value::StringValue(value) => Some(value.as_str()),
            _ => None,
        }
    })
}

/// Which of the box's two planes a scope carries, and how its spans read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Plane {
    /// One effective decision, under `strands-box.policy`.
    Policy,
    /// One change to the authority this box holds, under `strands-box.control`.
    Control,
}

impl Plane {
    /// The plane one scope name carries, or nothing when the scope is the agent's.
    fn of(scope: Option<&str>) -> Option<Self> {
        match scope? {
            crate::collector::SCOPE => Some(Self::Policy),
            crate::collector::CONTROL_SCOPE => Some(Self::Control),
            _ => None,
        }
    }

    /// The span's name, taken from the record's own subject.
    fn span_name(self, attributes: &[opentelemetry_proto::tonic::common::v1::KeyValue]) -> String {
        match self {
            Self::Policy => format!(
                "policy {}",
                text(attributes, "strands.box.policy.action").unwrap_or("decision")
            ),
            Self::Control => format!(
                "control {}",
                text(attributes, "strands.box.control.operation").unwrap_or("operation")
            ),
        }
    }

    /// The failure this span reports, when it reports one.
    fn failure(
        self,
        attributes: &[opentelemetry_proto::tonic::common::v1::KeyValue],
    ) -> Option<&'static str> {
        match self {
            Self::Policy => (text(attributes, "strands.box.policy.cause")
                == Some("internal_fault"))
            .then_some("policy evaluation failed"),
            // An absent outcome is not a failure: every `ControlRecord` carries one, so the absence
            // would be this crate's own defect rather than the operation's.
            Self::Control => text(attributes, "strands.box.control.outcome")
                .is_some_and(|outcome| outcome != "ok")
                .then_some("control-plane operation failed"),
        }
    }
}

/// Every box record in one log batch, as the matching span.
fn box_spans(logs: &ExportLogsServiceRequest) -> ExportTraceServiceRequest {
    use opentelemetry::trace::SpanId;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, Status};

    let resource_spans = logs
        .resource_logs
        .iter()
        .filter_map(|resource| {
            let scope_spans: Vec<_> = resource
                .scope_logs
                .iter()
                .filter_map(|scope| {
                    let plane = Plane::of(scope.scope.as_ref().map(|scope| scope.name.as_str()))?;
                    let spans: Vec<_> = scope
                        .log_records
                        .iter()
                        .filter(|record| record.trace_id.len() == 16 && record.span_id.len() == 8)
                        .map(|record| {
                            let parent_span_id =
                                text(&record.attributes, "strands.box.trace.parent_span_id")
                                    .and_then(|parent| SpanId::from_hex(parent).ok())
                                    .map(|parent| parent.to_bytes().to_vec())
                                    .unwrap_or_default();
                            let failure = plane.failure(&record.attributes);
                            // A control child parents under this run's own root, which is local, so
                            // only a decision can carry a remote caller's parent.
                            let remote_parent = match plane {
                                Plane::Policy if !parent_span_id.is_empty() => 0x300,
                                _ => 0,
                            };
                            Span {
                                trace_id: record.trace_id.clone(),
                                span_id: record.span_id.clone(),
                                parent_span_id,
                                name: plane.span_name(&record.attributes),
                                kind: 1,
                                start_time_unix_nano: record.time_unix_nano,
                                end_time_unix_nano: record.time_unix_nano,
                                attributes: record
                                    .attributes
                                    .iter()
                                    .filter(|attribute| {
                                        !SPAN_OMITS.contains(&attribute.key.as_str())
                                    })
                                    .cloned()
                                    .collect(),
                                flags: record.flags | remote_parent,
                                status: failure.map(|message| Status {
                                    code: 2,
                                    message: message.to_string(),
                                }),
                                ..Default::default()
                            }
                        })
                        .collect();
                    (!spans.is_empty()).then(|| ScopeSpans {
                        scope: scope.scope.clone(),
                        spans,
                        schema_url: scope.schema_url.clone(),
                    })
                })
                .collect();
            (!scope_spans.is_empty()).then(|| ResourceSpans {
                resource: resource.resource.clone(),
                scope_spans,
                schema_url: resource.schema_url.clone(),
            })
        })
        .collect();
    ExportTraceServiceRequest { resource_spans }
}

/// One request as one newline-terminated JSON line, so a reader never sees half a record.
fn one_line<T: serde::Serialize>(request: &T) -> std::result::Result<Vec<u8>, OTelSdkError> {
    let mut line = serde_json::to_vec(request)
        .map_err(|source| OTelSdkError::InternalFailure(source.to_string()))?;
    line.push(b'\n');
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file target opens under a directory that does not exist yet.
    #[test]
    fn a_file_target_creates_the_directory_that_holds_it() {
        let directory = tempfile::tempdir().expect("tempdir");
        let destination = directory.path().join("absent/records.jsonl");
        let target = crate::config::Target::new(
            crate::config::TargetKind::File,
            destination.to_string_lossy().to_string(),
        );
        TargetExporter::open(&target, std::sync::Arc::default()).expect("the target opens");
        assert!(
            destination.exists(),
            "{} was not created",
            destination.display()
        );
    }

    /// A transport failure names each cause beneath it, so a timeout reads apart from a reset.
    #[tokio::test]
    async fn a_transport_failure_names_its_cause() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let failure = reqwest::Client::new()
            .post(format!("http://{address}/v1/traces"))
            .send()
            .await
            .expect_err("nothing listens");
        let text = with_causes(&failure);
        assert!(
            text.starts_with(&failure.to_string()) && text.len() > failure.to_string().len(),
            "the causes follow the error: {text}"
        );
    }

    /// A serialized request is one line, so two batches never share one.
    #[test]
    fn the_serialized_request_is_one_line() {
        let request = ExportLogsServiceRequest {
            resource_logs: Vec::new(),
        };
        let line = one_line(&request).expect("serialize");
        assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(line.last(), Some(&b'\n'));
    }

    /// **A redirect never carries the credential to the host it names.**
    ///
    /// `reqwest` follows ten redirects by default, and its own sensitive-header strip keys on
    /// `host:port` — so a same-authority `https:` to `http:` downgrade kept the vendor key, and a
    /// vendor's own header name was never in that list at all.
    #[tokio::test]
    async fn a_redirect_never_carries_the_credential() {
        use tokio::io::AsyncReadExt as _;

        let second = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the redirect's destination");
        let elsewhere = second.local_addr().expect("its address");
        let first = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the declared destination");
        let declared = first.local_addr().expect("its address");

        // The declared endpoint answers a redirect and nothing else.
        tokio::spawn(async move {
            let (mut stream, _) = first.accept().await.expect("accept");
            let mut ignored = [0u8; 2048];
            let _ = stream.read(&mut ignored).await;
            let answer = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{elsewhere}/v1/logs\r\n\
                 content-length: 0\r\n\r\n"
            );
            let _ = stream.write_all(answer.as_bytes()).await;
        });
        // What the host the redirect names actually received.
        let received = tokio::spawn(async move {
            let (mut stream, _) = second.accept().await.expect("accept");
            let mut asked = vec![0u8; 4096];
            let read = stream.read(&mut asked).await.unwrap_or(0);
            asked.truncate(read);
            String::from_utf8_lossy(&asked).to_string()
        });

        let target = Target::new(TargetKind::Otlp, format!("http://{declared}"))
            .with_secret(TargetSecret::new("x-honeycomb-team", "vendor-key-abc123"));
        let exporter = TargetExporter::open(
            &target,
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        )
        .expect("open");
        let sent = exporter
            .relay_trace(&ExportTraceServiceRequest {
                resource_spans: Vec::new(),
            })
            .await;

        assert!(sent.is_err(), "a `302` is not a delivery: {sent:?}");
        let asked = tokio::time::timeout(Duration::from_millis(250), received).await;
        assert!(
            asked.is_err(),
            "the redirect was followed, and the host it named was reached: {asked:?}"
        );
    }

    /// A stand-in endpoint that answers `200` and hands back each request's head and body.
    async fn stand_in() -> (
        std::net::SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<(String, Vec<u8>)>,
    ) {
        use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a stand-in endpoint");
        let address = listener.local_addr().expect("its address");
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let sender = sender.clone();
                tokio::spawn(async move {
                    let mut reader = tokio::io::BufReader::new(stream);
                    loop {
                        let mut head = String::new();
                        let mut length = 0usize;
                        loop {
                            let mut line = String::new();
                            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                                return;
                            }
                            if line == "\r\n" {
                                break;
                            }
                            if let Some(value) =
                                line.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                length = value.trim().parse().unwrap_or(0);
                            }
                            head.push_str(&line);
                        }
                        let mut body = vec![0u8; length];
                        if reader.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let _ = sender.send((head, body));
                        let _ = reader
                            .get_mut()
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                            .await;
                    }
                });
            }
        });
        (address, receiver)
    }

    /// One header's value in a received head, matched case-insensitively.
    fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        })
    }

    /// The first line of a received head, which names the route.
    fn request_line(head: &str) -> &str {
        head.lines().next().unwrap_or("")
    }

    fn empty_spans() -> ExportTraceServiceRequest {
        ExportTraceServiceRequest {
            resource_spans: Vec::new(),
        }
    }

    fn empty_logs() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: Vec::new(),
        }
    }

    fn opened(target: &Target) -> TargetExporter {
        TargetExporter::open(target, std::sync::Arc::default()).expect("open")
    }

    /// A secret written to a file, as the operator's `file://` reference names it.
    fn secret_file(directory: &tempfile::TempDir, value: &str) -> credentials::Locator {
        let path = directory.path().join("secret");
        std::fs::write(&path, value).expect("write the secret");
        credentials::Locator::parse_uri(&format!("file://{}", path.display())).expect("a locator")
    }

    /// One vault holding one opaque route, and the phantom it minted.
    fn opaque_vault(
        address: std::net::SocketAddr,
        locator: credentials::Locator,
        mode: credentials::InjectMode,
    ) -> (std::sync::Arc<credentials::Vault>, String) {
        let pattern =
            credentials::DestinationPattern::parse(&format!("127.0.0.1:{}", address.port()))
                .expect("a pattern");
        let opened = credentials::Vault::open(
            credentials::VaultConfig::new(credentials::Backend::local(), "telemetry-test")
                .route(credentials::RouteSpec::opaque(pattern, locator, mode))
                .require_every_route(),
        )
        .expect("the vault opens");
        let phantom = opened.phantoms()[0].token().to_string();
        (std::sync::Arc::new(opened.into_vault()), phantom)
    }

    /// **A traces-only destination receives spans and is never sent a log or a metric batch.**
    ///
    /// Langfuse and LangSmith answer `404` on `/v1/logs`, so a target that sent one would count a
    /// dropped batch every second.
    #[tokio::test]
    async fn a_traces_only_target_is_sent_no_other_payload() {
        let (address, mut received) = stand_in().await;
        let target = Target::new(TargetKind::Otlp, format!("http://{address}"))
            .accepting(vec![Payload::Traces]);
        let exporter = opened(&target);

        exporter
            .relay_logs(&empty_logs())
            .await
            .expect("an unaccepted payload is no failure");
        exporter
            .relay_metrics(&ExportMetricsServiceRequest {
                resource_metrics: Vec::new(),
            })
            .await
            .expect("an unaccepted payload is no failure");
        exporter
            .relay_trace(&empty_spans())
            .await
            .expect("the span batch is delivered");

        let (head, _) = received.recv().await.expect("one request");
        assert!(
            request_line(&head).starts_with("POST /v1/traces "),
            "{head}"
        );
        assert!(received.try_recv().is_err(), "no other payload was sent");
        assert_eq!(
            exporter.dropped.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a payload the destination does not take is not a dropped batch"
        );
    }

    /// **A destination with a path keeps it**, which is how Langfuse and LangSmith spell theirs.
    #[tokio::test]
    async fn a_destination_path_prefixes_the_route() {
        let (address, mut received) = stand_in().await;
        let target = Target::new(
            TargetKind::Otlp,
            format!("http://{address}/api/public/otel/"),
        );
        opened(&target)
            .relay_trace(&empty_spans())
            .await
            .expect("delivered");
        let (head, _) = received.recv().await.expect("one request");
        assert!(
            request_line(&head).starts_with("POST /api/public/otel/v1/traces "),
            "{head}"
        );
    }

    /// **The vault swaps the phantom for the real key, so the exporter never holds it.** This is
    /// the LangSmith shape: `x-api-key` plus a fixed project header.
    #[tokio::test]
    async fn the_vault_attaches_an_api_key_header() {
        let (address, mut received) = stand_in().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let mode = credentials::InjectMode::header("{}", Some("x-api-key".to_string()))
            .expect("a header mode");
        let (vault, phantom) =
            opaque_vault(address, secret_file(&directory, "lsv2_pt_real_key"), mode);
        let target = Target::new(TargetKind::Otlp, format!("http://{address}/otel"))
            .accepting(vec![Payload::Traces])
            .with_header("Langsmith-Project", "strands-box")
            .with_header("x-api-key", phantom.clone())
            .with_vault(vault);
        let exporter = opened(&target);
        assert!(
            !format!("{exporter:?}").contains("lsv2_pt_real_key"),
            "the exporter does not hold the key"
        );

        exporter
            .relay_trace(&empty_spans())
            .await
            .expect("delivered");
        let (head, _) = received.recv().await.expect("one request");
        assert!(
            request_line(&head).starts_with("POST /otel/v1/traces "),
            "{head}"
        );
        assert_eq!(
            header(&head, "x-api-key"),
            Some("lsv2_pt_real_key"),
            "{head}"
        );
        assert_eq!(
            header(&head, "langsmith-project"),
            Some("strands-box"),
            "{head}"
        );
        assert!(
            !head.contains(&phantom),
            "the phantom never rides upstream: {head}"
        );
    }

    /// **Basic auth carries the `public:secret` pair, encoded by the vault.** This is the Langfuse
    /// shape, with its ingestion-version header.
    #[tokio::test]
    async fn the_vault_attaches_basic_auth() {
        use base64::Engine as _;

        let (address, mut received) = stand_in().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let (vault, phantom) = opaque_vault(
            address,
            secret_file(&directory, "pk-lf-1234:sk-lf-5678"),
            credentials::InjectMode::basic_auth(),
        );
        let presented = base64::engine::general_purpose::STANDARD.encode(format!("box:{phantom}"));
        let target = Target::new(
            TargetKind::Otlp,
            format!("http://{address}/api/public/otel"),
        )
        .accepting(vec![Payload::Traces])
        .with_header("x-langfuse-ingestion-version", "4")
        .with_header("authorization", format!("Basic {presented}"))
        .with_vault(vault);

        opened(&target)
            .relay_trace(&empty_spans())
            .await
            .expect("delivered");
        let (head, _) = received.recv().await.expect("one request");
        let expected = base64::engine::general_purpose::STANDARD.encode("pk-lf-1234:sk-lf-5678");
        assert_eq!(
            header(&head, "authorization"),
            Some(format!("Basic {expected}").as_str()),
            "{head}"
        );
        assert_eq!(header(&head, "x-langfuse-ingestion-version"), Some("4"));
        assert_eq!(
            head.to_ascii_lowercase().matches("authorization:").count(),
            1,
            "one authorization header, the real one: {head}"
        );
    }

    /// **A request that presents no phantom is refused by the vault and never sent.**
    #[tokio::test]
    async fn a_request_without_its_phantom_is_not_sent() {
        let (address, mut received) = stand_in().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let mode = credentials::InjectMode::header("{}", Some("x-api-key".to_string()))
            .expect("a header mode");
        let (vault, _phantom) = opaque_vault(address, secret_file(&directory, "real"), mode);
        let target = Target::new(TargetKind::Otlp, format!("http://{address}")).with_vault(vault);
        let exporter = opened(&target);

        assert!(exporter.relay_trace(&empty_spans()).await.is_err());
        assert_eq!(
            exporter.dropped.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        let nothing = tokio::time::timeout(Duration::from_millis(200), received.recv()).await;
        assert!(nothing.is_err(), "no request reached the destination");
    }

    /// A stand-in `credsd` that answers every `credential/get` with fixed session credentials.
    fn stand_in_credsd(directory: &tempfile::TempDir) -> std::path::PathBuf {
        use std::io::{BufRead as _, Write as _};

        let socket = directory.path().join("credsd.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind credsd");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut line = String::new();
                let _ = std::io::BufReader::new(&stream).read_line(&mut line);
                let id = serde_json::from_str::<serde_json::Value>(&line)
                    .ok()
                    .and_then(|request| request.get("id").cloned())
                    .unwrap_or(serde_json::Value::Null);
                let answer = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "credential": "login",
                        "material": {
                            "type": "session_credentials",
                            "access_key_id": "ASIATELEMETRYTEST",
                            "secret_access_key": "telemetry-secret-access-key",
                            "session_token": "telemetry-session-token"
                        },
                        "expires_at": "2099-01-01T00:00:00Z",
                        "provenance": "minted_for_request"
                    }
                });
                let _ = writeln!(stream, "{answer}");
            }
        });
        socket
    }

    /// **A CloudWatch Logs target is SigV4-signed by the vault for `logs` in its region**, with the
    /// log-group and log-stream headers inside the signature.
    ///
    /// The host must be the real AWS name, because the vault derives the signing scope from it, so
    /// the client resolves that name to the stand-in.
    #[tokio::test]
    async fn a_cloudwatch_logs_target_is_signed_for_logs() {
        let (address, mut received) = stand_in().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = stand_in_credsd(&directory);
        let host = "logs.us-west-2.amazonaws.com";
        let pattern = credentials::DestinationPattern::parse(&format!("{host}:{}", address.port()))
            .expect("a pattern");
        let opened = credentials::Vault::open(
            credentials::VaultConfig::new(credentials::Backend::local(), "telemetry-test")
                .credsd_socket(&socket)
                .route(credentials::RouteSpec::signed_aws(
                    pattern,
                    credentials::Locator::parse_uri("credsd://telemetry").expect("a locator"),
                ))
                .require_every_route(),
        )
        .expect("the vault opens");
        assert!(
            opened.phantoms().is_empty(),
            "a signed route mints no phantom"
        );
        let target = Target::new(
            TargetKind::Otlp,
            format!("http://{host}:{}", address.port()),
        )
        .accepting(vec![Payload::Logs])
        .with_header("x-aws-log-group", "/strands-box/test")
        .with_header("x-aws-log-stream", "box")
        .with_vault(std::sync::Arc::new(opened.into_vault()));
        let exporter = TargetExporter::open_with(
            &target,
            std::sync::Arc::default(),
            reqwest::Client::builder().resolve(host, address),
        )
        .expect("open");

        exporter
            .relay_trace(&empty_spans())
            .await
            .expect("traces are not accepted, so skipped");
        exporter.relay_logs(&empty_logs()).await.expect("delivered");
        let (head, _) = received.recv().await.expect("one request");
        assert!(request_line(&head).starts_with("POST /v1/logs "), "{head}");
        let authorization = header(&head, "authorization").expect("signed");
        assert!(
            authorization.starts_with("AWS4-HMAC-SHA256 Credential=ASIATELEMETRYTEST/"),
            "{authorization}"
        );
        assert!(
            authorization.contains("/us-west-2/logs/aws4_request"),
            "{authorization}"
        );
        let signed = authorization
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .expect("a signed-header list");
        for name in [
            "content-type",
            "host",
            "x-aws-log-group",
            "x-aws-log-stream",
        ] {
            assert!(
                signed.split(';').any(|signed| signed == name),
                "{name} in {signed}"
            );
        }
        assert_eq!(
            header(&head, "x-amz-security-token"),
            Some("telemetry-session-token")
        );
        assert!(header(&head, "x-amz-date").is_some(), "{head}");
        assert!(
            !head.contains("telemetry-secret-access-key"),
            "the secret key never crosses: {head}"
        );
        assert!(
            received.try_recv().is_err(),
            "the unaccepted trace batch was not sent"
        );
    }

    /// **An X-Ray target is signed for `xray`**, which is where CloudWatch takes OTLP spans.
    #[tokio::test]
    async fn an_xray_target_is_signed_for_xray() {
        let (address, mut received) = stand_in().await;
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = stand_in_credsd(&directory);
        let host = "xray.us-west-2.amazonaws.com";
        let pattern = credentials::DestinationPattern::parse(&format!("{host}:{}", address.port()))
            .expect("a pattern");
        let opened = credentials::Vault::open(
            credentials::VaultConfig::new(credentials::Backend::local(), "telemetry-test")
                .credsd_socket(&socket)
                .route(credentials::RouteSpec::signed_aws(
                    pattern,
                    credentials::Locator::parse_uri("credsd://telemetry").expect("a locator"),
                )),
        )
        .expect("the vault opens");
        let target = Target::new(
            TargetKind::Otlp,
            format!("http://{host}:{}", address.port()),
        )
        .accepting(vec![Payload::Traces])
        .with_vault(std::sync::Arc::new(opened.into_vault()));
        let exporter = TargetExporter::open_with(
            &target,
            std::sync::Arc::default(),
            reqwest::Client::builder().resolve(host, address),
        )
        .expect("open");

        exporter
            .relay_trace(&empty_spans())
            .await
            .expect("delivered");
        let (head, _) = received.recv().await.expect("one request");
        assert!(
            request_line(&head).starts_with("POST /v1/traces "),
            "{head}"
        );
        let authorization = header(&head, "authorization").expect("signed");
        assert!(
            authorization.contains("/us-west-2/xray/aws4_request"),
            "{authorization}"
        );
    }

    /// The exporter never prints the credential it carries.
    #[test]
    fn an_exporters_debug_output_holds_no_secret() {
        use crate::config::{TargetKind, TargetSecret};

        let target = Target::new(TargetKind::Otlp, "http://127.0.0.1:4318")
            .with_secret(TargetSecret::new("x-api-key", "vendor-key-abc123"));
        let exporter = TargetExporter::open(
            &target,
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        )
        .expect("open");

        let printed = format!("{exporter:?}");
        assert!(
            !printed.contains("vendor-key-abc123"),
            "the credential reached a Debug line: {printed}"
        );
        assert!(
            printed.contains("x-api-key"),
            "the header name is not secret"
        );
    }
}
