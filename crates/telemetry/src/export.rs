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

use crate::config::{Target, TargetKind, TargetSecret};
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
    },
}

/// One declared target, as the SDK's exporter.
#[derive(Debug)]
pub(crate) struct TargetExporter {
    wire: Wire,
    /// Set once when the provider is built.
    resource: std::sync::OnceLock<ResourceAttributesWithSchema>,
    /// Bumped for every batch a target refused, so a failing endpoint is not silent.
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl TargetExporter {
    /// Open the exporter `target` names, refusing what cannot work.
    pub(crate) fn open(
        target: &Target,
        dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<Self> {
        let wire = match target.kind() {
            TargetKind::File => {
                if let Some(file) = target.file() {
                    let file = file.try_clone().map_err(|source| TelemetryError::Config {
                        reason: format!("{} could not be cloned: {source}", target.destination()),
                    })?;
                    return Ok(Self {
                        wire: Wire::File(Mutex::new(tokio::fs::File::from_std(file))),
                        resource: std::sync::OnceLock::new(),
                        dropped,
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
                base: crate::config::dialed(target.destination()),
                client: reqwest::Client::builder()
                    .timeout(REQUEST_DEADLINE)
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .build()
                    .map_err(|source| TelemetryError::Config {
                        reason: format!("the OTLP client could not be built: {source}"),
                    })?,
                secret: target.secret().cloned(),
            },
        };
        Ok(Self {
            wire,
            resource: std::sync::OnceLock::new(),
            dropped,
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
        let traces = box_spans(&request);
        if traces.resource_spans.is_empty() {
            return self.deliver("/v1/logs", &request).await;
        }
        let (logs, spans) = tokio::join!(
            self.deliver("/v1/logs", &request),
            self.deliver("/v1/traces", &traces)
        );
        logs.and(spans)
    }

    /// Relay one span batch the agent already encoded.
    pub(crate) async fn relay_trace(&self, request: &ExportTraceServiceRequest) -> OTelSdkResult {
        self.deliver("/v1/traces", request).await
    }

    /// Relay one log batch the agent already encoded.
    ///
    /// Separate from [`Self::export_logs`], which encodes the box's own records and derives their
    /// spans. An agent's batch is relayed unchanged, so no `box_spans` pass runs over it.
    pub(crate) async fn relay_logs(&self, request: &ExportLogsServiceRequest) -> OTelSdkResult {
        self.deliver("/v1/logs", request).await
    }

    /// Relay one metric batch the agent already encoded.
    pub(crate) async fn relay_metrics(
        &self,
        request: &ExportMetricsServiceRequest,
    ) -> OTelSdkResult {
        self.deliver("/v1/metrics", request).await
    }

    /// Send one batch, counting it when it does not go.
    async fn deliver<T>(&self, route: &str, request: &T) -> OTelSdkResult
    where
        T: serde::Serialize + prost::Message,
    {
        let outcome = self.attempt(route, request).await;
        if outcome.is_err() {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            } => {
                let url = format!("{}{route}", base.trim_end_matches('/'));
                let mut sending = client
                    .post(&url)
                    .header("content-type", "application/x-protobuf")
                    .body(request.encode_to_vec());
                if let Some(secret) = secret {
                    sending = sending.header(secret.header(), secret.value());
                }
                let response = sending.send().await.map_err(|source| {
                    OTelSdkError::InternalFailure(format!("{url} did not answer: {source}"))
                })?;
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(OTelSdkError::InternalFailure(format!(
                        "{url} answered {}",
                        response.status()
                    )))
                }
            }
        }
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
    use tokio::io::AsyncReadExt as _;

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

    #[tokio::test]
    async fn a_trailing_slash_keeps_each_otlp_route_at_the_base_path() {
        for route in ["/v1/logs", "/v1/traces", "/v1/metrics"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let received = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.unwrap());
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                String::from_utf8(head).unwrap()
            });
            let target = Target::new(TargetKind::Otlp, format!("http://{address}/collector/"));
            let exporter = TargetExporter::open(&target, std::sync::Arc::default()).unwrap();
            exporter
                .deliver(route, &ExportTraceServiceRequest::default())
                .await
                .unwrap();
            let head = received.await.unwrap();
            assert_eq!(
                head.lines().next(),
                Some(format!("POST /collector{route} HTTP/1.1").as_str())
            );
        }
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
