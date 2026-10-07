//! The loopback port the agent's own instrumentation exports to.
//!
//! | Route | Signal | What arrives |
//! |---|---|---|
//! | `/v1/traces` | `agent_trace` | the agent's own spans |
//! | `/v1/logs` | `agent_logs` | the agent's own log records |
//! | `/v1/metrics` | `agent_metrics` | the agent's own metrics |
//!
//! `axum` owns the framing, the body cap and the answer. This module owns the strip and the stamp.

use std::sync::Arc;

use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value};
use opentelemetry_proto::tonic::resource::v1::Resource;
use tokio::sync::Semaphore;

use crate::error::{Result, TelemetryError};
use crate::export::TargetExporter;

/// The most a single request body may carry.
const BODY_LIMIT: usize = 4 * 1024 * 1024;

/// The most posted traces decoded at once.
const RELAY_CAPACITY: usize = 1;

/// The most resource entries one request may carry, whichever signal it names.
const RESOURCE_LIMIT: usize = 1024;

/// The longest one request may take, so a dribbled body cannot hold a task open.
const REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// The attribute namespace the box reserves, stripped from every agent payload.
///
/// `strands.box.` and not all of `strands.`: the Strands Agents SDK owns its own names under
/// `strands.`, and a wider reserve would delete them and still answer `200`.
const RESERVED_PREFIX: &str = "strands.box.";

/// The scope namespace the box reserves.
const RESERVED_SCOPE: &str = "strands-box.";

/// What an agent-claimed scope is renamed to.
const RENAMED_SCOPE: &str = "agent-claimed:";

/// The route the agent's spans arrive on.
const TRACES: &str = "/v1/traces";

/// The route the agent's log records arrive on.
const LOGS: &str = "/v1/logs";

/// The route the agent's metrics arrive on.
const METRICS: &str = "/v1/metrics";

/// The targets that asked for each of the agent's three signals.
#[derive(Default)]
pub(crate) struct Relays {
    pub(crate) traces: Vec<Arc<TargetExporter>>,
    pub(crate) logs: Vec<Arc<TargetExporter>>,
    pub(crate) metrics: Vec<Arc<TargetExporter>>,
}

/// What a handler needs: the targets that asked for a signal, and the box to stamp it with.
struct Inbound {
    box_name: String,
    run_id: String,
    relays: Relays,
    admitted: Semaphore,
    dropped: Arc<AtomicU64>,
}

/// A bound loopback listener, and the port the kernel gave it.
///
/// Bound with the standard library, so `Collector::start` stays synchronous.
pub(crate) struct Receiver {
    listener: std::net::TcpListener,
    port: u16,
}

impl Receiver {
    /// Bind a loopback port, or refuse.
    pub(crate) fn bind() -> Result<Self> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|source| {
            TelemetryError::Config {
                reason: format!("the telemetry port could not be bound: {source}"),
            }
        })?;
        let port = listener
            .local_addr()
            .map_err(|source| TelemetryError::Config {
                reason: format!("the telemetry port could not be read back: {source}"),
            })?
            .port();
        listener
            .set_nonblocking(true)
            .map_err(|source| TelemetryError::Config {
                reason: format!("the telemetry port could not be made non-blocking: {source}"),
            })?;
        Ok(Self { listener, port })
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Serve every connection, relaying each decoded payload to the targets that asked for it.
    ///
    /// Every route but the three answers `404`.
    pub(crate) async fn serve_forever(
        self,
        box_name: String,
        run_id: String,
        relays: Relays,
        dropped: Arc<AtomicU64>,
    ) {
        let Ok(listener) = tokio::net::TcpListener::from_std(self.listener) else {
            return;
        };
        let router = Router::new()
            .route(TRACES, post(accept_trace))
            .route(LOGS, post(accept_logs))
            .route(METRICS, post(accept_metrics))
            .layer(DefaultBodyLimit::max(BODY_LIMIT))
            .layer(tower_http::timeout::TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                REQUEST_DEADLINE,
            ))
            .with_state(Arc::new(Inbound {
                box_name,
                run_id,
                relays,
                admitted: Semaphore::new(RELAY_CAPACITY),
                dropped,
            }));
        let _ = axum::serve(listener, router).await;
    }
}

/// One decoded body, or `None` when the bytes are not the payload the route names.
///
/// The `content-type` header selects the encoding, as the OTLP specification states.
fn decoded<T>(headers: &HeaderMap, body: &Bytes) -> Option<T>
where
    T: prost::Message + Default + serde::de::DeserializeOwned,
{
    let json = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));

    if json {
        serde_json::from_slice(body.as_ref()).ok()
    } else {
        T::decode(body.as_ref()).ok()
    }
}

/// Whether one payload names more resource entries than the stamp may amplify.
///
/// The bound is what keeps the stamp's memory cost bounded, so every route applies it.
fn beyond_the_fan_out_bound(inbound: &Inbound, resources: usize) -> bool {
    let beyond = resources > RESOURCE_LIMIT;
    if beyond {
        inbound.dropped.fetch_add(1, Ordering::Relaxed);
    }
    beyond
}

/// The answer every handler returns, so a client always reads one shape.
fn answer(status: StatusCode) -> (StatusCode, [(&'static str, &'static str); 1], &'static str) {
    (status, [("content-type", "application/json")], "{}")
}

/// Decode one posted trace, strip what it may not claim, and relay it inline.
async fn accept_trace(
    State(inbound): State<Arc<Inbound>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl axum::response::IntoResponse {
    // Taken before the decode, because the decode is where the cost is. `try_acquire`, never
    // `acquire`: a queue the agent could wait in is a queue it could measure.
    let Ok(_permit) = inbound.admitted.try_acquire() else {
        inbound.dropped.fetch_add(1, Ordering::Relaxed);
        return answer(StatusCode::OK);
    };

    let Some(mut trace) = decoded::<ExportTraceServiceRequest>(&headers, &body) else {
        return answer(StatusCode::BAD_REQUEST);
    };
    if beyond_the_fan_out_bound(&inbound, trace.resource_spans.len()) {
        return answer(StatusCode::PAYLOAD_TOO_LARGE);
    }

    for resource_spans in &mut trace.resource_spans {
        for scope_spans in &mut resource_spans.scope_spans {
            strip_scope(&mut scope_spans.scope);
            for span in &mut scope_spans.spans {
                strip(&mut span.attributes);
                for event in &mut span.events {
                    strip(&mut event.attributes);
                }
                for link in &mut span.links {
                    strip(&mut link.attributes);
                }
            }
        }
        strip_and_stamp_resource(
            &mut resource_spans.resource,
            &inbound.box_name,
            &inbound.run_id,
        );
    }

    for relay in &inbound.relays.traces {
        let _ = relay.relay_trace(&trace).await;
    }
    answer(StatusCode::OK)
}

/// Decode one posted log batch, strip what it may not claim, and relay it inline.
async fn accept_logs(
    State(inbound): State<Arc<Inbound>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl axum::response::IntoResponse {
    let Ok(_permit) = inbound.admitted.try_acquire() else {
        inbound.dropped.fetch_add(1, Ordering::Relaxed);
        return answer(StatusCode::OK);
    };

    let Some(mut logs) = decoded::<ExportLogsServiceRequest>(&headers, &body) else {
        return answer(StatusCode::BAD_REQUEST);
    };
    if beyond_the_fan_out_bound(&inbound, logs.resource_logs.len()) {
        return answer(StatusCode::PAYLOAD_TOO_LARGE);
    }

    for resource_logs in &mut logs.resource_logs {
        for scope_logs in &mut resource_logs.scope_logs {
            strip_scope(&mut scope_logs.scope);
            for record in &mut scope_logs.log_records {
                strip(&mut record.attributes);
            }
        }
        strip_and_stamp_resource(
            &mut resource_logs.resource,
            &inbound.box_name,
            &inbound.run_id,
        );
    }

    for relay in &inbound.relays.logs {
        let _ = relay.relay_logs(&logs).await;
    }
    answer(StatusCode::OK)
}

/// Decode one posted metric batch, strip what it may not claim, and relay it inline.
async fn accept_metrics(
    State(inbound): State<Arc<Inbound>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl axum::response::IntoResponse {
    let Ok(_permit) = inbound.admitted.try_acquire() else {
        inbound.dropped.fetch_add(1, Ordering::Relaxed);
        return answer(StatusCode::OK);
    };

    let Some(mut metrics) = decoded::<ExportMetricsServiceRequest>(&headers, &body) else {
        return answer(StatusCode::BAD_REQUEST);
    };
    if beyond_the_fan_out_bound(&inbound, metrics.resource_metrics.len()) {
        return answer(StatusCode::PAYLOAD_TOO_LARGE);
    }

    for resource_metrics in &mut metrics.resource_metrics {
        for scope_metrics in &mut resource_metrics.scope_metrics {
            strip_scope(&mut scope_metrics.scope);
            for metric in &mut scope_metrics.metrics {
                strip_metric(metric);
            }
        }
        strip_and_stamp_resource(
            &mut resource_metrics.resource,
            &inbound.box_name,
            &inbound.run_id,
        );
    }

    for relay in &inbound.relays.metrics {
        let _ = relay.relay_metrics(&metrics).await;
    }
    answer(StatusCode::OK)
}

fn strip(attributes: &mut Vec<KeyValue>) {
    attributes.retain(|attribute| !attribute.key.starts_with(RESERVED_PREFIX));
}

/// Strip a scope's attributes and rename it when it claims the box's namespace.
fn strip_scope(scope: &mut Option<InstrumentationScope>) {
    let Some(scope) = scope else { return };
    if scope.name.starts_with(RESERVED_SCOPE) {
        scope.name = format!("{RENAMED_SCOPE}{}", scope.name);
    }
    strip(&mut scope.attributes);
}

/// Strip every reserved attribute a metric carries, at every level the schema allows one.
///
/// An exhaustive `match` on the data variants, so a seventh variant is a compile error rather than
/// an unstripped level.
fn strip_metric(metric: &mut opentelemetry_proto::tonic::metrics::v1::Metric) {
    use opentelemetry_proto::tonic::metrics::v1::metric::Data;

    strip(&mut metric.metadata);
    match &mut metric.data {
        Some(Data::Gauge(gauge)) => {
            for point in &mut gauge.data_points {
                strip(&mut point.attributes);
                strip_exemplars(&mut point.exemplars);
            }
        }
        Some(Data::Sum(sum)) => {
            for point in &mut sum.data_points {
                strip(&mut point.attributes);
                strip_exemplars(&mut point.exemplars);
            }
        }
        Some(Data::Histogram(histogram)) => {
            for point in &mut histogram.data_points {
                strip(&mut point.attributes);
                strip_exemplars(&mut point.exemplars);
            }
        }
        Some(Data::ExponentialHistogram(histogram)) => {
            for point in &mut histogram.data_points {
                strip(&mut point.attributes);
                strip_exemplars(&mut point.exemplars);
            }
        }
        Some(Data::Summary(summary)) => {
            for point in &mut summary.data_points {
                strip(&mut point.attributes);
            }
        }
        None => {}
    }
}

fn strip_exemplars(exemplars: &mut [opentelemetry_proto::tonic::metrics::v1::Exemplar]) {
    for exemplar in exemplars {
        strip(&mut exemplar.filtered_attributes);
    }
}

/// Strip one resource, then stamp it as the agent's, naming the box that received it.
///
/// **One function, because the order is load-bearing**: the stamp is itself in the reserved
/// namespace, so a strip after it would remove the box's own provenance. A route that stamped
/// without stripping let `strands.box.name` survive with the agent's own value, which one of the
/// three forgery tests below caught.
fn strip_and_stamp_resource(resource: &mut Option<Resource>, box_name: &str, run_id: &str) {
    let resource = resource.get_or_insert_with(Default::default);
    strip(&mut resource.attributes);
    resource.attributes.push(text_attribute(
        crate::export::SOURCE_ATTRIBUTE,
        crate::export::SOURCE_AGENT,
    ));
    resource
        .attributes
        .push(text_attribute(crate::export::BOX_ATTRIBUTE, box_name));
    resource
        .attributes
        .push(text_attribute(crate::export::RUN_ATTRIBUTE, run_id));
}

fn text_attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message as _;

    /// A reserved key the agent claims, whose value also claims the box's own provenance.
    fn claimed(key: &str) -> KeyValue {
        text_attribute(key, crate::export::SOURCE_BOX)
    }

    /// An unreserved key the agent owns, which must survive untouched.
    ///
    /// Its value is deliberately NOT the word `box`, so an assertion that no surviving value says
    /// `box` cannot pass on this attribute.
    fn agents_own(key: &str) -> KeyValue {
        text_attribute(key, "the agent's own value")
    }

    /// A trace posted as protobuf is accepted and delivered.
    #[tokio::test]
    async fn a_posted_trace_is_delivered() {
        let (port, _directory, path) = live().await;
        let body = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans::default()],
        }
        .encode_to_vec();

        let answered = post_to(port, TRACES, "application/x-protobuf", body).await;
        assert_eq!(answered, 200, "a well-formed trace is accepted");
        // Written before the answer, because the relay is inline.
        let written = std::fs::read_to_string(&path).expect("the relayed span");
        assert!(
            written.contains(crate::export::SOURCE_AGENT),
            "the relayed span carries its provenance: {written}"
        );
    }

    /// **A log the agent posted is accepted and stamped as the agent's.**
    #[tokio::test]
    async fn a_posted_log_is_delivered() {
        use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};

        let (port, _directory, path) = live().await;
        let body = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord::default()],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec();

        let answered = post_to(port, LOGS, "application/x-protobuf", body).await;
        assert_eq!(answered, 200, "a well-formed log batch is accepted");
        let written = std::fs::read_to_string(&path).expect("the relayed log");
        assert!(
            written.contains("resourceLogs"),
            "the log batch must reach the target as a log batch: {written}"
        );
        assert!(
            written.contains(crate::export::SOURCE_AGENT),
            "the relayed log carries its provenance: {written}"
        );
    }

    /// **A metric the agent posted is accepted and stamped as the agent's.**
    #[tokio::test]
    async fn a_posted_metric_is_delivered() {
        let (port, _directory, path) = live().await;
        let body = ExportMetricsServiceRequest {
            resource_metrics: vec![gauge_of(Vec::new())],
        }
        .encode_to_vec();

        let answered = post_to(port, METRICS, "application/x-protobuf", body).await;
        assert_eq!(answered, 200, "a well-formed metric batch is accepted");
        let written = std::fs::read_to_string(&path).expect("the relayed metric");
        assert!(
            written.contains("resourceMetrics"),
            "the metric batch must reach the target as a metric batch: {written}"
        );
        assert!(
            written.contains(crate::export::SOURCE_AGENT),
            "the relayed metric carries its provenance: {written}"
        );
    }

    /// A route the receiver does not serve answers `404`.
    #[tokio::test]
    async fn an_unserved_route_is_refused() {
        let (port, _directory, _path) = live().await;
        for route in ["/", "/v1/traces/extra", "/v1/profiles", "/v1/logs/extra"] {
            let answered = post_to(port, route, "application/x-protobuf", Vec::new()).await;
            assert_eq!(answered, 404, "{route} must be refused");
        }
    }

    /// A body that is not a trace is refused rather than kept as an empty one.
    #[tokio::test]
    async fn a_body_that_is_not_a_trace_is_refused() {
        let (port, _directory, _path) = live().await;
        let answered = post_to(port, TRACES, "application/json", b"not json".to_vec()).await;
        assert_eq!(answered, 400);
    }

    /// A body over [`BODY_LIMIT`] is refused by the layer rather than allocated.
    #[tokio::test]
    async fn a_body_over_the_cap_is_refused() {
        let (port, _directory, _path) = live().await;
        let answered = post_to(
            port,
            TRACES,
            "application/x-protobuf",
            vec![0u8; BODY_LIMIT + 1],
        )
        .await;
        assert_eq!(
            answered, 413,
            "the cap is the library's, not a hand-rolled one"
        );
    }

    /// **Every route applies the fan-out bound**, so no signal is a route around the stamp's cost.
    ///
    /// The bound lived in the one trace handler. A second handler that forgot it would take a 4 MiB
    /// body of empty resource entries and amplify it, which is the measured 937 MB case.
    #[tokio::test]
    async fn a_body_naming_too_many_resources_is_refused_on_every_route() {
        use opentelemetry_proto::tonic::logs::v1::ResourceLogs;
        use opentelemetry_proto::tonic::metrics::v1::ResourceMetrics;

        let bodies = [
            (
                TRACES,
                ExportTraceServiceRequest {
                    resource_spans: vec![ResourceSpans::default(); RESOURCE_LIMIT + 1],
                }
                .encode_to_vec(),
            ),
            (
                LOGS,
                ExportLogsServiceRequest {
                    resource_logs: vec![ResourceLogs::default(); RESOURCE_LIMIT + 1],
                }
                .encode_to_vec(),
            ),
            (
                METRICS,
                ExportMetricsServiceRequest {
                    resource_metrics: vec![ResourceMetrics::default(); RESOURCE_LIMIT + 1],
                }
                .encode_to_vec(),
            ),
        ];

        for (route, body) in bodies {
            let (port, _directory, path) = live().await;
            assert!(
                body.len() < BODY_LIMIT,
                "{route}: the byte cap must not be what refuses this"
            );
            let answered = post_to(port, route, "application/x-protobuf", body).await;
            assert_eq!(answered, 413, "{route}: the fan-out bound must refuse it");
            assert!(
                std::fs::read_to_string(&path).is_ok_and(|kept| kept.is_empty()),
                "{route}: a refused payload must reach no target"
            );
        }
    }

    /// One gauge metric holding `attributes` on its single data point and on that point's exemplar.
    fn gauge_of(
        attributes: Vec<KeyValue>,
    ) -> opentelemetry_proto::tonic::metrics::v1::ResourceMetrics {
        use opentelemetry_proto::tonic::metrics::v1::{
            Exemplar, Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, metric::Data,
        };

        ResourceMetrics {
            scope_metrics: vec![ScopeMetrics {
                metrics: vec![Metric {
                    name: "the agent's own counter".to_string(),
                    metadata: attributes.clone(),
                    data: Some(Data::Gauge(Gauge {
                        data_points: vec![NumberDataPoint {
                            attributes: attributes.clone(),
                            exemplars: vec![Exemplar {
                                filtered_attributes: attributes,
                                ..Default::default()
                            }],
                            ..Default::default()
                        }],
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// A live receiver writing to one file target, and that file's path.
    ///
    /// A real exporter rather than a counting closure, because the relay is inline now: the file is
    /// written before the answer, so no test has to poll for it. The one exporter takes all three
    /// of the agent's signals, which is what a target naming no `include` now receives.
    async fn live() -> (u16, tempfile::TempDir, std::path::PathBuf) {
        use crate::config::{Target, TargetKind};

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("agent.jsonl");
        let target = Target::new(TargetKind::File, path.to_string_lossy().to_string());
        let dropped = Arc::new(AtomicU64::new(0));
        let exporter = Arc::new(
            TargetExporter::open(&target, Arc::clone(&dropped)).expect("open the file target"),
        );

        let inbound = Receiver::bind().expect("bind");
        let port = inbound.port();
        tokio::spawn(inbound.serve_forever(
            "probe".to_string(),
            "probe-run".to_string(),
            Relays {
                traces: vec![Arc::clone(&exporter)],
                logs: vec![Arc::clone(&exporter)],
                metrics: vec![exporter],
            },
            dropped,
        ));
        (port, directory, path)
    }

    /// Post one body and answer with the status the receiver replied.
    async fn post_to(port: u16, route: &str, content_type: &str, body: Vec<u8>) -> u16 {
        let client = reqwest::Client::new();
        for _ in 0..50 {
            match client
                .post(format!("http://127.0.0.1:{port}{route}"))
                .header("content-type", content_type)
                .body(body.clone())
                .send()
                .await
            {
                Ok(response) => return response.status().as_u16(),
                // The server may not have accepted yet.
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }
        panic!("the receiver never answered");
    }

    /// **An agent cannot claim the box's namespace at any level a SPAN carries.**
    ///
    /// The stamp once sat on the resource only, and a decision record carries its verdict on the
    /// record itself — so a payload claiming `strands.box.source` deeper down read as a permit.
    ///
    /// Posted through the real route rather than calling a strip function, because the walk now
    /// lives inside the handler and each of the three routes owns its own.
    #[tokio::test]
    async fn every_reserved_attribute_is_stripped_at_every_level_a_span_carries() {
        let (port, _directory, path) = live().await;
        let body = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![claimed("strands.box.name"), agents_own("service.name")],
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        name: "strands-box.policy".to_string(),
                        attributes: vec![claimed("strands.box.policy.verdict")],
                        ..Default::default()
                    }),
                    spans: vec![Span {
                        name: "the agent's own span".to_string(),
                        attributes: vec![claimed("strands.box.policy.verdict")],
                        events: vec![Event {
                            attributes: vec![claimed("strands.box.policy.rule")],
                            ..Default::default()
                        }],
                        links: vec![Link {
                            attributes: vec![claimed("strands.box.policy.principal")],
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec();

        assert_eq!(
            post_to(port, TRACES, "application/x-protobuf", body).await,
            200
        );
        let relayed = std::fs::read_to_string(&path).expect("the relayed span");
        assert_no_forgery_survived(&relayed);
        assert!(
            relayed.contains("agent-claimed:strands-box.policy"),
            "a scope claiming the box's namespace must be renamed: {relayed}"
        );
    }

    /// **An agent cannot claim the box's namespace at any level a LOG RECORD carries.**
    ///
    /// The sharper of the two new routes: the box's own decisions ARE log records, so an
    /// unstripped agent log would sit in the same `resourceLogs` array as a verdict.
    #[tokio::test]
    async fn every_reserved_attribute_is_stripped_at_every_level_a_log_carries() {
        use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};

        let (port, _directory, path) = live().await;
        let body = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![claimed("strands.box.name"), agents_own("service.name")],
                    ..Default::default()
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        name: "strands-box.policy".to_string(),
                        attributes: vec![claimed("strands.box.policy.verdict")],
                        ..Default::default()
                    }),
                    log_records: vec![LogRecord {
                        attributes: vec![
                            claimed("strands.box.policy.verdict"),
                            claimed("strands.box.policy.rule"),
                            claimed("strands.box.source"),
                        ],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec();

        assert_eq!(
            post_to(port, LOGS, "application/x-protobuf", body).await,
            200
        );
        let relayed = std::fs::read_to_string(&path).expect("the relayed log");
        assert_no_forgery_survived(&relayed);
        assert!(
            relayed.contains("agent-claimed:strands-box.policy"),
            "a scope claiming the box's namespace must be renamed: {relayed}"
        );
    }

    /// **An agent cannot claim the box's namespace at any level a METRIC carries.**
    ///
    /// Three levels below the resource: the metric's own metadata, each data point, and each
    /// exemplar a data point carries.
    #[tokio::test]
    async fn every_reserved_attribute_is_stripped_at_every_level_a_metric_carries() {
        let (port, _directory, path) = live().await;
        let mut resource_metrics = gauge_of(vec![
            claimed("strands.box.policy.verdict"),
            agents_own("service.name"),
        ]);
        resource_metrics.resource = Some(Resource {
            attributes: vec![claimed("strands.box.name"), agents_own("service.name")],
            ..Default::default()
        });
        let body = ExportMetricsServiceRequest {
            resource_metrics: vec![resource_metrics],
        }
        .encode_to_vec();

        assert_eq!(
            post_to(port, METRICS, "application/x-protobuf", body).await,
            200
        );
        let relayed = std::fs::read_to_string(&path).expect("the relayed metric");
        assert_no_forgery_survived(&relayed);
    }

    /// What every one of the three routes must leave behind: no claimed attribute, one honest
    /// stamp, and the agent's own unreserved attributes untouched.
    fn assert_no_forgery_survived(relayed: &str) {
        assert!(
            !relayed.contains("strands.box.policy."),
            "an agent-claimed policy attribute survived: {relayed}"
        );
        assert!(
            relayed.contains(r#""key":"strands.box.name""#)
                && relayed.contains(r#""stringValue":"probe""#),
            "the receiver must name the box that received the payload: {relayed}"
        );
        // The fixture also claims `strands.box.source` with the value `box`, so counting the
        // stamps is what proves the strip ran before it.
        assert_eq!(
            relayed
                .matches(&format!(r#""key":"{}""#, crate::export::SOURCE_ATTRIBUTE))
                .count(),
            1,
            "the payload must carry exactly one provenance stamp: {relayed}"
        );
        assert!(
            !relayed.contains(&format!(r#""stringValue":"{}""#, crate::export::SOURCE_BOX)),
            "no value in an agent payload may say `box`: {relayed}"
        );
        assert!(
            relayed.contains(crate::export::SOURCE_AGENT),
            "the one stamp must say `agent`: {relayed}"
        );
        assert!(
            relayed.contains("service.name"),
            "an unreserved attribute must survive: {relayed}"
        );
    }

    /// **The reserve is `strands.box.` and not all of `strands.`**, so the Strands Agents SDK keeps
    /// its own two span attributes.
    ///
    /// The product and the namespace share a word. A reserve of `strands.` deletes
    /// `strands.cancellation.type` and `strands.tool.backgrounded` and still answers `200`, so an
    /// operator loses two diagnostics in silence. Walked on **all three** routes, because serving
    /// `/v1/logs` and `/v1/metrics` gave the wider reserve two more places to delete an SDK name.
    #[tokio::test]
    async fn a_strands_sdk_attribute_outside_the_box_namespace_survives() {
        use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};

        let sdk = || {
            vec![
                agents_own("strands.cancellation.type"),
                agents_own("strands.tool.backgrounded"),
                claimed("strands.box.policy.verdict"),
            ]
        };

        let spans = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: "the agent's own span".to_string(),
                        attributes: sdk(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec();
        let logs = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord {
                        attributes: sdk(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec();
        let metrics = ExportMetricsServiceRequest {
            resource_metrics: vec![gauge_of(sdk())],
        }
        .encode_to_vec();

        for (route, body) in [(TRACES, spans), (LOGS, logs), (METRICS, metrics)] {
            let (port, _directory, path) = live().await;
            assert_eq!(
                post_to(port, route, "application/x-protobuf", body).await,
                200
            );
            let relayed = std::fs::read_to_string(&path).expect("the relayed payload");
            for kept in ["strands.cancellation.type", "strands.tool.backgrounded"] {
                assert!(
                    relayed.contains(kept),
                    "{route}: {kept} is the SDK's own key and must survive: {relayed}"
                );
            }
            assert!(
                !relayed.contains("strands.box.policy.verdict"),
                "{route}: a claimed box key must still be stripped: {relayed}"
            );
        }
    }
}
