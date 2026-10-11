//! One provider, one lane per target, and the count of what did not fit.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use opentelemetry::InstrumentationScope;
use opentelemetry::logs::{LogRecord as _, Logger as _, LoggerProvider as _};
use opentelemetry::trace::{SpanId, TraceFlags, TraceId};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::log_processor_with_async_runtime::BatchLogProcessor;
use opentelemetry_sdk::logs::{LogProcessor, SdkLogRecord, SdkLogger, SdkLoggerProvider};
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{IdGenerator as _, RandomIdGenerator};

use crate::config::TelemetryConfig;
use crate::error::Result;
use crate::export::{BOX_ATTRIBUTE, SOURCE_ATTRIBUTE, SOURCE_BOX, TargetExporter};
use crate::receive::Receiver;
use crate::record::{ControlRecord, DecisionRecord, RefusalRecord, Signal};

/// The scope every decision record carries.
pub(crate) const SCOPE: &str = "strands-box.policy";

/// The scope every control-plane record carries, so a reader filters one plane from the other.
pub(crate) const CONTROL_SCOPE: &str = "strands-box.control";

/// The scope every kernel-refusal record carries: containment's, not policy's.
pub(crate) const CONTAINMENT_SCOPE: &str = "strands-box.containment";

/// The service every record names.
const SERVICE: &str = "strands-box";

/// The longest one lane's flush may take.
const EXPORT_DEADLINE: Duration = Duration::from_secs(5);

/// One request must end inside one lane's flush, or a flush cannot tell delivery from loss.
const _: () = assert!(
    crate::export::REQUEST_DEADLINE.as_millis() < EXPORT_DEADLINE.as_millis(),
    "REQUEST_DEADLINE must be shorter than EXPORT_DEADLINE"
);

/// The longest the whole provider shutdown may take.
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);

/// One lane's flush must end inside the drain, or the drain cuts a flush that would have finished.
const _: () = assert!(
    EXPORT_DEADLINE.as_millis() < DRAIN_DEADLINE.as_millis(),
    "EXPORT_DEADLINE must be shorter than DRAIN_DEADLINE"
);

/// Shut `logs` down on a thread no runtime joins, and answer what the outcome arrives on.
///
/// A `std::thread` and not `spawn_blocking`, because a tokio runtime joins its blocking tasks while
/// it shuts down, and this shutdown waits on a reply from the batch worker — an ordinary runtime
/// task that can no longer be scheduled by then.
fn shut_down_off_runtime(
    logs: SdkLoggerProvider,
) -> Option<std::sync::mpsc::Receiver<OTelSdkResult>> {
    let (ended, waiting) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("strands-box-telemetry-drain".to_string())
        .spawn(move || {
            let _ = ended.send(logs.shutdown());
        })
        .ok()
        .map(|_| waiting)
}

/// Shut `logs` down and stop waiting after `deadline`.
///
/// The bound lives here because the SDK has none:
/// `BatchLogProcessor::shutdown_with_timeout` names its argument `_timeout`, never reads it, and
/// blocks on a reply from the batch worker.
///
/// **Only a caller that is not holding a runtime thread may wait.** The batch worker needs that
/// thread to answer, so waiting on it is what turns this bound into the deadline every time.
fn shut_down_bounded(logs: SdkLoggerProvider, deadline: Duration) -> bool {
    shut_down_off_runtime(logs)
        .is_some_and(|waiting| matches!(waiting.recv_timeout(deadline), Ok(Ok(()))))
}

/// One exporter, shared between the SDK lane and the agent-trace relay.
#[derive(Debug)]
struct SharedTarget(Arc<TargetExporter>);

impl opentelemetry_sdk::logs::LogExporter for SharedTarget {
    async fn export(&self, batch: opentelemetry_sdk::logs::LogBatch<'_>) -> OTelSdkResult {
        self.0.export_logs(batch).await
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.0.set_resource_once(resource);
    }
}

/// One declared target's lane: the signals it receives, and what it loses.
#[derive(Debug)]
struct TargetLane {
    accepts: [bool; Signal::SLOTS],
    inner: BatchLogProcessor<Tokio>,
}

impl LogProcessor for TargetLane {
    fn emit(&self, data: &mut SdkLogRecord, instrumentation: &InstrumentationScope) {
        let Some(signal) = Signal::of_severity(data.severity_number()) else {
            return;
        };
        if !self.accepts[signal.slot()] {
            return;
        }
        self.inner.emit(data, instrumentation);
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    /// Forwarded, because the trait's default is a no-op.
    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

/// The live lane. Hold it for as long as the box runs.
pub struct Collector {
    logs: SdkLoggerProvider,
    logger: SdkLogger,
    /// The control-plane scope's own logger, so a record names which plane it came from.
    control_logger: SdkLogger,
    /// The containment scope's own logger, for kernel refusals.
    containment_logger: SdkLogger,
    dropped: Arc<AtomicU64>,
    /// The union of every lane's signals, so a record nothing wants costs one load.
    accepts: [bool; Signal::SLOTS],
    port: u16,

    /// The one trace every control-plane operation of this run joins.
    control_trace: TraceId,
    /// The span the run's first control-plane operation takes, and every later one parents under.
    control_root: SpanId,
    /// Whether [`Self::control_root`] is spent.
    control_root_spent: std::sync::atomic::AtomicBool,

    /// The receiver, aborted when this value drops.
    receiver: tokio::task::AbortHandle,

    /// Set by whichever of `drained` and `drop` runs first, so the second does no work.
    shut: std::sync::atomic::AtomicBool,
}

impl Drop for Collector {
    /// Starts the provider shutdown on a thread no runtime joins, and waits for nothing.
    ///
    /// `drained` is the call that waits. This one cannot: a dropping `Collector` may hold the very
    /// runtime thread the batch worker needs in order to answer.
    fn drop(&mut self) {
        self.receiver.abort();
        if self.shut.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = shut_down_off_runtime(self.logs.clone());
    }
}

impl Collector {
    pub(crate) fn start(config: TelemetryConfig) -> Result<Self> {
        config.validate()?;
        let box_name = config.box_name().to_string();
        let run_id = RandomIdGenerator::default().new_trace_id().to_string();
        let dropped = Arc::new(AtomicU64::new(0));

        // Bound whatever the signals say, so the agent's exporter always finds a listener.
        let inbound = Receiver::bind()?;
        let port = inbound.port();

        // One exporter per target, shared by both lanes.
        let mut logs = SdkLoggerProvider::builder().with_resource(resource(&box_name, &run_id));
        let mut relays = crate::receive::Relays::default();
        let mut accepts = [false; Signal::SLOTS];
        for target in config.targets() {
            let exporter = Arc::new(TargetExporter::open(target, Arc::clone(&dropped))?);
            let mut lane = [false; Signal::SLOTS];
            // The harness's own log records and metrics reach every target, whatever it names, so
            // no declaration has to ask for what the agent already exports.
            for signal in target
                .signals()
                .iter()
                .copied()
                .chain(Signal::always_received())
            {
                lane[signal.slot()] = true;
                accepts[signal.slot()] = true;
            }
            if lane[Signal::AgentTrace.slot()] {
                relays.traces.push(Arc::clone(&exporter));
            }
            if lane[Signal::AgentLogs.slot()] {
                relays.logs.push(Arc::clone(&exporter));
            }
            if lane[Signal::AgentMetrics.slot()] {
                relays.metrics.push(Arc::clone(&exporter));
            }
            // A target that names only relayed signals gets no log lane, because a worker that can
            // never receive a record is a task with nothing to do.
            if !target.signals().iter().any(|signal| !signal.is_relayed()) {
                continue;
            }
            logs = logs.with_log_processor(TargetLane {
                accepts: lane,
                inner: BatchLogProcessor::builder(SharedTarget(exporter), Tokio)
                    .with_batch_config(
                        opentelemetry_sdk::logs::BatchConfigBuilder::default()
                            .with_max_export_timeout(EXPORT_DEADLINE)
                            .build(),
                    )
                    .build(),
            });
        }
        let logs = logs.build();
        let logger = logs.logger(SCOPE);
        let control_logger = logs.logger(CONTROL_SCOPE);
        let containment_logger = logs.logger(CONTAINMENT_SCOPE);

        // An agent's span arrives already encoded, so it relays rather than going through the SDK.
        let receiving = tokio::spawn(inbound.serve_forever(
            box_name.clone(),
            run_id,
            relays,
            Arc::clone(&dropped),
        ));

        let ids = RandomIdGenerator::default();
        Ok(Self {
            logs,
            logger,
            control_logger,
            containment_logger,
            dropped,
            accepts,
            port,
            control_trace: ids.new_trace_id(),
            control_root: ids.new_span_id(),
            control_root_spent: std::sync::atomic::AtomicBool::new(false),
            receiver: receiving.abort_handle(),
            shut: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// The loopback port the agent's own instrumentation exports to.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Queue one record.
    ///
    /// Never blocks, never awaits, and never fails.
    pub fn record(&self, record: DecisionRecord) {
        let signal = record.signal();
        if !self.accepts[signal.slot()] {
            return;
        }
        let mut emitted = self.logger.create_log_record();
        emitted.set_event_name(crate::record::EVENT_NAME);
        let parent = record.correlation().parent();
        let ids = RandomIdGenerator::default();
        let trace_id = if parent.is_valid() {
            parent.trace_id()
        } else {
            ids.new_trace_id()
        };
        let flags = if parent.is_valid() {
            parent.trace_flags().to_u8() & 2
        } else {
            2
        };
        emitted.set_trace_context(
            trace_id,
            ids.new_span_id(),
            Some(TraceFlags::new(flags | 1)),
        );
        if parent.is_valid() {
            emitted.add_attribute(
                "strands.box.trace.parent_span_id",
                parent.span_id().to_string(),
            );
        }
        for (key, value) in record.correlation().attributes() {
            emitted.add_attribute(key, value);
        }
        // The decision's own time, not the emit time, because a full queue delays the emit.
        emitted.set_timestamp(
            std::time::UNIX_EPOCH
                + Duration::from_nanos(u64::try_from(record.unix_nanos()).unwrap_or(u64::MAX)),
        );
        emitted.set_severity_number(signal.severity());
        emitted.set_severity_text(record.verdict());
        for (key, value) in record.attributes() {
            emitted.add_attribute(key, value);
        }
        self.logger.emit(emitted);
    }

    /// Queue one control-plane operation.
    ///
    /// Never blocks, never awaits, and never fails, on the same terms as [`Self::record`].
    pub fn control(&self, record: ControlRecord) {
        let signal = record.signal();
        if !self.accepts[signal.slot()] {
            return;
        }
        let mut emitted = self.control_logger.create_log_record();
        // One trace holds the run's whole control plane, and the first operation is its root. A
        // control-plane operation has no request to inherit a parent from, so there is nothing else
        // to join: the alternative is one parentless root per operation, which a viewer shows as
        // several unrelated traces for one box life.
        let root = !self
            .control_root_spent
            .swap(true, std::sync::atomic::Ordering::SeqCst);
        let span_id = if root {
            self.control_root
        } else {
            RandomIdGenerator::default().new_span_id()
        };
        emitted.set_trace_context(self.control_trace, span_id, Some(TraceFlags::new(0x3)));
        if !root {
            emitted.add_attribute(
                "strands.box.trace.parent_span_id",
                self.control_root.to_string(),
            );
        }
        // The operation's own time, not the emit time, because a full queue delays the emit.
        emitted.set_timestamp(
            std::time::UNIX_EPOCH
                + Duration::from_nanos(u64::try_from(record.unix_nanos()).unwrap_or(u64::MAX)),
        );
        emitted.set_severity_number(signal.severity());
        emitted.set_severity_text(record.outcome());
        for (key, value) in record.attributes() {
            emitted.add_attribute(key, value);
        }
        self.control_logger.emit(emitted);
    }

    /// Queue one kernel refusal.
    ///
    /// Never blocks, never awaits, and never fails, on the same terms as [`Self::record`]. The
    /// caller has already rate-limited it: a workload chooses how often it is refused.
    pub fn refusal(&self, record: RefusalRecord) {
        let signal = record.signal();
        if !self.accepts[signal.slot()] {
            return;
        }
        let mut emitted = self.containment_logger.create_log_record();
        emitted.set_event_name(crate::record::REFUSAL_EVENT_NAME);
        let ids = RandomIdGenerator::default();
        emitted.set_trace_context(
            ids.new_trace_id(),
            ids.new_span_id(),
            Some(TraceFlags::new(0x3)),
        );
        // The refusal's own time, not the emit time, because a full queue delays the emit.
        emitted.set_timestamp(
            std::time::UNIX_EPOCH
                + Duration::from_nanos(u64::try_from(record.unix_nanos()).unwrap_or(u64::MAX)),
        );
        emitted.set_severity_number(signal.severity());
        emitted.set_severity_text("refused");
        for (key, value) in record.attributes() {
            emitted.add_attribute(key, value);
        }
        self.containment_logger.emit(emitted);
    }

    /// Flush every lane and shut it down, inside [`DRAIN_DEADLINE`]. Call it before teardown.
    pub async fn drained(&self) {
        if self.shut.swap(true, Ordering::SeqCst) {
            return;
        }
        let logs = self.logs.clone();
        // `shutdown` exports what is queued before it stops the exporter, so no separate flush. The
        // blocking task returns at the deadline whatever the batch worker does, so the runtime's own
        // teardown never waits on it.
        let ended =
            tokio::task::spawn_blocking(move || shut_down_bounded(logs, DRAIN_DEADLINE)).await;
        if !matches!(ended, Ok(true)) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// How many batches a target refused, which is not a count of records.
    ///
    /// No consumer outside this crate reads it, so it is not on the facade. Making it a reported
    /// number needs a unit an operator can act on.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// The resource every record from one producer carries.
fn resource(box_name: &str, run_id: &str) -> Resource {
    Resource::builder()
        .with_service_name(SERVICE)
        .with_attribute(opentelemetry::KeyValue::new(
            BOX_ATTRIBUTE,
            box_name.to_string(),
        ))
        .with_attribute(opentelemetry::KeyValue::new(SOURCE_ATTRIBUTE, SOURCE_BOX))
        .with_attribute(opentelemetry::KeyValue::new(
            crate::export::RUN_ATTRIBUTE,
            run_id.to_string(),
        ))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Target, TargetKind};
    use crate::record::ControlOperation;

    #[tokio::test]
    async fn decisions_export_spans_and_matching_logs_with_request_parentage() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("spans.jsonl");
        let collector = Collector::start(file_config(&path)).unwrap();
        let correlation = crate::Correlation::from_headers(
            Some("00-0123456789abcdef0123456789abcdef-0123456789abcdef-03"),
            Some("vendor=example"),
        )
        .mcp(Some("7"));
        for record in [
            DecisionRecord::permit("fs:read", "~/ok", "read-rule"),
            DecisionRecord::deny("fs:write", "~/no", "write-rule", "forbidden"),
        ] {
            collector.record(record.correlated(correlation.clone()));
        }
        collector.drained().await;
        let batches: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let mut spans = Vec::new();
        let mut logs = Vec::new();
        for batch in &batches {
            if let Some(resources) = batch["resourceSpans"].as_array() {
                for resource in resources {
                    for scope in resource["scopeSpans"].as_array().unwrap() {
                        spans.extend(scope["spans"].as_array().unwrap());
                    }
                }
            }
            if let Some(resources) = batch["resourceLogs"].as_array() {
                for resource in resources {
                    for scope in resource["scopeLogs"].as_array().unwrap() {
                        logs.extend(scope["logRecords"].as_array().unwrap());
                    }
                }
            }
        }
        assert_eq!(spans.len(), 2);
        assert_eq!(logs.len(), 2);
        // Presence of the log record's own event name is what marks it an event, so it is a field
        // rather than an attribute, and a span carries its identity in `name` instead.
        for log in &logs {
            assert_eq!(log["eventName"], "strands.box.policy.decision");
            assert!(
                !log["attributes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|attribute| attribute["key"] == "event.name"),
                "the event name is a field, never a second attribute: {log}"
            );
        }
        // The span omits only what one of its own fields already states, and the log record keeps
        // every key.
        for span in &spans {
            let carried = |value: &serde_json::Value, key: &str| {
                value["attributes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|attribute| attribute["key"] == key)
            };
            for key in [
                "strands.box.policy.principal",
                "strands.box.policy.action",
                "strands.box.policy.resource",
                "strands.box.policy.verdict",
                "strands.box.policy.cause",
            ] {
                assert!(
                    carried(span, key),
                    "the span states the whole decision, so it keeps {key}: {span}"
                );
            }
            let paired = logs
                .iter()
                .find(|log| log["spanId"] == span["spanId"])
                .unwrap_or_else(|| panic!("every span has its log record: {span}"));
            // Audit detail the span keeps, because no span field states it. Present only when the
            // decision carried attribution, so the log record is what decides whether to look.
            for key in ["strands.box.policy.determining.ids", "jsonrpc.request.id"] {
                assert_eq!(
                    carried(span, key),
                    carried(paired, key),
                    "{key} is not omitted, so the span and the log record agree: {span}"
                );
            }
            for key in crate::export::SPAN_OMITS {
                assert!(
                    !carried(span, key),
                    "a span field already states {key}, so the span omits it: {span}"
                );
                assert!(
                    carried(paired, key),
                    "the log record has no field for {key}, so it keeps it: {paired}"
                );
            }
        }
        assert_ne!(spans[0]["spanId"], spans[1]["spanId"]);
        for span in spans {
            assert_eq!(span["traceId"], "0123456789abcdef0123456789abcdef");
            assert_eq!(span["parentSpanId"], "0123456789abcdef");
            assert_eq!(
                span["traceState"], "",
                "the caller sent vendor=example and the box records no tracestate: {span}"
            );
            assert_eq!(span["flags"], 0x303);
            assert_ne!(span["spanId"], span["parentSpanId"]);
            assert_eq!(span["startTimeUnixNano"], span["endTimeUnixNano"]);
            assert!(span["status"].is_null() || span["status"]["code"] == 0);
            assert!(logs.iter().any(|log| log["traceId"] == span["traceId"] && log["spanId"] == span["spanId"]));
            let attributes = span["attributes"].as_array().unwrap();
            assert!(
                attributes
                    .iter()
                    .any(|attribute| attribute["key"] == "jsonrpc.request.id"
                        && attribute["value"]["stringValue"] == "7")
            );
            // The removed correlation keys must not return under any spelling.
            for key in [
                "gen_ai.conversation.id",
                "gen_ai.tool.call.id",
                "gen_ai.tool.name",
                "mcp.method.name",
                "strands.box.trace.correlation",
                "strands.box.trace.link_traceparent",
            ] {
                assert!(
                    !attributes.iter().any(|attribute| attribute["key"] == key),
                    "{key} was removed: {span}"
                );
            }
        }
    }

    /// Every span and log record one file target received, in arrival order.
    fn spans_and_logs(path: &std::path::Path) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
        let mut spans = Vec::new();
        let mut logs = Vec::new();
        for line in std::fs::read_to_string(path).unwrap().lines() {
            let batch: serde_json::Value = serde_json::from_str(line).unwrap();
            if let Some(resources) = batch["resourceSpans"].as_array() {
                for resource in resources {
                    for scope in resource["scopeSpans"].as_array().unwrap() {
                        for span in scope["spans"].as_array().unwrap() {
                            spans.push(span.clone());
                        }
                    }
                }
            }
            if let Some(resources) = batch["resourceLogs"].as_array() {
                for resource in resources {
                    for scope in resource["scopeLogs"].as_array().unwrap() {
                        for record in scope["logRecords"].as_array().unwrap() {
                            logs.push(record.clone());
                        }
                    }
                }
            }
        }
        (spans, logs)
    }

    /// One control-plane operation reaches a span beside its log record, under the control scope.
    #[tokio::test]
    async fn a_control_operation_exports_a_span_beside_its_log_record() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.jsonl");
        let collector = Collector::start(file_config(&path)).unwrap();
        collector.control(ControlRecord::completed(
            ControlOperation::BoxStarted,
            "demo",
        ));
        collector.drained().await;

        let (spans, logs) = spans_and_logs(&path);
        assert_eq!(spans.len(), 1, "one operation, one span: {spans:?}");
        assert_eq!(logs.len(), 1, "one operation, one log record: {logs:?}");
        assert_eq!(spans[0]["name"], "control box_started");
        assert_eq!(spans[0]["kind"], 1);
        // The span and its log record are two views of one operation, so they share their identity
        // and their attributes.
        assert_eq!(spans[0]["spanId"], logs[0]["spanId"]);
        assert_eq!(spans[0]["traceId"], logs[0]["traceId"]);
        assert_eq!(spans[0]["attributes"], logs[0]["attributes"]);
        // An instant, not a duration: the span marks when the authority changed.
        assert_eq!(
            spans[0]["startTimeUnixNano"], spans[0]["endTimeUnixNano"],
            "{:?}",
            spans[0]
        );
        assert!(
            spans[0]["status"].is_null() || spans[0]["status"]["code"] == 0,
            "an `ok` outcome reports no failure: {:?}",
            spans[0]
        );
    }

    /// Every control-plane operation of one run joins one trace, and the first is its root.
    #[tokio::test]
    async fn one_trace_holds_the_runs_whole_control_plane() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.jsonl");
        let collector = Collector::start(file_config(&path)).unwrap();
        for operation in [
            ControlOperation::BoxStarted,
            ControlOperation::PolicyInstalled,
            ControlOperation::DiscoveryComplete,
            ControlOperation::BoxStopped,
        ] {
            collector.control(ControlRecord::completed(operation, "demo"));
        }
        collector.drained().await;

        let (spans, _) = spans_and_logs(&path);
        assert_eq!(spans.len(), 4, "{spans:?}");
        let trace = spans[0]["traceId"].clone();
        assert!(trace.is_string() && trace != "", "{spans:?}");
        for span in &spans {
            assert_eq!(span["traceId"], trace, "one trace per run: {span}");
        }
        // The first operation is the root, so the trace has exactly one, and no span points at a
        // parent that was never exported.
        let roots: Vec<_> = spans
            .iter()
            .filter(|span| {
                span["parentSpanId"].is_null() || span["parentSpanId"].as_str() == Some("")
            })
            .collect();
        assert_eq!(roots.len(), 1, "exactly one root: {spans:?}");
        assert_eq!(roots[0]["name"], "control box_started");
        let root_id = roots[0]["spanId"].as_str().unwrap().to_string();
        for span in spans.iter().filter(|span| span["spanId"] != root_id) {
            assert_eq!(
                span["parentSpanId"].as_str(),
                Some(root_id.as_str()),
                "every later operation hangs under the root: {span}"
            );
        }
        let ids: std::collections::BTreeSet<_> = spans
            .iter()
            .map(|span| span["spanId"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids.len(),
            4,
            "each operation has its own span id: {spans:?}"
        );
    }

    /// **No control span claims a remote parent**, because its parent is this run's own root.
    ///
    /// The bits are `has_is_remote_parent | is_remote_parent`. A viewer that reads them draws the
    /// box's own children as if a remote caller had sent them.
    #[tokio::test]
    async fn a_control_child_never_claims_a_remote_parent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.jsonl");
        let collector = Collector::start(file_config(&path)).unwrap();
        for operation in [
            ControlOperation::BoxStarted,
            ControlOperation::PolicyInstalled,
            ControlOperation::DiscoveryComplete,
        ] {
            collector.control(ControlRecord::completed(operation, "demo"));
        }
        collector.drained().await;

        let (spans, _) = spans_and_logs(&path);
        assert_eq!(spans.len(), 3, "{spans:?}");
        let children: Vec<_> = spans
            .iter()
            .filter(|span| {
                span["parentSpanId"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty())
            })
            .collect();
        assert_eq!(children.len(), 2, "two children under the root: {spans:?}");
        for span in &spans {
            let flags = span["flags"].as_u64().unwrap_or_default();
            assert_eq!(
                flags & 0x300,
                0,
                "a control span carries no remote-parent bit: {span}"
            );
        }
    }

    /// A refused operation reports a failure on its span, where a completed one does not.
    #[tokio::test]
    async fn a_refused_operation_reports_a_failed_span() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.jsonl");
        let collector = Collector::start(file_config(&path)).unwrap();
        collector.control(ControlRecord::refused(
            ControlOperation::PolicyRefused,
            "policy.dw",
            "two rules share one id",
        ));
        collector.drained().await;

        let (spans, _) = spans_and_logs(&path);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(spans[0]["name"], "control policy_refused");
        assert_eq!(spans[0]["status"]["code"], 2, "{:?}", spans[0]);
        assert_eq!(
            spans[0]["status"]["message"], "control-plane operation failed",
            "{:?}",
            spans[0]
        );
    }

    /// A target that names only the verdicts receives no control-plane span.
    ///
    /// TWO targets, because `control` returns at the acceptance union before any lane filter runs, so
    /// a single-target test would pass even with the filter removed.
    #[tokio::test]
    async fn a_target_naming_only_verdicts_receives_no_control_span() {
        let directory = tempfile::tempdir().unwrap();
        let verdicts_only = directory.path().join("verdicts.jsonl");
        let everything = directory.path().join("everything.jsonl");
        let collector = Collector::start(
            TelemetryConfig::for_box("demo")
                .with_target(
                    Target::new(
                        TargetKind::File,
                        verdicts_only.to_string_lossy().to_string(),
                    )
                    .receiving(Signal::every_verdict()),
                )
                .with_target(Target::new(
                    TargetKind::File,
                    everything.to_string_lossy().to_string(),
                )),
        )
        .unwrap();
        collector.control(ControlRecord::completed(
            ControlOperation::BoxStarted,
            "demo",
        ));
        collector.drained().await;

        let (refused_spans, refused_logs) = spans_and_logs(&verdicts_only);
        assert!(
            refused_spans.is_empty() && refused_logs.is_empty(),
            "a verdicts-only target receives neither: {refused_spans:?} {refused_logs:?}"
        );
        let (spans, _) = spans_and_logs(&everything);
        assert_eq!(
            spans.len(),
            1,
            "the other target still receives it: {spans:?}"
        );
    }

    /// **The drain returns even when the batch worker can never answer.**
    ///
    /// The SDK discards the timeout it is given, so this is the only bound. The worker here is alive
    /// and unschedulable, which is the state the box reaches when its runtime is already shutting
    /// down, and `shutdown` then waits on a reply that never comes.
    #[test]
    fn the_drain_returns_when_the_batch_worker_cannot_answer() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let guard = runtime.enter();
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("records.jsonl");
        let collector = Collector::start(file_config(&path)).expect("open");
        collector.record(DecisionRecord::deny(
            r#"Box::Action::"fs:read""#,
            "~/x",
            "rule-1",
            "refused",
        ));
        // Nothing ever drives this runtime, so the worker is alive and cannot be scheduled.
        drop(guard);

        let deadline = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let flushed = shut_down_bounded(collector.logs.clone(), deadline);
        let waited = started.elapsed();
        // This drain set no flag on the collector, so `Drop` starts a second shutdown, and the
        // provider's own guard answers it.
        drop(collector);

        assert!(
            !flushed,
            "a worker that cannot answer is not a successful flush"
        );
        assert!(
            waited < deadline * 2,
            "the drain must return at its deadline, and waited {waited:?}"
        );
    }

    /// A drained collector does no second shutdown, which is what its flag is for.
    #[tokio::test]
    async fn a_drained_collector_drops_without_a_second_shutdown() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("records.jsonl");
        let collector = Collector::start(file_config(&path)).expect("open");
        collector.record(DecisionRecord::permit(
            r#"Box::Action::"fs:read""#,
            "~/ok",
            "rule-1",
        ));
        collector.drained().await;

        let started = std::time::Instant::now();
        drop(collector);
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(1),
            "the drop must take the flag's early return, and waited {waited:?}"
        );
        assert!(
            std::fs::read_to_string(&path)
                .expect("the records")
                .contains("rule-1"),
            "the drain still exported what was queued"
        );
    }

    fn logs_of(path: &std::path::Path) -> Vec<(String, serde_json::Value)> {
        let mut logs = Vec::new();
        for line in std::fs::read_to_string(path).unwrap_or_default().lines() {
            let batch: serde_json::Value = serde_json::from_str(line).unwrap();
            for resource in batch["resourceLogs"].as_array().into_iter().flatten() {
                for scope in resource["scopeLogs"].as_array().unwrap() {
                    let name = scope["scope"]["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    for log in scope["logRecords"].as_array().unwrap() {
                        logs.push((name.clone(), log.clone()));
                    }
                }
            }
        }
        logs
    }

    fn a_raw_socket_refusal() -> crate::record::RefusalRecord {
        crate::record::RefusalRecord::seccomp(
            "socket",
            Some("family=AF_PACKET type=SOCK_RAW"),
            7,
            crate::record::Subject::process("/bin/probe", &[], &[], ""),
        )
    }

    /// A kernel refusal reaches a file target as its own event under the containment scope, and
    /// derives no span: it is not a decision and not a control-plane operation.
    #[tokio::test]
    async fn a_refusal_reaches_a_file_target_under_the_containment_scope() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("refusal.jsonl");
        let collector = Collector::start(file_config(&path)).unwrap();
        collector.refusal(a_raw_socket_refusal());
        collector.drained().await;

        let logs = logs_of(&path);
        assert_eq!(logs.len(), 1, "{logs:?}");
        let (scope, log) = &logs[0];
        assert_eq!(scope, "strands-box.containment");
        assert_eq!(log["eventName"], "strands.box.containment.refusal");
        assert_eq!(log["severityText"], "refused");
        let syscall = log["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|pair| pair["key"] == "strands.box.containment.syscall")
            .map(|pair| pair["value"]["stringValue"].clone());
        assert_eq!(syscall, Some(serde_json::json!("socket")));
        let (spans, _) = spans_and_logs(&path);
        assert!(spans.is_empty(), "a refusal derives no span: {spans:?}");
    }

    /// A target that names only denials receives no kernel refusal.
    #[tokio::test]
    async fn a_target_without_kernel_receives_no_refusal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("deny-only.jsonl");
        let config = TelemetryConfig::for_box("demo").with_target(
            Target::new(TargetKind::File, path.to_string_lossy().to_string())
                .receiving(vec![Signal::PolicyDenied]),
        );
        let collector = Collector::start(config).unwrap();
        collector.refusal(a_raw_socket_refusal());
        collector.drained().await;
        assert!(logs_of(&path).is_empty());
    }

    fn file_config(path: &std::path::Path) -> TelemetryConfig {
        TelemetryConfig::for_box("demo").with_target(Target::new(
            TargetKind::File,
            path.to_string_lossy().to_string(),
        ))
    }

    /// An unreachable OTLP destination, so every request waits out its own deadline.
    fn nothing_listening() -> String {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = taken.local_addr().expect("its address").port();
        drop(taken);
        format!("http://127.0.0.1:{port}")
    }

    /// A recorded verdict reaches the file, and the record names its box and its producer.
    #[tokio::test]
    async fn a_recorded_verdict_reaches_the_file() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("records.jsonl");
        let collector = Collector::start(file_config(&path)).expect("open");

        collector.record(DecisionRecord::deny(
            r#"Box::Action::"fs:read""#,
            "~/.ssh/id_rsa",
            "rule-7",
            "a forbid rule matched",
        ));
        collector.drained().await;

        let text = std::fs::read_to_string(&path).expect("the records");
        assert!(text.contains("rule-7"), "{text}");
        assert!(
            text.contains(BOX_ATTRIBUTE),
            "the record names its box: {text}"
        );
        assert!(
            text.contains(SOURCE_BOX),
            "the record names its producer: {text}"
        );
    }

    #[tokio::test]
    async fn an_opened_file_target_survives_a_path_swap() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("records.jsonl");
        std::fs::write(&path, []).expect("empty target");
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("target descriptor");
        let moved = directory.path().join("moved.jsonl");
        std::fs::rename(&path, &moved).expect("move opened target");
        std::fs::write(&path, b"replacement").expect("replacement target");
        let config = TelemetryConfig::for_box("demo")
            .with_target(Target::opened_file(path.to_string_lossy(), file));
        let collector = Collector::start(config).expect("open");

        collector.record(DecisionRecord::deny(
            r#"Box::Action::"fs:read""#,
            "~/.ssh/id_rsa",
            "rule-opened",
            "refused",
        ));
        collector.drained().await;

        assert_eq!(
            std::fs::read(&path).expect("replacement reads"),
            b"replacement"
        );
        assert!(
            std::fs::read_to_string(moved)
                .expect("opened target reads")
                .contains("rule-opened")
        );
    }

    /// A target naming only `refusal` never fills with permits.
    #[tokio::test]
    async fn a_target_naming_only_refusals_receives_no_permit() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("denied.jsonl");
        let collector = Collector::start(
            TelemetryConfig::for_box("demo").with_target(
                Target::new(TargetKind::File, path.to_string_lossy().to_string())
                    .receiving(vec![Signal::PolicyDenied]),
            ),
        )
        .expect("open");

        collector.record(DecisionRecord::permit(
            r#"Box::Action::"fs:read""#,
            "~/ok",
            "rule-1",
        ));
        collector.record(DecisionRecord::deny(
            r#"Box::Action::"fs:read""#,
            "~/no",
            "rule-2",
            "refused",
        ));
        collector.drained().await;

        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(text.contains("rule-2"), "the refusal is kept: {text}");
        assert!(
            !text.contains("rule-1"),
            "a permit must not reach it: {text}"
        );
    }

    /// **The agent's own log records and metrics reach a target that names neither.**
    ///
    /// They are unconditional, so an `include` narrows the verdicts and the spans and never these
    /// two. A target naming one verdict is the case that proves it: its lane holds `policy_denied`
    /// alone, and both relayed signals still register a relay.
    #[tokio::test]
    async fn a_target_naming_only_refusals_still_receives_the_agents_logs_and_metrics() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("denied.jsonl");
        let collector = Collector::start(
            TelemetryConfig::for_box("demo").with_target(
                Target::new(TargetKind::File, path.to_string_lossy().to_string())
                    .receiving(vec![Signal::PolicyDenied]),
            ),
        )
        .expect("open");

        let client = reqwest::Client::new();
        for (route, body) in [
            (
                "/v1/logs",
                r#"{"resourceLogs":[{"scopeLogs":[{"scope":{"name":"my-agent"},
                   "logRecords":[{"body":{"stringValue":"the agent own log line"}}]}]}]}"#,
            ),
            (
                "/v1/metrics",
                r#"{"resourceMetrics":[{"scopeMetrics":[{"scope":{"name":"my-agent"},
                   "metrics":[{"name":"agent.turns","gauge":{"dataPoints":[{"asInt":"1"}]}}]}]}]}"#,
            ),
        ] {
            let answered = client
                .post(format!("http://127.0.0.1:{}{route}", collector.port()))
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .expect("the receiver answers")
                .status()
                .as_u16();
            assert_eq!(answered, 200, "{route}");
        }
        collector.drained().await;

        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            text.contains("the agent own log line"),
            "the agent's log record reaches a deny-only target: {text}"
        );
        assert!(
            text.contains("agent.turns"),
            "the agent's metric reaches a deny-only target: {text}"
        );
    }

    /// **A flood of relayed payloads costs no decision**, which is the audit-suppression property.
    ///
    /// The relay slot admits one payload at a time and drops the rest without waiting, so a workload
    /// posting without pause cannot hold the box's own export worker behind it. One queue carrying both
    /// kinds would break this: the workload would fill it and the box's refusals would be dropped to
    /// make room.
    ///
    /// The scope is the relay path. The decision count stays inside the queue's own capacity, so this
    /// pins that a flood costs no decision, and not that the queue can never overflow.
    #[tokio::test]
    async fn a_flood_of_relayed_payloads_loses_no_decision() {
        const DECISIONS: usize = 200;
        const POSTS: usize = 200;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("records.jsonl");
        let collector = Collector::start(file_config(&path)).expect("open");

        let endpoint = format!("http://127.0.0.1:{}/v1/logs", collector.port());
        let flood = tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut posting = Vec::with_capacity(POSTS);
            for _ in 0..POSTS {
                let client = client.clone();
                let endpoint = endpoint.clone();
                posting.push(tokio::spawn(async move {
                    client
                        .post(endpoint)
                        .header("content-type", "application/json")
                        .body(
                            r#"{"resourceLogs":[{"scopeLogs":[{"scope":{"name":"my-agent"},
                               "logRecords":[{"body":{"stringValue":"flood"}}]}]}]}"#
                                .to_string(),
                        )
                        .send()
                        .await
                        .map(|answered| answered.status().as_u16())
                }));
            }
            for one in posting {
                let _ = one.await;
            }
        });

        // Submitted while the flood is in flight, which is the contended case this test exists for.
        for index in 0..DECISIONS {
            collector.record(DecisionRecord::deny(
                "fs:read",
                &format!("~/decision-{index}"),
                "a-rule",
                "forbidden",
            ));
        }
        flood.await.expect("the flood finishes");
        collector.drained().await;

        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let missing: Vec<usize> = (0..DECISIONS)
            .filter(|index| !text.contains(&format!("~/decision-{index}\"")))
            .collect();
        assert!(
            missing.is_empty(),
            "every decision must survive a relay flood; {} of {DECISIONS} are absent: {missing:?}",
            missing.len()
        );
    }

    /// A slow target does not stall a fast one, because each holds its own queue and worker.
    #[tokio::test]
    async fn a_slow_target_does_not_stall_a_fast_one() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("fast.jsonl");
        let collector = Collector::start(
            TelemetryConfig::for_box("demo")
                .with_target(Target::new(TargetKind::Otlp, nothing_listening()))
                .with_target(Target::new(
                    TargetKind::File,
                    path.to_string_lossy().to_string(),
                )),
        )
        .expect("open");

        for index in 0..5 {
            collector.record(DecisionRecord::deny(
                r#"Box::Action::"fs:read""#,
                "~/x",
                &format!("rule-{index}"),
                "refused",
            ));
        }
        collector.drained().await;

        let text = std::fs::read_to_string(&path).expect("the fast target");
        for index in 0..5 {
            assert!(
                text.contains(&format!("rule-{index}")),
                "the fast target must not wait on the slow one: {text}"
            );
        }
    }

    /// A target that cannot be reached is counted, so a failing endpoint is not silent.
    #[tokio::test]
    async fn a_failed_export_is_counted() {
        let collector = Collector::start(
            TelemetryConfig::for_box("demo")
                .with_target(Target::new(TargetKind::Otlp, nothing_listening())),
        )
        .expect("open");

        collector.record(DecisionRecord::deny(
            r#"Box::Action::"fs:read""#,
            "~/x",
            "rule-1",
            "refused",
        ));
        collector.drained().await;

        assert!(
            collector.dropped() > 0,
            "a record nothing received must be counted as lost"
        );
    }

    /// The collector releases its port when it drops, so a later box can take one.
    #[tokio::test]
    async fn dropping_the_collector_releases_its_port() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("records.jsonl");
        let port = {
            let collector = Collector::start(file_config(&path)).expect("open");
            collector.port()
        };
        for _ in 0..50 {
            if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the port stayed bound one second after the drop");
    }

    /// A control-plane record reaches the file, under its own scope, beside the decisions.
    #[tokio::test]
    async fn a_control_plane_record_reaches_the_file_under_its_own_scope() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("records.jsonl");
        let collector = Collector::start(file_config(&path)).expect("open");

        collector.control(
            ControlRecord::completed(crate::ControlOperation::SchemaInstalled, "issues-mcp")
                .detailed("27 tools"),
        );
        collector.record(DecisionRecord::permit(
            r#"Box::Action::"fs:read""#,
            "~/ok",
            "rule-1",
        ));
        collector.drained().await;

        let text = std::fs::read_to_string(&path).expect("the records");
        assert!(text.contains("schema_installed"), "{text}");
        assert!(
            text.contains("issues-mcp"),
            "the subject is recorded: {text}"
        );
        assert!(text.contains("27 tools"), "the detail is recorded: {text}");
        assert!(
            text.contains(CONTROL_SCOPE),
            "a control record names its own scope: {text}"
        );
        assert!(
            text.contains(SCOPE),
            "and the decision keeps the policy scope: {text}"
        );
    }

    /// A target naming only `control_plane` still gets a log lane.
    #[tokio::test]
    async fn a_target_naming_only_the_control_plane_receives_it() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("control.jsonl");
        let collector = Collector::start(
            TelemetryConfig::for_box("demo").with_target(
                Target::new(TargetKind::File, path.to_string_lossy().to_string())
                    .receiving(vec![Signal::ControlPlane]),
            ),
        )
        .expect("open");

        collector.control(ControlRecord::refused(
            crate::ControlOperation::PolicyRefused,
            "policy.dw",
            "the schema does not validate",
        ));
        collector.record(DecisionRecord::permit(
            r#"Box::Action::"fs:read""#,
            "~/ok",
            "rule-1",
        ));
        collector.drained().await;

        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(text.contains("policy_refused"), "{text}");
        assert!(text.contains("refused"), "the outcome is recorded: {text}");
        assert!(
            !text.contains("rule-1"),
            "a verdict must not reach it: {text}"
        );
    }

    /// **Two targets, so this exercises the SEVERITY routing rather than the acceptance union.**
    ///
    /// With one target, `Collector::control` returns at the union gate and the lane filter is never
    /// reached — the test passed with `ControlPlane` sharing `Info` with a permit. A second target
    /// opens the union, so a shared severity puts a control record in the verdicts-only file.
    #[tokio::test]
    async fn a_target_naming_only_verdicts_receives_no_control_record() {
        let directory = tempfile::tempdir().expect("tempdir");
        let verdicts = directory.path().join("verdicts.jsonl");
        let control = directory.path().join("control.jsonl");
        let collector = Collector::start(
            TelemetryConfig::for_box("demo")
                .with_target(
                    Target::new(TargetKind::File, verdicts.to_string_lossy().to_string())
                        .receiving(Signal::every_verdict()),
                )
                .with_target(
                    Target::new(TargetKind::File, control.to_string_lossy().to_string())
                        .receiving(vec![Signal::ControlPlane]),
                ),
        )
        .expect("open");

        collector.control(ControlRecord::completed(
            crate::ControlOperation::BoxStarted,
            "demo",
        ));
        collector.record(DecisionRecord::permit(
            r#"Box::Action::"fs:read""#,
            "~/ok",
            "rule-1",
        ));
        collector.drained().await;

        let verdicts = std::fs::read_to_string(&verdicts).unwrap_or_default();
        assert!(
            verdicts.contains("rule-1"),
            "the verdict is kept: {verdicts}"
        );
        assert!(
            !verdicts.contains("box_started"),
            "a control record must not reach a verdicts-only target: {verdicts}"
        );

        // The paired positive, or the assertion above would pass on a record nothing received.
        let control = std::fs::read_to_string(&control).unwrap_or_default();
        assert!(
            control.contains("box_started"),
            "the control target received it: {control}"
        );
        assert!(
            !control.contains("rule-1"),
            "and no verdict reached it: {control}"
        );
    }

    /// **A target naming none receives the control plane too**, so an operator who declares nothing
    /// still sees why an early request was denied.
    #[tokio::test]
    async fn the_default_target_receives_the_control_plane() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("records.jsonl");
        let collector = Collector::start(file_config(&path)).expect("open");

        collector.control(ControlRecord::completed(
            crate::ControlOperation::DiscoveryComplete,
            "policy",
        ));
        collector.drained().await;

        let text = std::fs::read_to_string(&path).expect("the records");
        assert!(text.contains("discovery_complete"), "{text}");
    }

    /// **The box builds that default target from an OPENED file**, so the other constructor must
    /// accept the control plane too, or a box declaring no `[telemetry]` table records none of it.
    #[tokio::test]
    async fn an_opened_default_target_receives_the_control_plane() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("records.jsonl");
        std::fs::write(&path, []).expect("empty target");
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("target descriptor");
        let config = TelemetryConfig::for_box("demo")
            .with_target(Target::opened_file(path.to_string_lossy(), file));
        let collector = Collector::start(config).expect("open");

        collector.control(ControlRecord::completed(
            crate::ControlOperation::BoxStarted,
            "demo",
        ));
        collector.drained().await;

        let text = std::fs::read_to_string(&path).expect("the records");
        assert!(
            text.contains("box_started"),
            "a box declaring no telemetry table must still record its control plane: {text}"
        );
    }

    /// Every refusal happens at `open`, so no box starts believing it records.
    #[tokio::test]
    async fn a_config_no_run_could_honour_is_refused_at_open() {
        // A relative file destination would open against the trusted process's working directory.
        let relative = TelemetryConfig::for_box("demo")
            .with_target(Target::new(TargetKind::File, "records.jsonl"));
        assert!(Collector::start(relative).is_err());

        // A target that names no signal states a destination nothing would reach.
        let silent = TelemetryConfig::for_box("demo")
            .with_target(Target::new(TargetKind::File, "/tmp/records.jsonl").receiving(Vec::new()));
        assert!(Collector::start(silent).is_err());
    }
}
