//! The box's telemetry file, as a reader validates it.
//!
//! One line of the file is one OTLP-JSON request. A reader selects on the resource's
//! `strands.box.source` and on the scope name, because shape alone no longer tells a box record from
//! an agent's.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The scope every policy decision carries.
pub const POLICY_SCOPE: &str = "strands-box.policy";

/// The scope every control-plane operation carries.
pub const CONTROL_SCOPE: &str = "strands-box.control";

/// The scope every kernel-refusal record carries.
pub const CONTAINMENT_SCOPE: &str = "strands-box.containment";

/// The resource attribute naming the box a record belongs to.
pub const BOX_NAME_KEY: &str = "strands.box.name";

/// The resource attribute naming the one `run` a record belongs to.
pub const RUN_ID_KEY: &str = "strands.box.run.id";

/// The resource attribute naming who produced a record.
pub const SOURCE_KEY: &str = "strands.box.source";

/// The `strands.box.source` value the box's own records carry.
pub const SOURCE_BOX: &str = "box";

/// The `strands.box.source` value a relayed harness payload carries.
pub const SOURCE_AGENT: &str = "agent";

/// What the receiver prefixes to a scope name that claims the box's own namespace.
pub const AGENT_CLAIMED: &str = "agent-claimed:";

/// What the record holds instead of an expanded argument.
pub const REDACTED: &str = "<redacted>";

/// The `strands.box.policy.rule` value an absent permit carries.
pub const DEFAULT_DENY_RULE: &str = "<default-deny>";

/// The `strands.box.policy.reason` value an absent permit carries.
pub const NO_PERMIT_REASON: &str = "no permit matched";

/// The attribute naming a decision's refusal class or its permit.
pub const CAUSE_KEY: &str = "strands.box.policy.cause";

/// The attribute naming a control-plane operation.
pub const CONTROL_OPERATION_KEY: &str = "strands.box.control.operation";

/// The three top-level keys one request may carry.
const SIGNAL_KEYS: [&str; 3] = ["resourceLogs", "resourceSpans", "resourceMetrics"];

/// Which signal one line carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Payload {
    /// `resourceLogs`: a decision, a control operation, or a relayed harness log.
    Logs,
    /// `resourceSpans`: a span the box derived, or one a harness exported.
    Spans,
    /// `resourceMetrics`: a metric a harness exported.
    Metrics,
}

impl Payload {
    /// The OTLP-JSON key this signal arrives under.
    pub fn as_key(self) -> &'static str {
        match self {
            Self::Logs => "resourceLogs",
            Self::Spans => "resourceSpans",
            Self::Metrics => "resourceMetrics",
        }
    }
}

/// What a resource says about the box and the producer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Producer {
    /// `strands.box.name`.
    pub box_name: Option<String>,
    /// `strands.box.run.id`.
    pub run_id: Option<String>,
    /// `strands.box.source`.
    pub source: Option<String>,
}

/// One log record, with the line and the scope it arrived under.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// The 1-based line of the file this record arrived on.
    pub line: usize,
    /// The scope name, empty when the payload named none.
    pub scope: String,
    /// The resource identity this record sits under.
    pub producer: Producer,
    /// Every string attribute, keyed by name.
    pub attributes: BTreeMap<String, String>,
    /// Every array-of-string attribute, keyed by name.
    pub lists: BTreeMap<String, Vec<String>>,
    /// `traceId`, empty when the record carries none.
    pub trace_id: String,
    /// `spanId`, empty when the record carries none.
    pub span_id: String,
    /// `timeUnixNano`, 0 when the record carries none.
    pub at_unix_nano: u64,
    /// `severityText`, which is how a record reaches its lane.
    pub severity_text: String,
    /// `severityNumber`, 0 when the record carries none.
    pub severity_number: u64,
    /// `eventName`, empty when the record carries none.
    pub event_name: String,
    /// The record's body as a string, empty when it carries none.
    pub body: String,
}

impl LogRecord {
    /// One string attribute, or nothing when the record carries none under `key`.
    pub fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }

    /// Fail unless `key` holds exactly `value`.
    pub fn assert_attribute(&self, key: &str, value: &str) {
        crate::count_assertion();
        assert_eq!(
            self.attribute(key),
            Some(value),
            "line {} {}: {key} must hold {value:?}; the record holds {:?}",
            self.line,
            self.scope,
            self.attributes,
        );
    }
}

/// One span the file holds.
#[derive(Debug, Clone)]
pub struct SpanRecord {
    /// The 1-based line of the file this span arrived on.
    pub line: usize,
    /// The scope name, empty when the payload named none.
    pub scope: String,
    /// The resource identity this span sits under.
    pub producer: Producer,
    /// The span name.
    pub name: String,
    /// `traceId`.
    pub trace_id: String,
    /// `spanId`.
    pub span_id: String,
    /// `parentSpanId`, empty for a root.
    pub parent_span_id: String,
    /// `flags`, 0 when the span carries none.
    pub flags: u64,
    /// Every string attribute, keyed by name.
    pub attributes: BTreeMap<String, String>,
}

impl SpanRecord {
    /// Whether this span names no parent.
    pub fn is_root(&self) -> bool {
        self.parent_span_id.is_empty()
    }
}

/// One telemetry file, parsed.
///
/// Parsing is lenient and the assertions are strict: a line this reader cannot read is a defect in
/// the box, so it must reach a case as a FAIL rather than stop the reader.
#[derive(Debug, Clone)]
pub struct Journal {
    /// The destination this journal was read from.
    pub path: PathBuf,
    /// The whole file, for an absence assertion.
    pub text: String,
    /// One entry per line that is one request, in file order.
    pub lines: Vec<(usize, Payload, serde_json::Value)>,
    /// One entry per line that is not, as `(line, why)`.
    pub malformed: Vec<(usize, String)>,
}

impl Journal {
    /// Read and parse `path`. An absent file is an empty journal, never a panic, so a case states
    /// what it expects rather than reading an error for an absence.
    pub fn read(path: &Path) -> Self {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let (lines, malformed) = Self::parse(&text);
        Journal {
            path: path.to_path_buf(),
            text,
            lines,
            malformed,
        }
    }

    /// Every line as one request, and every line that is not one.
    #[allow(clippy::type_complexity)]
    fn parse(
        text: &str,
    ) -> (
        Vec<(usize, Payload, serde_json::Value)>,
        Vec<(usize, String)>,
    ) {
        let mut parsed = Vec::new();
        let mut malformed = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            if line.trim().is_empty() {
                malformed.push((number, "the line is blank".to_string()));
                continue;
            }
            let value: serde_json::Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(error) => {
                    malformed.push((
                        number,
                        format!(
                            "the line is not JSON: {error}; first 120 bytes [{}]",
                            line.chars().take(120).collect::<String>()
                        ),
                    ));
                    continue;
                }
            };
            let named: Vec<Payload> = [Payload::Logs, Payload::Spans, Payload::Metrics]
                .into_iter()
                .filter(|signal| value.get(signal.as_key()).is_some())
                .collect();
            let [signal] = named[..] else {
                malformed.push((
                    number,
                    format!(
                        "the line names {} of {SIGNAL_KEYS:?}; one line is exactly one request",
                        named.len()
                    ),
                ));
                continue;
            };
            if value[signal.as_key()].as_array().map_or(0, Vec::len) == 0 {
                malformed.push((
                    number,
                    format!(
                        "{} is empty; a request with no resource is not a record",
                        signal.as_key()
                    ),
                ));
                continue;
            }
            parsed.push((number, signal, value));
        }
        (parsed, malformed)
    }

    /// Fail unless every line is exactly one OTLP request. Counts as a case assertion.
    pub fn assert_well_formed(&self) {
        crate::count_assertion();
        assert!(
            self.malformed.is_empty(),
            "{} is one OTLP-JSON request per line, and {} line(s) are not: {:?}",
            self.path.display(),
            self.malformed.len(),
            self.malformed
        );
    }

    /// How many lines name `signal`.
    pub fn count_of(&self, signal: Payload) -> usize {
        self.lines
            .iter()
            .filter(|(_, named, _)| *named == signal)
            .count()
    }

    /// Every log record the file holds, in file order.
    pub fn logs(&self) -> Vec<LogRecord> {
        let mut found = Vec::new();
        for (number, signal, value) in &self.lines {
            if *signal != Payload::Logs {
                continue;
            }
            for resource in value["resourceLogs"].as_array().into_iter().flatten() {
                let producer = producer_of(&resource["resource"]);
                for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                    let name = text_of(&scope["scope"]["name"]);
                    for entry in scope["logRecords"].as_array().into_iter().flatten() {
                        found.push(LogRecord {
                            line: *number,
                            scope: name.clone(),
                            producer: producer.clone(),
                            attributes: strings_of(&entry["attributes"]),
                            lists: lists_of(&entry["attributes"]),
                            trace_id: text_of(&entry["traceId"]),
                            span_id: text_of(&entry["spanId"]),
                            at_unix_nano: number_of(&entry["timeUnixNano"]),
                            severity_text: text_of(&entry["severityText"]),
                            severity_number: number_of(&entry["severityNumber"]),
                            event_name: text_of(&entry["eventName"]),
                            body: text_of(&entry["body"]["stringValue"]),
                        });
                    }
                }
            }
        }
        found
    }

    /// Every span the file holds, in file order.
    pub fn spans(&self) -> Vec<SpanRecord> {
        let mut found = Vec::new();
        for (number, signal, value) in &self.lines {
            if *signal != Payload::Spans {
                continue;
            }
            for resource in value["resourceSpans"].as_array().into_iter().flatten() {
                let producer = producer_of(&resource["resource"]);
                for scope in resource["scopeSpans"].as_array().into_iter().flatten() {
                    let name = text_of(&scope["scope"]["name"]);
                    for entry in scope["spans"].as_array().into_iter().flatten() {
                        found.push(SpanRecord {
                            line: *number,
                            scope: name.clone(),
                            producer: producer.clone(),
                            name: text_of(&entry["name"]),
                            trace_id: text_of(&entry["traceId"]),
                            span_id: text_of(&entry["spanId"]),
                            parent_span_id: text_of(&entry["parentSpanId"]),
                            flags: number_of(&entry["flags"]),
                            attributes: strings_of(&entry["attributes"]),
                        });
                    }
                }
            }
        }
        found
    }

    /// Every log record under `scope`.
    pub fn logs_under(&self, scope: &str) -> Vec<LogRecord> {
        self.logs()
            .into_iter()
            .filter(|record| record.scope == scope)
            .collect()
    }

    /// Every scope name the file names, deduplicated.
    pub fn scopes(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .logs()
            .into_iter()
            .map(|record| record.scope)
            .chain(self.spans().into_iter().map(|span| span.scope))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Every distinct `strands.box.source` value, deduplicated.
    pub fn sources(&self) -> Vec<String> {
        let mut found: Vec<String> = self
            .logs()
            .into_iter()
            .filter_map(|record| record.producer.source)
            .chain(
                self.spans()
                    .into_iter()
                    .filter_map(|span| span.producer.source),
            )
            .collect();
        found.sort();
        found.dedup();
        found
    }

    /// Every decision the policy scope holds, as the shared parser reads it.
    pub fn decisions(&self) -> Vec<crate::Decision> {
        crate::parse_decisions(&self.text)
    }

    /// Fail unless the whole file holds `needle` nowhere. Counts as a case assertion.
    pub fn assert_absent(&self, needle: &str, why: &str) {
        crate::count_assertion();
        // By line rather than by byte: a byte window can cut a multi-byte character, and that panic
        // would replace this message with a slicing error.
        if let Some((number, line)) = self
            .text
            .lines()
            .enumerate()
            .find(|(_, line)| line.contains(needle))
        {
            panic!(
                "{why}: {needle:?} must not reach {}, and line {} holds it; that line begins [{}]",
                self.path.display(),
                number + 1,
                line.chars().take(400).collect::<String>(),
            );
        }
    }

    /// Fail unless the whole file holds `needle`. Counts as a case assertion.
    pub fn assert_present(&self, needle: &str, why: &str) {
        crate::count_assertion();
        assert!(
            self.text.contains(needle),
            "{why}: {needle:?} must reach {}, and the file holds {} lines; first 400 bytes [{}]",
            self.path.display(),
            self.lines.len(),
            self.text.chars().take(400).collect::<String>()
        );
    }

    /// Fail unless the file holds at least one line. Counts as a case assertion.
    pub fn assert_recorded(&self) {
        crate::count_assertion();
        assert!(
            !self.lines.is_empty(),
            "{} holds no request; the box recorded nothing, so every later assertion would be \
             vacuous",
            self.path.display()
        );
    }

    /// Every log record and every span, each labelled by where it sits, for an identity assertion.
    fn producers(&self) -> Vec<(String, Producer)> {
        self.logs()
            .into_iter()
            .map(|record| (format!("line {} log", record.line), record.producer))
            .chain(
                self.spans()
                    .into_iter()
                    .map(|span| (format!("line {} span", span.line), span.producer)),
            )
            .collect()
    }

    /// Every distinct `strands.box.run.id`, in the order the file names them.
    ///
    /// One `strands-box run` is one id, so a file holding two runs names two. The fixture preflight
    /// is a run of its own, which is why a case's own run is never the only one.
    pub fn run_ids(&self) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        for (_, producer) in self.producers() {
            if let Some(run) = producer.run_id {
                if !found.contains(&run) {
                    found.push(run);
                }
            }
        }
        found
    }

    /// Fail unless every record and every span names `box_id`, `source`, and some run.
    ///
    /// Counts as a case assertion. Returns the run ids the file names.
    pub fn assert_identity(&self, box_id: &str, source: &str) -> Vec<String> {
        crate::count_assertion();
        let producers = self.producers();
        assert!(
            !producers.is_empty(),
            "{} names no producer at all",
            self.path.display()
        );
        for (where_, producer) in &producers {
            assert_eq!(
                producer.box_name.as_deref(),
                Some(box_id),
                "{where_}: {BOX_NAME_KEY} must hold this box's own id"
            );
            assert_eq!(
                producer.source.as_deref(),
                Some(source),
                "{where_}: {SOURCE_KEY} must name the producer"
            );
            let run = producer
                .run_id
                .as_deref()
                .unwrap_or_else(|| panic!("{where_}: {RUN_ID_KEY} is absent"));
            assert!(!run.is_empty(), "{where_}: {RUN_ID_KEY} is empty");
        }
        self.run_ids()
    }

    /// Fail unless this file holds the `shell:exec` permit for the hosted Shell's own entry echo.
    ///
    /// A mediated run proves entry by a journaled `shell:exec`, and `RunResult` reads that from the
    /// DEFAULT destination. A declared target replaces that destination, so a case that declares one
    /// takes its entry proof from here instead. Counts as a case assertion.
    pub fn assert_mediated_entry(&self) {
        crate::count_assertion();
        let records = self.logs_under(POLICY_SCOPE);
        let found = records.iter().any(|record| {
            record.attribute("strands.box.policy.action") == Some("shell:exec")
                && record.attribute("strands.box.policy.verdict") == Some("permit")
                && record
                    .lists
                    .get("process.command_args")
                    .is_some_and(|args| args.iter().any(|arg| arg == crate::MEDIATED))
        });
        assert!(
            found,
            "{} holds no `shell:exec` permit for the Shell's own `echo {}`; the command ran in a \
             shell that did not reach the broker, or the records went elsewhere. {} record(s): {:?}",
            self.path.display(),
            crate::MEDIATED,
            records.len(),
            records
                .iter()
                .map(|record| (
                    record.attribute("strands.box.policy.action"),
                    record.attribute("strands.box.policy.verdict"),
                    record.lists.get("process.command_args"),
                ))
                .collect::<Vec<_>>(),
        );
    }

    /// The one decision record for `action` whose resource holds `resource`.
    ///
    /// Fails when the file holds none, naming every decision it does hold. Counts as a case
    /// assertion.
    pub fn assert_decision(&self, action: &str, resource: &str, verdict: &str) -> LogRecord {
        crate::count_assertion();
        let records = self.logs_under(POLICY_SCOPE);
        records
            .iter()
            .find(|record| {
                record.attribute("strands.box.policy.action") == Some(action)
                    && record.attribute("strands.box.policy.verdict") == Some(verdict)
                    && record
                        .attribute("strands.box.policy.resource")
                        .is_some_and(|held| held.contains(resource))
            })
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "{} holds no {verdict} of {action} on a resource naming {resource}; it holds \
                     {:?}",
                    self.path.display(),
                    records
                        .iter()
                        .map(|record| (
                            record.attribute("strands.box.policy.action"),
                            record.attribute("strands.box.policy.verdict"),
                            record.attribute("strands.box.policy.resource"),
                        ))
                        .collect::<Vec<_>>(),
                )
            })
    }

    /// Fail unless every scope the file names is one this box writes.
    ///
    /// Counts as a case assertion. A scope outside the two is a reader's problem: a query that
    /// names no scope reads the wrong record shape.
    pub fn assert_scopes_are_the_boxs_own(&self) {
        crate::count_assertion();
        let found = self.scopes();
        let unexpected: Vec<&String> = found
            .iter()
            .filter(|name| {
                ![POLICY_SCOPE, CONTROL_SCOPE, CONTAINMENT_SCOPE].contains(&name.as_str())
            })
            .collect();
        assert!(
            unexpected.is_empty(),
            "{} names {unexpected:?}; a box writes {POLICY_SCOPE}, {CONTROL_SCOPE}, and \
             {CONTAINMENT_SCOPE} alone",
            self.path.display()
        );
        assert!(
            found.iter().any(|name| name == POLICY_SCOPE),
            "{} names no {POLICY_SCOPE} record, so no decision reached it: {found:?}",
            self.path.display()
        );
    }
}

/// `value` as a string, empty when it is absent or holds another type.
fn text_of(value: &serde_json::Value) -> String {
    value.as_str().unwrap_or_default().to_string()
}

/// `value` as a number, reading the string spelling OTLP uses for a 64-bit field.
fn number_of(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::String(text) => text.parse().unwrap_or(0),
        serde_json::Value::Number(number) => number.as_u64().unwrap_or(0),
        _ => 0,
    }
}

/// Every string attribute of an OTLP attribute array, and every integer one in its decimal spelling
/// (OTLP-JSON writes a 64-bit integer as a string).
fn strings_of(attributes: &serde_json::Value) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    for attribute in attributes.as_array().into_iter().flatten() {
        let Some(key) = attribute["key"].as_str() else {
            continue;
        };
        if let Some(value) = attribute["value"]["stringValue"].as_str() {
            found.insert(key.to_string(), value.to_string());
        } else if !attribute["value"]["intValue"].is_null() {
            found.insert(
                key.to_string(),
                number_of(&attribute["value"]["intValue"]).to_string(),
            );
        }
    }
    found
}

/// Every array-of-string attribute of an OTLP attribute array.
fn lists_of(attributes: &serde_json::Value) -> BTreeMap<String, Vec<String>> {
    let mut found = BTreeMap::new();
    for attribute in attributes.as_array().into_iter().flatten() {
        let Some(key) = attribute["key"].as_str() else {
            continue;
        };
        if let Some(values) = attribute["value"]["arrayValue"]["values"].as_array() {
            found.insert(
                key.to_string(),
                values
                    .iter()
                    .filter_map(|value| value["stringValue"].as_str())
                    .map(str::to_string)
                    .collect(),
            );
        }
    }
    found
}

/// The three identity attributes one resource carries.
fn producer_of(resource: &serde_json::Value) -> Producer {
    let attributes = strings_of(&resource["attributes"]);
    Producer {
        box_name: attributes.get(BOX_NAME_KEY).cloned(),
        run_id: attributes.get(RUN_ID_KEY).cloned(),
        source: attributes.get(SOURCE_KEY).cloned(),
    }
}

/// A `bash` command that posts `body` as OTLP-JSON to the endpoint the box handed the workload.
///
/// `/dev/tcp` is a `bash` redirection rather than a program, so the workload needs no `exec` grant
/// and nothing passes the broker. The box permits outbound traffic to the receiver's port, so this
/// is the one route a contained workload has to the collector.
pub fn post_as_workload(route: &str, body: &str) -> String {
    let quoted = crate::sh_quote(body);
    format!(
        r#"
BODY={quoted}
HOSTPORT=${{OTEL_EXPORTER_OTLP_ENDPOINT#http://}}
HOST=${{HOSTPORT%%:*}}
PORT=${{HOSTPORT##*:}}
printf 'TL_ENDPOINT %s\n' "$OTEL_EXPORTER_OTLP_ENDPOINT"
exec 3<>"/dev/tcp/$HOST/$PORT" || {{ printf 'TL_DIAL_FAILED\n'; exit 1; }}
printf 'POST {route} HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
  "$HOSTPORT" "${{#BODY}}" "$BODY" >&3
while IFS= read -r line <&3; do printf 'TL_REPLY %s\n' "$line"; done
exec 3<&-
printf 'TL_POSTED\n'
"#
    )
}
