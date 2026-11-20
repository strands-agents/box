//! Read the policy decisions, and the policies installed, saved for one run.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;

use chrono::{DateTime, SecondsFormat, Utc};
use nix::libc;
use serde::{Serialize, Serializer};
use serde_json::Value;

use crate::files::{open_at, open_directory_below};
use crate::host::box_home_base;
use crate::{Error, OutputFormat};

/// The longest records line `box runs history` reads.
const LINE_LIMIT: usize = 8 * 1024 * 1024;
const HEADER: &str = "TIME (UTC)\tRESULT\tACTION\tRESOURCE\tRULE\tREASON";

/// The output and selection for one run's saved decisions.
#[derive(Clone, Debug, Default)]
pub struct RecordsOptions {
    /// The output representation.
    pub format: OutputFormat,
    /// Keep recorded denials, excluding explicit would-denies.
    pub deny: bool,
    /// Keep recorded denials explicitly marked as not enforced.
    pub would_deny: bool,
    /// Match the normalized action exactly, with case preserved.
    pub action: Option<String>,
    /// Match a case-sensitive substring of the recorded resource.
    pub resource: Option<String>,
    /// Keep decisions at or after this instant.
    pub since: Option<DateTime<Utc>>,
    /// Keep the last matching decisions in their recorded order.
    pub tail: Option<usize>,
}

#[derive(Serialize)]
struct Decision {
    #[serde(serialize_with = "serialize_time")]
    time: Option<DateTime<Utc>>,
    result: Option<String>,
    enforced: Option<bool>,
    action: Option<String>,
    resource: Option<String>,
    rule: Option<String>,
    reason: Option<String>,
}

impl Decision {
    fn from_span(span: &Value) -> Self {
        let action = attribute(span, "strands.box.policy.action").map(|action| {
            action
                .strip_prefix("Box::Action::\"")
                .and_then(|action| action.strip_suffix('"'))
                .unwrap_or(action)
                .to_owned()
        });
        let resource = [
            "strands.box.policy.resource",
            "file.path",
            "server.address",
            "process.command",
        ]
        .into_iter()
        .find_map(|key| attribute(span, key))
        .map(str::to_owned);
        Self {
            time: timestamp(span),
            result: attribute(span, "strands.box.policy.verdict").map(str::to_owned),
            enforced: boolean_attribute(span, "strands.box.policy.enforced"),
            action,
            resource,
            rule: attribute(span, "strands.box.policy.rule").map(str::to_owned),
            reason: attribute(span, "strands.box.policy.reason").map(str::to_owned),
        }
    }

    /// A row for the box installing or refusing a policy, at startup or on a reload, such as the
    /// activity banner turning policy off or on. Other control records are left out.
    fn from_policy_change(span: &Value) -> Option<Self> {
        let result = match attribute(span, "strands.box.control.operation")? {
            "policy_installed" => "installed",
            "policy_refused" => "refused",
            _ => return None,
        };
        Some(Self {
            time: timestamp(span),
            result: Some(result.to_owned()),
            enforced: None,
            action: Some("policy".to_owned()),
            resource: attribute(span, "strands.box.control.subject").map(str::to_owned),
            rule: None,
            reason: attribute(span, "strands.box.control.reason").map(str::to_owned),
        })
    }

    fn is_would_deny(&self) -> bool {
        self.result.as_deref() == Some("deny") && self.enforced == Some(false)
    }

    fn matches(&self, options: &RecordsOptions) -> bool {
        (!options.deny || (self.result.as_deref() == Some("deny") && !self.is_would_deny()))
            && (!options.would_deny || self.is_would_deny())
            && options
                .action
                .as_ref()
                .is_none_or(|action| self.action.as_ref() == Some(action))
            && options.resource.as_ref().is_none_or(|resource| {
                self.resource
                    .as_ref()
                    .is_some_and(|value| value.contains(resource))
            })
            && options
                .since
                .is_none_or(|since| self.time.is_some_and(|time| time >= since))
    }

    fn write_text(&self, output: &mut impl Write) -> io::Result<()> {
        let time = self
            .time
            .map(|time| time.to_rfc3339_opts(SecondsFormat::Nanos, true))
            .unwrap_or_else(|| "unknown".to_owned());
        let result = if self.is_would_deny() {
            "would deny"
        } else {
            self.result
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("unknown")
        };
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}\t{}",
            time,
            result.escape_debug(),
            self.action.as_deref().unwrap_or("-").escape_debug(),
            self.resource.as_deref().unwrap_or("-").escape_debug(),
            self.rule.as_deref().unwrap_or("-").escape_debug(),
            self.reason.as_deref().unwrap_or("-").escape_debug()
        )
    }
}

struct RecordsOutput<'a, W> {
    output: &'a mut W,
    format: OutputFormat,
    shown: bool,
}

impl<W: Write> RecordsOutput<'_, W> {
    fn write(&mut self, decision: &Decision) -> io::Result<()> {
        match self.format {
            OutputFormat::Text => {
                if !self.shown {
                    writeln!(self.output, "{HEADER}")?;
                }
                decision.write_text(self.output)?;
            }
            OutputFormat::Json => {
                self.output
                    .write_all(if self.shown { b",\n" } else { b"[\n" })?;
                crate::output::json(&mut *self.output, decision)?;
            }
        }
        self.shown = true;
        Ok(())
    }

    fn finish(&mut self, options: &RecordsOptions) -> io::Result<()> {
        match self.format {
            OutputFormat::Json => {
                self.output
                    .write_all(if self.shown { b"\n]\n" } else { b"[]\n" })?;
            }
            OutputFormat::Text if !self.shown => {
                let message = if options.action.is_some()
                    || options.resource.is_some()
                    || options.since.is_some()
                    || options.tail.is_some()
                {
                    "No matching policy decisions recorded."
                } else if options.deny {
                    "No denied policy decisions recorded."
                } else if options.would_deny {
                    "No would-deny policy decisions recorded."
                } else {
                    "No policy decisions recorded."
                };
                writeln!(self.output, "{message}")?;
            }
            OutputFormat::Text => {}
        }
        Ok(())
    }
}

pub(crate) fn show(
    home: &Path,
    box_home: &Path,
    id: &str,
    options: &RecordsOptions,
    output: &mut impl Write,
    warnings: &mut impl Write,
) -> Result<(), Error> {
    if !box_home.is_absolute() {
        return Err(Error::NoHome);
    }
    if id.is_empty() || matches!(id, "." | "..") || id.contains(['/', '\0']) {
        return Err(Error::RecordsId { id: id.to_owned() });
    }
    let path = box_home
        .join(crate::run::RUNS)
        .join(id)
        .join("records.jsonl");
    let file = open_records(home, box_home, id).map_err(|source| read_error(&path, source))?;
    let length = file
        .metadata()
        .map_err(|source| read_error(&path, source))?
        .len();
    let mut tail = VecDeque::new();
    let mut output = RecordsOutput {
        output,
        format: options.format,
        shown: false,
    };
    let incomplete = each_decision(file.take(length), &path, warnings, |decision| {
        if !decision.matches(options) {
            return Ok(());
        }
        if let Some(limit) = options.tail {
            if limit != 0 {
                if tail.len() == limit {
                    tail.pop_front();
                }
                tail.push_back(decision);
            }
            Ok(())
        } else {
            output.write(&decision).map_err(output_error)
        }
    })?;
    for decision in tail {
        output.write(&decision).map_err(output_error)?;
    }
    output.finish(options).map_err(output_error)?;
    if incomplete {
        Err(Error::RecordsIncomplete { path })
    } else {
        Ok(())
    }
}

/// One decision a run's records hold, as the activity banner restores it at startup.
pub(crate) struct SavedDecision<'a> {
    pub(crate) time: Option<std::time::SystemTime>,
    pub(crate) permitted: bool,
    pub(crate) action: &'a str,
    pub(crate) resource: &'a str,
    pub(crate) rule: &'a str,
    pub(crate) reason: Option<&'a str>,
}

/// The bytes of one run's records file as they were when [`saved`] opened it.
pub(crate) struct Saved {
    file: io::Take<File>,
    path: std::path::PathBuf,
}

/// Open `journal` and fix its length now, so a later read sees nothing appended after this call.
/// A missing or unreadable file gives `None`.
pub(crate) fn saved(home: &Path, journal: &Path) -> Option<Saved> {
    let run = journal.parent()?;
    let box_home = run.parent().and_then(Path::parent)?;
    let id = run.file_name().and_then(|id| id.to_str())?;
    if journal.file_name() != Some("records.jsonl".as_ref())
        || run.parent().and_then(Path::file_name) != Some(crate::run::RUNS.as_ref())
    {
        return None;
    }
    let file = open_records(home, box_home, id).ok()?;
    let length = file.metadata().ok()?.len();
    Some(Saved {
        file: file.take(length),
        path: journal.to_path_buf(),
    })
}

impl Saved {
    /// Visit each permit and each enforced denial, as `box runs history` reads them. A line it
    /// cannot read gives nothing.
    pub(crate) fn each(self, mut visit: impl FnMut(SavedDecision<'_>)) {
        let _ = each_decision(self.file, &self.path, &mut io::sink(), |decision| {
            let permitted = match decision.result.as_deref() {
                Some("permit") => true,
                Some("deny") if !decision.is_would_deny() => false,
                _ => return Ok(()),
            };
            visit(SavedDecision {
                time: decision.time.map(std::time::SystemTime::from),
                permitted,
                action: decision.action.as_deref().unwrap_or_default(),
                resource: decision.resource.as_deref().unwrap_or_default(),
                rule: decision.rule.as_deref().unwrap_or_default(),
                reason: decision.reason.as_deref(),
            });
            Ok(())
        });
    }
}

/// Visit each policy decision and policy change in `source`, and report whether any line could
/// not be read.
fn each_decision(
    source: impl Read,
    path: &Path,
    warnings: &mut impl Write,
    mut visit: impl FnMut(Decision) -> Result<(), Error>,
) -> Result<bool, Error> {
    let mut reader = BufReader::new(source);
    let mut line = Vec::new();
    let mut number = 0;
    let mut incomplete = false;
    while let Some(oversized) =
        read_line(&mut reader, &mut line).map_err(|source| read_error(path, source))?
    {
        number += 1;
        if oversized {
            incomplete = true;
            warn(warnings, path, number, "line exceeds 8 MiB; skipped")?;
            continue;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let batch: Value = match serde_json::from_slice(&line) {
            Ok(batch) => batch,
            Err(error) => {
                incomplete = true;
                warn(
                    warnings,
                    path,
                    number,
                    &format!("invalid JSON; skipped: {error}"),
                )?;
                continue;
            }
        };
        let mut decisions = Vec::new();
        let mut changes = Vec::new();
        for resource in items(&batch, "resourceSpans") {
            for scope in items(resource, "scopeSpans") {
                let control = match scope.pointer("/scope/name").and_then(Value::as_str) {
                    Some("strands-box.policy") => false,
                    Some("strands-box.control") => true,
                    _ => continue,
                };
                for span in items(scope, "spans") {
                    if span.get("spanId").and_then(Value::as_str).is_none() {
                        continue;
                    }
                    if control {
                        changes.extend(Decision::from_policy_change(span));
                    } else if span
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| name.starts_with("policy "))
                    {
                        decisions.push(Decision::from_span(span));
                    }
                }
            }
        }
        for decision in in_time_order(decisions, changes) {
            visit(decision)?;
        }
    }
    Ok(incomplete)
}

/// One batch's decisions and policy changes as one list, because a batch holds each kind in its
/// own scope. Each kind keeps its recorded order, and a change goes before the first decision at
/// or after its time. A change that can't be placed by time waits for the batch's end.
fn in_time_order(decisions: Vec<Decision>, changes: Vec<Decision>) -> Vec<Decision> {
    let mut merged = Vec::with_capacity(decisions.len() + changes.len());
    let mut changes = changes.into_iter().peekable();
    for decision in decisions {
        while let Some(change) = changes.next_if(
            |change| matches!((change.time, decision.time), (Some(at), Some(next)) if at <= next),
        ) {
            merged.push(change);
        }
        merged.push(decision);
    }
    merged.extend(changes);
    merged
}

fn open_records(home: &Path, box_home: &Path, id: &str) -> io::Result<File> {
    let mut directory = open_directory_below(box_home, box_home_base(home, box_home))?;
    for name in [crate::run::RUNS, id] {
        directory = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    }
    let file = File::from(open_at(
        &directory,
        "records.jsonl",
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )?);
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "records.jsonl is not a regular file",
        ));
    }
    Ok(file)
}

/// One bounded line, or an oversized line consumed through its delimiter.
fn read_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<Option<bool>> {
    line.clear();
    let mut oversized = false;
    let mut started = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(started.then_some(oversized));
        }
        started = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let length = newline.unwrap_or(available.len());
        if !oversized {
            if length > LINE_LIMIT - line.len() {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(&available[..length]);
            }
        }
        reader.consume(length + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(oversized));
        }
    }
}

fn items<'a>(value: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn attribute<'a>(span: &'a Value, key: &str) -> Option<&'a str> {
    items(span, "attributes").find_map(|attribute| {
        (attribute.get("key").and_then(Value::as_str) == Some(key))
            .then(|| {
                attribute
                    .pointer("/value/stringValue")
                    .and_then(Value::as_str)
            })
            .flatten()
    })
}

fn boolean_attribute(span: &Value, key: &str) -> Option<bool> {
    items(span, "attributes").find_map(|attribute| {
        (attribute.get("key").and_then(Value::as_str) == Some(key))
            .then(|| {
                attribute
                    .pointer("/value/boolValue")
                    .and_then(Value::as_bool)
            })
            .flatten()
    })
}

fn timestamp(span: &Value) -> Option<DateTime<Utc>> {
    span.get("startTimeUnixNano")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|nanos| {
            DateTime::from_timestamp(
                (nanos / 1_000_000_000) as i64,
                (nanos % 1_000_000_000) as u32,
            )
        })
}

fn serialize_time<S: Serializer>(
    time: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    time.map(|time| time.to_rfc3339_opts(SecondsFormat::Nanos, true))
        .serialize(serializer)
}

fn warn(warnings: &mut impl Write, path: &Path, number: usize, message: &str) -> Result<(), Error> {
    writeln!(
        warnings,
        "box: warning: {path:?}: line {number}: {}",
        message.escape_debug()
    )
    .map_err(|source| Error::RecordsOutput {
        stream: "stderr",
        source,
    })
}

fn read_error(path: &Path, source: io::Error) -> Error {
    Error::RecordsRead {
        path: path.to_owned(),
        source,
    }
}

fn output_error(source: io::Error) -> Error {
    Error::RecordsOutput {
        stream: "stdout",
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AppendOnWrite<'a> {
        path: &'a Path,
        append: &'a [u8],
        output: Vec<u8>,
        appended: bool,
    }

    impl Write for AppendOnWrite<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.appended {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(self.path)?
                    .write_all(self.append)?;
                self.appended = true;
            }
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn reads_only_the_bytes_present_before_output_starts() {
        let home = tempfile::tempdir().unwrap();
        let run = home.path().join(".strands/box/r/b-1234567812345678");
        std::fs::create_dir_all(&run).unwrap();
        let path = run.join("records.jsonl");
        let batch = serde_json::json!({"resourceSpans": [{"scopeSpans": [{
            "scope": {"name": "strands-box.policy"}, "spans": [{
                "spanId": "1234567812345678", "name": "policy fs:read",
                "attributes": [{"key": "strands.box.policy.resource",
                    "value": {"stringValue": "/before"}}]
            }]
        }]}]})
        .to_string();
        let append = format!("\n{}\n", batch.replace("/before", "/after"));
        for format in [OutputFormat::Text, OutputFormat::Json] {
            for tail in [None, Some(1)] {
                std::fs::write(&path, &batch).unwrap();
                let mut output = AppendOnWrite {
                    path: &path,
                    append: append.as_bytes(),
                    output: Vec::new(),
                    appended: false,
                };
                let mut warnings = Vec::new();
                show(
                    home.path(),
                    &home.path().join(".strands/box"),
                    "b-1234567812345678",
                    &RecordsOptions {
                        format,
                        tail,
                        ..RecordsOptions::default()
                    },
                    &mut output,
                    &mut warnings,
                )
                .unwrap();
                let text = String::from_utf8(output.output).unwrap();
                assert!(output.appended);
                assert!(text.contains("/before"));
                assert!(!text.contains("/after"));
                assert!(warnings.is_empty());
                assert!(std::fs::read_to_string(&path).unwrap().contains("/after"));
            }
        }
    }
}
