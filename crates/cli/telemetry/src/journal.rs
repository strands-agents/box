use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::fcntl::OFlag;
use serde_json::Value;

use crate::CoreOutcome;

const READ_LIMIT: usize = 1024 * 1024;
const ATTRIBUTE_LIMIT: usize = 1024;

/// One observed Core lifecycle record or policy decision.
#[derive(Debug, PartialEq, Eq)]
pub enum Record {
    WorkloadStarted(Option<SystemTime>),
    BoxStopped(CoreOutcome),
    Decision(Decision),
}

/// One observed policy decision, before vocabulary classification.
#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    pub action: String,
    pub category: String,
    pub verdict: Verdict,
    pub cause: Option<String>,
}

/// The policy decision's explicit verdict.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Permit,
    Deny,
}

/// An incremental reader of records appended to one Core journal.
pub struct Journal {
    _lock: Option<Arc<dyn Send + Sync>>,
    path: PathBuf,
    file: Option<File>,
    identity: Option<(u64, u64)>,
    offset: u64,
    line_start: u64,
    decisions_after: u64,
    pending: Vec<u8>,
    valid: bool,
    at_end: bool,
    broken: bool,
}

impl Journal {
    /// Observe only bytes appended after this call.
    pub fn start(path: &Path) -> io::Result<Self> {
        let mut journal = Self {
            _lock: None,
            path: path.components().collect(),
            file: None,
            identity: None,
            offset: 0,
            line_start: 0,
            decisions_after: 0,
            pending: Vec::new(),
            valid: true,
            at_end: false,
            broken: false,
        };
        match journal.open() {
            Ok(()) => journal.discard_to_end()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(journal)
    }

    /// Observe new bytes while retaining the caller's instance lock.
    pub fn start_locked(path: &Path, lock: Arc<dyn Send + Sync>) -> io::Result<Self> {
        let mut journal = Self::start(path)?;
        journal._lock = Some(lock);
        Ok(journal)
    }

    /// Read at most one MiB and visit each new record once.
    pub fn read(&mut self, mut visit: impl FnMut(Record)) {
        if self.broken {
            return;
        }
        if self.file.is_none() {
            match self.open() {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => return,
                Err(_) => {
                    self.broken = true;
                    return;
                }
            }
        }
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            self.broken = true;
            return;
        };
        if !metadata.is_file()
            || Some((metadata.dev(), metadata.ino())) != self.identity
            || metadata.len() < self.offset
        {
            self.broken = true;
            return;
        }
        let end = metadata.len();
        let limit = end.min(self.offset.saturating_add(READ_LIMIT as u64));
        let mut buffer = [0; 16 * 1024];
        while self.offset < limit {
            let amount = (limit - self.offset).min(buffer.len() as u64) as usize;
            let Some(file) = self.file.as_mut() else {
                self.broken = true;
                return;
            };
            match file.read(&mut buffer[..amount]) {
                Ok(0) => {
                    self.broken = true;
                    return;
                }
                Ok(count) => {
                    self.offset += count as u64;
                    self.consume(&buffer[..count], &mut visit);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.broken = true;
                    return;
                }
            }
        }
        self.at_end = self.offset == end;
    }

    /// Whether the last read reached its end or cannot continue.
    pub fn at_end(&self) -> bool {
        self.at_end || self.broken || self.file.is_none()
    }

    /// Finish the interval and exclude its incomplete decisions from later intervals.
    pub fn finish_interval(&mut self) -> bool {
        let complete = !self.broken
            && self.file.is_some()
            && self.valid
            && self.at_end
            && self.pending.is_empty();
        if !self.broken
            && let Some(file) = self.file.as_ref()
            && (!self.at_end || !self.pending.is_empty())
        {
            match file.metadata() {
                Ok(metadata) => self.decisions_after = metadata.len(),
                Err(_) => self.broken = true,
            }
        }
        self.valid = true;
        complete
    }

    fn open(&mut self) -> io::Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC).bits())
            .open(&self.path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal is not a regular file",
            ));
        }
        self.identity = Some((metadata.dev(), metadata.ino()));
        self.file = Some(file);
        Ok(())
    }

    fn discard_to_end(&mut self) -> io::Result<()> {
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        let end = file.metadata()?.len();
        file.seek(SeekFrom::Start(end))?;
        self.offset = end;
        self.line_start = end;
        self.pending.clear();
        self.at_end = true;
        Ok(())
    }

    fn consume(&mut self, bytes: &[u8], visit: &mut impl FnMut(Record)) {
        let chunk_start = self.offset - bytes.len() as u64;
        for (index, &byte) in bytes.iter().enumerate() {
            let count_decisions = self.line_start >= self.decisions_after;
            if byte == b'\n' {
                let result = parse_line(&self.pending, &mut |record| {
                    if count_decisions
                        || matches!(record, Record::WorkloadStarted(_) | Record::BoxStopped(_))
                    {
                        visit(record);
                    }
                });
                if count_decisions && result.is_err() {
                    self.valid = false;
                }
                self.pending.clear();
                self.line_start = chunk_start + index as u64 + 1;
            } else {
                self.pending.push(byte);
            }
        }
    }
}

fn attribute<'a>(attributes: &'a Value, key: &str) -> Result<Option<&'a str>, ()> {
    let mut value = None;
    for attribute in attributes.as_array().ok_or(())? {
        if attribute["key"].as_str() == Some(key) {
            if value.is_some() {
                return Err(());
            }
            let text = attribute["value"]["stringValue"].as_str().ok_or(())?;
            if text.len() > ATTRIBUTE_LIMIT {
                return Err(());
            }
            value = Some(text);
        }
    }
    Ok(value)
}

fn parse_line(bytes: &[u8], visit: &mut impl FnMut(Record)) -> Result<(), ()> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    let Some(resources) = object.get("resourceLogs") else {
        return Ok(());
    };
    let mut valid = true;
    for resource in resources.as_array().ok_or(())? {
        let attributes = &resource["resource"]["attributes"];
        if attribute(attributes, "strands.box.source")? != Some("box")
            || attribute(attributes, "service.name") != Ok(Some("strands-box"))
        {
            continue;
        }
        for scope in resource["scopeLogs"].as_array().ok_or(())? {
            let scope_name = scope["scope"]["name"].as_str();
            if !matches!(
                scope_name,
                Some("strands-box.control" | "strands-box.policy")
            ) {
                continue;
            }
            let Some(records) = scope["logRecords"].as_array() else {
                valid = false;
                continue;
            };
            for record in records {
                if parse_record(scope_name, record, visit).is_err() {
                    valid = false;
                }
            }
        }
    }
    if valid { Ok(()) } else { Err(()) }
}

fn parse_record(
    scope: Option<&str>,
    record: &Value,
    visit: &mut impl FnMut(Record),
) -> Result<(), ()> {
    let attributes = &record["attributes"];
    if scope == Some("strands-box.control") {
        let operation = attribute(attributes, "strands.box.control.operation")?;
        if !matches!(operation, Some("workload_started" | "box_stopped")) {
            return Ok(());
        }
        match (
            operation,
            attribute(attributes, "strands.box.control.outcome")?,
        ) {
            (Some("workload_started"), Some("ok")) => {
                visit(Record::WorkloadStarted(timestamp(record)));
            }
            (Some("box_stopped"), Some("ok")) => {
                visit(Record::BoxStopped(CoreOutcome::Ok));
            }
            (Some("box_stopped"), Some("refused")) => {
                visit(Record::BoxStopped(CoreOutcome::Refused));
            }
            _ => {}
        }
        return Ok(());
    }
    if record["eventName"].as_str() != Some("strands.box.policy.decision") {
        return Ok(());
    }
    let action = attribute(attributes, "strands.box.policy.action")?
        .filter(|s| !s.is_empty())
        .ok_or(())?;
    let category = attribute(attributes, "strands.box.policy.category")?
        .filter(|s| !s.is_empty())
        .ok_or(())?;
    let verdict = match attribute(attributes, "strands.box.policy.verdict")? {
        Some("permit") => Verdict::Permit,
        Some("deny") => Verdict::Deny,
        _ => return Err(()),
    };
    let cause = attribute(attributes, "strands.box.policy.cause")?;
    visit(Record::Decision(Decision {
        action: action.into(),
        category: category.into(),
        verdict,
        cause: cause.map(str::to_owned),
    }));
    Ok(())
}

fn timestamp(record: &Value) -> Option<SystemTime> {
    let text = record["timeUnixNano"].as_str()?;
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let nanos: u64 = text.parse().ok()?;
    if nanos == 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_nanos(nanos))
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::symlink;

    use serde_json::{Value, json};

    use super::*;

    fn record() -> Value {
        json!({"resourceLogs": [{
            "resource": {"attributes": [
                {"key":"service.name", "value":{"stringValue":"strands-box"}},
                {"key":"strands.box.source", "value":{"stringValue":"box"}}
            ]},
            "scopeLogs": [{
                "scope":{"name":"strands-box.control"},
                "logRecords":[{
                    "timeUnixNano":"1794528000123456789",
                    "observedTimeUnixNano":"1794528009987654321",
                    "attributes":[
                        {"key":"strands.box.control.operation", "value":{"stringValue":"workload_started"}},
                        {"key":"strands.box.control.outcome", "value":{"stringValue":"ok"}}
                    ]
                }]
            }]
        }]})
    }

    fn started() -> Record {
        Record::WorkloadStarted(Some(UNIX_EPOCH + Duration::new(1_794_528_000, 123_456_789)))
    }

    fn stopped(outcome: &str) -> Value {
        let mut value = record();
        let attributes =
            &mut value["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"];
        attributes[0]["value"]["stringValue"] = json!("box_stopped");
        attributes[1]["value"]["stringValue"] = json!(outcome);
        value
    }

    fn append(path: &Path, bytes: &[u8]) {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    fn line(value: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn collect(journal: &mut Journal) -> Vec<Record> {
        let mut records = Vec::new();
        journal.read(|record| records.push(record));
        records
    }

    #[test]
    fn only_new_core_lifecycle_logs_supply_evidence() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let records = [record(), stopped("ok"), stopped("refused")];
        for value in &records {
            append(&path, &line(value));
        }
        let mut journal = Journal::start(&path).unwrap();
        for value in &records {
            for (pointer, other) in [
                (
                    "/resourceLogs/0/resource/attributes/1/value/stringValue",
                    "agent",
                ),
                (
                    "/resourceLogs/0/resource/attributes/0/value/stringValue",
                    "other",
                ),
                (
                    "/resourceLogs/0/scopeLogs/0/scope/name",
                    "strands-box.policy",
                ),
                (
                    "/resourceLogs/0/scopeLogs/0/logRecords/0/attributes/0/value/stringValue",
                    "unrelated",
                ),
                (
                    "/resourceLogs/0/scopeLogs/0/logRecords/0/attributes/1/value/stringValue",
                    "error",
                ),
            ] {
                let mut invalid = value.clone();
                *invalid.pointer_mut(pointer).unwrap() = json!(other);
                append(&path, &line(&invalid));
            }
            let mut relayed = value.clone();
            relayed["resourceLogs"][0]["resource"]["attributes"][1]["value"]["stringValue"] =
                json!("agent");
            relayed["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"] =
                json!({"stringValue":serde_json::to_string(value).unwrap()});
            append(&path, &line(&relayed));
        }
        append(&path, &line(&json!({"resourceSpans": []})));
        for value in &records {
            append(&path, &line(value));
        }
        assert_eq!(
            collect(&mut journal),
            vec![
                started(),
                Record::BoxStopped(CoreOutcome::Ok),
                Record::BoxStopped(CoreOutcome::Refused),
            ]
        );
        assert!(collect(&mut journal).is_empty());
        assert!(journal.at_end());
    }

    #[test]
    fn missing_or_invalid_source_timestamps_preserve_confirmed_startup() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let mut journal = Journal::start(&path).unwrap();
        let mut absent = record();
        absent["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
            .as_object_mut()
            .unwrap()
            .remove("timeUnixNano");
        append(&path, &line(&absent));
        assert_eq!(collect(&mut journal), vec![Record::WorkloadStarted(None)]);
        for timestamp in [
            json!(null),
            json!(""),
            json!("invalid"),
            json!("0"),
            json!("-1"),
            json!("+1"),
            json!(" 1"),
            json!("1.5"),
            json!("18446744073709551616"),
            json!(1794528000123456789u64),
        ] {
            let mut value = record();
            value["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["timeUnixNano"] = timestamp;
            append(&path, &line(&value));
            assert_eq!(collect(&mut journal), vec![Record::WorkloadStarted(None)]);
        }
        for nanos in [1, u64::MAX] {
            let mut value = record();
            value["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["timeUnixNano"] =
                json!(nanos.to_string());
            append(&path, &line(&value));
            assert_eq!(
                collect(&mut journal),
                vec![Record::WorkloadStarted(Some(
                    UNIX_EPOCH + Duration::from_nanos(nanos)
                ))]
            );
        }
    }

    #[test]
    fn partial_records_complete_once_and_old_fragments_do_not_hide_new_records() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        fs::write(&path, []).unwrap();
        let bytes = line(&record());
        let split = bytes.len() / 2;
        let mut journal = Journal::start(&path).unwrap();
        append(&path, &bytes[..split]);
        assert!(collect(&mut journal).is_empty());
        append(&path, &bytes[split..]);
        assert_eq!(collect(&mut journal), vec![started()]);
        assert!(collect(&mut journal).is_empty());
        for fragment in [b"{}".as_slice(), &bytes[..split], &bytes[..bytes.len() - 1]] {
            append(&path, fragment);
            let mut later = Journal::start(&path).unwrap();
            append(&path, &bytes);
            assert_eq!(collect(&mut later), vec![started()]);
            assert!(collect(&mut later).is_empty());
        }
        append(&path, &bytes[..split]);
        let mut later = Journal::start(&path).unwrap();
        append(&path, &bytes[split..]);
        assert!(collect(&mut later).is_empty());
        append(&path, &bytes);
        assert_eq!(collect(&mut later), vec![started()]);
    }

    #[test]
    fn a_missing_journal_can_supply_evidence_after_it_appears() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let mut journal = Journal::start(&path).unwrap();
        assert!(collect(&mut journal).is_empty());
        assert!(journal.at_end());
        append(&path, &line(&record()));
        assert_eq!(collect(&mut journal), vec![started()]);
    }

    #[test]
    fn malformed_records_supply_no_lifecycle_evidence_or_block_later_records() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let mut journal = Journal::start(&path).unwrap();
        for value in [record(), stopped("ok"), stopped("refused")] {
            let mut duplicate = value.clone();
            let attrs = duplicate["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
                .as_array_mut()
                .unwrap();
            attrs.push(attrs[1].clone());
            let mut absent = value.clone();
            absent["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
                .as_array_mut()
                .unwrap()
                .pop();
            let mut wrong_type = value.clone();
            wrong_type["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"][1]["value"] =
                json!({"intValue":1});
            let mut long = value;
            long["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"][0]["value"]["stringValue"] =
                json!("x".repeat(1025));
            for bytes in [
                b"not JSON\n".to_vec(),
                line(&duplicate),
                line(&absent),
                line(&wrong_type),
                line(&long),
            ] {
                append(&path, &bytes);
                assert!(collect(&mut journal).is_empty());
            }
        }
        append(&path, &line(&record()));
        assert_eq!(collect(&mut journal), vec![started()]);
    }

    #[test]
    fn linked_nonregular_replaced_removed_and_truncated_journals_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let link = root.path().join("link");
        fs::write(&path, b"{}\n").unwrap();
        symlink(&path, &link).unwrap();
        assert!(Journal::start(&link).is_err());
        assert!(Journal::start(root.path()).is_err());
        let fifo = root.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || sender.send(Journal::start(&fifo).is_err()).unwrap());
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap()
        );
        for change in [0, 1, 2] {
            fs::write(&path, b"{}\n").unwrap();
            let mut journal = Journal::start(&path).unwrap();
            match change {
                0 => {
                    let old = root.path().join("old");
                    fs::rename(&path, &old).unwrap();
                    append(&old, &line(&record()));
                    append(&path, &line(&record()));
                }
                1 => fs::write(&path, []).unwrap(),
                _ => fs::remove_file(&path).unwrap(),
            }
            assert!(collect(&mut journal).is_empty());
            if change == 1 {
                append(&path, b"{}\n");
            }
            append(&path, &line(&record()));
            assert!(collect(&mut journal).is_empty());
            assert!(journal.at_end());
        }
    }

    #[test]
    fn reads_are_bounded_without_losing_later_startup_evidence() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let mut journal = Journal::start(&path).unwrap();
        append(&path, &b"{}\n".repeat(READ_LIMIT / 3 + 1));
        append(&path, &line(&record()));
        assert!(collect(&mut journal).is_empty());
        assert!(!journal.at_end());
        assert_eq!(collect(&mut journal), vec![started()]);
        assert!(journal.at_end());
    }

    fn policy_record() -> Value {
        json!({"resourceLogs": [{
            "resource": {"attributes": [
                {"key":"service.name", "value":{"stringValue":"strands-box"}},
                {"key":"strands.box.source", "value":{"stringValue":"box"}},
                {"key":"strands.box.run.id", "value":{"stringValue":"1234"}}
            ]},
            "scopeLogs": [{
                "scope":{"name":"strands-box.policy"},
                "logRecords":[{
                    "eventName":"strands.box.policy.decision",
                    "attributes":[
                        {"key":"strands.box.policy.action", "value":{"stringValue":"fs:read"}},
                        {"key":"strands.box.policy.category", "value":{"stringValue":"fs"}},
                        {"key":"strands.box.policy.verdict", "value":{"stringValue":"permit"}},
                        {"key":"strands.box.policy.cause", "value":{"stringValue":"enforcement"}}
                    ]
                }]
            }]
        }]})
    }

    fn collect_decisions(journal: &mut Journal) -> Vec<Decision> {
        let mut decisions = Vec::new();
        journal.read(|record| {
            if let Record::Decision(decision) = record {
                decisions.push(decision);
            }
        });
        decisions
    }

    #[test]
    fn large_core_batches_complete_once_across_bounded_reads() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let mut journal = Journal::start(&path).unwrap();
        let mut batch = policy_record();
        let decision = batch["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0].clone();
        batch["resourceLogs"][0]["scopeLogs"][0]["logRecords"] = json!(vec![decision; 4096]);
        let bytes = line(&batch);
        assert!(bytes.len() > READ_LIMIT);
        append(&path, &bytes);

        assert!(collect_decisions(&mut journal).is_empty());
        assert_eq!(journal.offset, READ_LIMIT as u64);
        assert!(!journal.at_end());
        let mut decisions = Vec::new();
        for _ in 0..bytes.len().div_ceil(READ_LIMIT) {
            decisions.extend(collect_decisions(&mut journal));
        }
        assert_eq!(decisions.len(), 4096);
        assert!(decisions.iter().all(|decision| {
            decision.action == "fs:read"
                && decision.category == "fs"
                && decision.verdict == Verdict::Permit
                && decision.cause.as_deref() == Some("enforcement")
        }));
        assert!(journal.at_end());
        assert!(journal.finish_interval());
        assert!(collect_decisions(&mut journal).is_empty());
    }

    #[test]
    fn large_unrelated_batches_do_not_invalidate_policy_counts() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let mut journal = Journal::start(&path).unwrap();
        let mut agent = policy_record();
        agent["resourceLogs"][0]["resource"]["attributes"][1]["value"]["stringValue"] =
            json!("agent");
        agent["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"] =
            json!({"stringValue": "x".repeat(300 * 1024)});
        let spans = json!({"resourceSpans": [{
            "scopeSpans": [{"spans": [{"name": "x".repeat(300 * 1024)}]}]
        }]});

        for batch in [spans, agent] {
            append(&path, &line(&batch));
            append(&path, &line(&policy_record()));
            assert_eq!(collect_decisions(&mut journal).len(), 1);
            assert!(journal.finish_interval());
        }
    }

    #[test]
    fn large_incomplete_batches_preserve_lifecycle_without_recounting_decisions() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let mut journal = Journal::start(&path).unwrap();
        let mut batch = record();
        let scopes = batch["resourceLogs"][0]["scopeLogs"]
            .as_array_mut()
            .unwrap();
        scopes.push(stopped("ok")["resourceLogs"][0]["scopeLogs"][0].clone());
        scopes.push(policy_record()["resourceLogs"][0]["scopeLogs"][0].clone());
        batch["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"] =
            json!({"stringValue": "x".repeat(300 * 1024)});
        let bytes = line(&batch);
        append(&path, &bytes[..bytes.len() - 1]);
        assert!(collect(&mut journal).is_empty());
        assert!(!journal.finish_interval());

        append(&path, b"\n");
        append(&path, &line(&policy_record()));
        assert_eq!(
            collect(&mut journal),
            vec![
                started(),
                Record::BoxStopped(CoreOutcome::Ok),
                Record::Decision(Decision {
                    action: "fs:read".into(),
                    category: "fs".into(),
                    verdict: Verdict::Permit,
                    cause: Some("enforcement".into()),
                }),
            ]
        );
        assert!(journal.finish_interval());
        assert!(collect(&mut journal).is_empty());
    }

    #[test]
    fn polling_boundaries_preserve_lifecycle_evidence_and_exclude_old_decisions() {
        for partial in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("journal");
            fs::write(&path, []).unwrap();
            let mut journal = Journal::start(&path).unwrap();
            let mut mixed = record();
            mixed["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
                .as_array_mut()
                .unwrap()
                .extend(["ok", "refused"].map(|outcome| {
                    stopped(outcome)["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0].clone()
                }));
            mixed["resourceLogs"][0]["scopeLogs"]
                .as_array_mut()
                .unwrap()
                .push(policy_record()["resourceLogs"][0]["scopeLogs"][0].clone());
            let bytes = line(&mixed);
            let split = bytes.len() / 2;
            if partial {
                append(&path, &bytes[..split]);
            } else {
                append(&path, &b"{}\n".repeat(READ_LIMIT / 3 + 1));
                append(&path, &bytes);
            }
            assert!(collect(&mut journal).is_empty());
            assert!(!journal.finish_interval());
            if partial {
                append(&path, &bytes[split..]);
            }
            append(&path, &line(&policy_record()));
            assert_eq!(
                collect(&mut journal),
                vec![
                    started(),
                    Record::BoxStopped(CoreOutcome::Ok),
                    Record::BoxStopped(CoreOutcome::Refused),
                    Record::Decision(Decision {
                        action: "fs:read".into(),
                        category: "fs".into(),
                        verdict: Verdict::Permit,
                        cause: Some("enforcement".into()),
                    }),
                ]
            );
            assert!(journal.finish_interval());
        }
    }

    #[test]
    fn malformed_policy_records_do_not_hide_later_lifecycle_evidence() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let mut journal = Journal::start(&path).unwrap();
        let mut mixed = policy_record();
        mixed["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"][2]["value"]["stringValue"] =
            json!("invalid");
        mixed["resourceLogs"][0]["scopeLogs"]
            .as_array_mut()
            .unwrap()
            .extend(
                [record(), stopped("ok"), stopped("refused")]
                    .map(|value| value["resourceLogs"][0]["scopeLogs"][0].clone()),
            );
        append(&path, &line(&mixed));
        assert_eq!(
            collect(&mut journal),
            vec![
                started(),
                Record::BoxStopped(CoreOutcome::Ok),
                Record::BoxStopped(CoreOutcome::Refused),
            ]
        );
        assert!(!journal.finish_interval());
    }

    #[test]
    fn only_new_core_policy_logs_are_counted_once() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        append(&path, &line(&policy_record()));
        let mut journal = Journal::start(&path).unwrap();
        let mut agent = policy_record();
        agent["resourceLogs"][0]["resource"]["attributes"][1]["value"]["stringValue"] =
            json!("agent");
        let mut other_service = policy_record();
        other_service["resourceLogs"][0]["resource"]["attributes"][0]["value"]["stringValue"] =
            json!("other");
        let mut other_scope = policy_record();
        other_scope["resourceLogs"][0]["scopeLogs"][0]["scope"]["name"] = json!("other");
        let mut other_event = policy_record();
        other_event["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["eventName"] =
            json!("other");
        for mut value in [agent, other_service, other_scope, other_event] {
            value["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"][0]["value"]["stringValue"] =
                json!("excluded");
            append(&path, &line(&value));
        }
        append(&path, &line(&json!({"resourceSpans": []})));
        append(&path, &line(&policy_record()));
        assert_eq!(
            collect_decisions(&mut journal),
            vec![Decision {
                action: "fs:read".into(),
                category: "fs".into(),
                verdict: Verdict::Permit,
                cause: Some("enforcement".into()),
            }]
        );
        assert!(collect_decisions(&mut journal).is_empty());
        assert!(journal.finish_interval());
    }

    #[test]
    fn partial_writes_complete_once_and_incomplete_boundary_fragments_are_discarded() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        fs::write(&path, []).unwrap();
        let bytes = line(&policy_record());
        let split = bytes.len() / 2;
        let mut journal = Journal::start(&path).unwrap();
        append(&path, &bytes[..split]);
        assert!(collect_decisions(&mut journal).is_empty());
        append(&path, &bytes[split..]);
        assert_eq!(collect_decisions(&mut journal).len(), 1);
        assert!(journal.finish_interval());
        append(&path, &bytes[..split]);
        assert!(collect_decisions(&mut journal).is_empty());
        assert!(!journal.finish_interval());
        append(&path, &bytes[split..]);
        append(&path, &bytes);
        assert_eq!(collect_decisions(&mut journal).len(), 1);
        assert!(journal.finish_interval());
        for fragment in [b"{}".as_slice(), &bytes[..split], &bytes[..bytes.len() - 1]] {
            append(&path, fragment);
            let mut later = Journal::start(&path).unwrap();
            append(&path, &bytes);
            assert_eq!(collect_decisions(&mut later).len(), 1);
            assert!(later.finish_interval());
        }
        append(&path, &bytes[..split]);
        let mut later = Journal::start(&path).unwrap();
        append(&path, &bytes[split..]);
        append(&path, &bytes);
        assert_eq!(collect_decisions(&mut later).len(), 1);
        assert!(!later.finish_interval());
        append(&path, &bytes);
        assert_eq!(collect_decisions(&mut later).len(), 1);
        assert!(later.finish_interval());
    }

    #[test]
    fn a_missing_journal_is_unknown_until_it_exists_and_then_starts_at_zero() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let mut journal = Journal::start(&path).unwrap();
        assert!(collect_decisions(&mut journal).is_empty());
        assert!(!journal.finish_interval());
        append(&path, &line(&policy_record()));
        assert_eq!(collect_decisions(&mut journal).len(), 1);
        assert!(journal.finish_interval());
    }

    #[test]
    fn malformed_records_invalidate_only_their_interval() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        fs::write(&path, []).unwrap();
        let mut journal = Journal::start(&path).unwrap();
        let mut invalid_verdict = policy_record();
        invalid_verdict["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"][2]["value"]
            ["stringValue"] = json!("maybe");
        let mut duplicate = policy_record();
        let attrs = duplicate["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
            .as_array_mut()
            .unwrap();
        attrs.push(attrs[2].clone());
        let mut absent_action = policy_record();
        absent_action["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        let mut long_action = policy_record();
        long_action["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"][0]["value"]
            ["stringValue"] = json!("x".repeat(1025));
        for bytes in [
            b"not JSON\n".to_vec(),
            line(&invalid_verdict),
            line(&duplicate),
            line(&absent_action),
            line(&long_action),
        ] {
            append(&path, &bytes);
            assert!(collect_decisions(&mut journal).is_empty());
            assert!(!journal.finish_interval());
            append(&path, &line(&policy_record()));
            assert_eq!(collect_decisions(&mut journal).len(), 1);
            assert!(journal.finish_interval());
        }
    }

    #[test]
    fn a_denial_retains_an_unknown_or_absent_cause_for_classification() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        fs::write(&path, []).unwrap();
        let mut journal = Journal::start(&path).unwrap();
        let mut denial = policy_record();
        let attrs = denial["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
            .as_array_mut()
            .unwrap();
        attrs[2]["value"]["stringValue"] = json!("deny");
        attrs[3]["value"]["stringValue"] = json!("future_cause");
        append(&path, &line(&denial));
        denial["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
            .as_array_mut()
            .unwrap()
            .pop();
        append(&path, &line(&denial));
        let decisions = collect_decisions(&mut journal);
        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].verdict, Verdict::Deny);
        assert_eq!(decisions[0].cause.as_deref(), Some("future_cause"));
        assert_eq!(decisions[1].verdict, Verdict::Deny);
        assert_eq!(decisions[1].cause, None);
        assert!(journal.finish_interval());
    }

    #[test]
    fn unread_backlogs_are_bounded_and_discarded_at_the_boundary() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        fs::write(&path, []).unwrap();
        let mut journal = Journal::start(&path).unwrap();
        append(&path, &b"{}\n".repeat(READ_LIMIT / 3 + 1));
        append(&path, &line(&policy_record()));
        assert!(collect_decisions(&mut journal).is_empty());
        assert!(!journal.finish_interval());
        append(&path, &line(&policy_record()));
        assert_eq!(collect_decisions(&mut journal).len(), 1);
        assert!(journal.finish_interval());
    }

    #[test]
    fn non_core_service_attributes_do_not_invalidate_policy_counts() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        let mut journal = Journal::start(&path).unwrap();
        for source in ["agent", "box"] {
            for values in [
                vec![json!({"intValue":"7"})],
                vec![
                    json!({"stringValue":"strands-box"}),
                    json!({"stringValue":"strands-box"}),
                ],
                vec![json!({"stringValue":"x".repeat(2000)})],
            ] {
                let mut unrelated = policy_record();
                let mut attributes: Vec<Value> = values
                    .into_iter()
                    .map(|value| json!({"key":"service.name", "value":value}))
                    .collect();
                attributes.push(json!({
                    "key":"strands.box.source", "value":{"stringValue":source}
                }));
                unrelated["resourceLogs"][0]["resource"]["attributes"] = json!(attributes);
                let mut batch = policy_record();
                batch["resourceLogs"]
                    .as_array_mut()
                    .unwrap()
                    .insert(0, unrelated["resourceLogs"][0].clone());
                append(&path, &line(&batch));
                assert_eq!(collect_decisions(&mut journal).len(), 1, "{source}");
                assert!(journal.finish_interval(), "{source}");
            }
        }
    }
}
