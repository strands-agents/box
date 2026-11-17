//! Compile legacy policies and validate caller-owned scratch stores through protocol version 1.
#![warn(missing_docs, unreachable_pub)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::path::Path;
use std::process::ExitCode;

use dogwood_language::{ParsedPolicySet, PolicySchema, ServiceSchema, Validator};
use dogwood_local_engine::{
    DurableConfig, DurableLog, DurableTemporalEngine, PolicyEntry, SnapshotPayload,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_MESSAGE: usize = 8 * 1024 * 1024;
const MAX_ERROR: usize = 64 * 1024;
const STDIN_DATABASE: &str = "/dev/fd/0";

#[derive(Debug, Error)]
enum Error {
    #[error("expected exactly one mode: describe, compile, checkpoint, or validate")]
    Arguments,
    #[error("{0}")]
    Refused(&'static str),
    #[error("legacy policy compilation failed: {0}")]
    Compile(String),
    #[error("legacy engine recovery failed: {0}")]
    Durable(String),
    #[error("scratch database operation failed: {0}")]
    Log(#[from] dogwood_local_engine::LogError),
    #[error("invalid snapshot: {0}")]
    Snapshot(String),
    #[error("protocol JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Describe,
    Compile,
    Checkpoint,
    Validate,
}

impl Mode {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self, Error> {
        let mode = match args.next().as_deref().and_then(|s| s.to_str()) {
            Some("describe") => Self::Describe,
            Some("compile") => Self::Compile,
            Some("checkpoint") => Self::Checkpoint,
            Some("validate") => Self::Validate,
            _ => return Err(Error::Arguments),
        };
        if args.next().is_some() {
            return Err(Error::Arguments);
        }
        Ok(mode)
    }
}

#[derive(Debug, Serialize)]
struct Version {
    protocol: u32,
    engine_version: &'static str,
    language_version: &'static str,
}

impl Version {
    fn legacy() -> Self {
        Self {
            protocol: 1,
            engine_version: "1.0.0",
            language_version: "1.0.0",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompileRequest {
    source: String,
    event_schema: String,
    action_schema: String,
}

#[derive(Debug, Serialize)]
struct Compiled {
    #[serde(flatten)]
    version: Version,
    statements: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Recovered {
    #[serde(flatten)]
    version: Version,
    policies: Vec<PolicyEntry>,
    next_id: u64,
    action_schema: String,
    last_ts: i64,
    offset: u64,
    engine_sha256: String,
}

/// Accumulate a complete response before writing any success bytes to stdout.
struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("protocol output exceeds its byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_response(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let mut output = BoundedBytes {
        bytes: Vec::new(),
        limit: MAX_MESSAGE,
    };
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")?;
    Ok(output.bytes)
}

fn read_request(input: impl Read) -> Result<CompileRequest, Error> {
    let mut bytes = Vec::new();
    input
        .take((MAX_MESSAGE + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(Error::Refused("compile input exceeds 8 MiB"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn compile(request: CompileRequest) -> Result<Compiled, Error> {
    let service = ServiceSchema::builder()
        .event_schema_str(&request.event_schema)
        .build()
        .map_err(|e| Error::Compile(e.to_string()))?;
    let schema = PolicySchema::from_cedarschema_str(&request.action_schema)
        .map_err(|e| Error::Compile(e.to_string()))?;
    let parsed = ParsedPolicySet::parse(&request.source, &service)
        .map_err(|e| Error::Compile(e.to_string()))?;
    if parsed.policies().any(|policy| policy.uses_providers()) {
        return Err(Error::Refused(
            "legacy migration does not support information providers",
        ));
    }
    let lowered = parsed
        .lower(&schema)
        .map_err(|e| Error::Compile(e.to_string()))?;
    // Dogwood's public validator always uses Cedar's strict mode.
    let validation = Validator::new().validate(&lowered);
    if let Some(error) = validation.validation_errors().next() {
        return Err(Error::Compile(error.to_string()));
    }
    Ok(Compiled {
        version: Version::legacy(),
        statements: parsed
            .policies()
            .map(|policy| policy.expanded_source())
            .collect(),
    })
}

fn check_file(file: &File) -> Result<(), Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(Error::Refused(
            "database stdin must be a nonempty regular scratch file",
        ));
    }
    Ok(())
}

/// Require a real snapshot with no surviving records available for recovery fallback.
fn snapshot_only(log: &DurableLog, end: u64) -> Result<SnapshotPayload, Error> {
    let snapshot = log
        .get_snapshot()?
        .ok_or(Error::Refused("scratch database has no snapshot"))?;
    if end == 0
        || log.base_offset() != end
        || snapshot.up_to_offset != end
        || log.next_offset() != end
    {
        return Err(Error::Refused(
            "validation requires base = snapshot offset = nonzero log end",
        ));
    }
    SnapshotPayload::decode(&snapshot.payload).map_err(Error::Snapshot)
}

fn recover(log: DurableLog, path: &Path, end: u64) -> Result<DurableTemporalEngine, Error> {
    let engine =
        DurableTemporalEngine::open_with_log_config(log, path.to_path_buf(), DurableConfig::new(0))
            .map_err(|error| Error::Durable(error.to_string()))?;
    if !engine.has_policy() || engine.log_offset() != end {
        return Err(Error::Refused(
            "recovery did not preserve the installed state and log end",
        ));
    }
    Ok(engine)
}

fn matches_engine(engine: &DurableTemporalEngine, payload: &SnapshotPayload) -> Result<(), Error> {
    let entries: Vec<_> = payload.bundle.policies.entries().cloned().collect();
    if engine.list() != entries
        || engine.action_schema().as_deref() != Some(&payload.bundle.action_schema)
    {
        return Err(Error::Refused(
            "recovered policies or action schema differ from the snapshot",
        ));
    }
    Ok(())
}

/// Operate only on the retained scratch descriptor supplied by the parent process.
fn database(file: &File, path: &Path, mode: Mode) -> Result<Recovered, Error> {
    check_file(file)?;
    let log = DurableLog::open(path)?;
    let end = log.next_offset();
    if mode == Mode::Validate {
        let payload = snapshot_only(&log, end)?;
        let engine = recover(log, path, end)?;
        matches_engine(&engine, &payload)?;
        drop(engine);
        let unchanged = snapshot_only(&DurableLog::open(path)?, end)?;
        if unchanged != payload {
            return Err(Error::Refused("validation changed the saved snapshot"));
        }
        return Ok(report(payload, end));
    }
    if mode != Mode::Checkpoint {
        return Err(Error::Arguments);
    }
    if log.base_offset() > end {
        return Err(Error::Refused("scratch log base exceeds its end"));
    }
    if let Some(snapshot) = log.get_snapshot()? {
        if snapshot.up_to_offset < log.base_offset() || snapshot.up_to_offset > end {
            return Err(Error::Refused(
                "scratch snapshot lies outside the retained log range",
            ));
        }
    } else if log.base_offset() != 0 {
        return Err(Error::Refused("pruned scratch database has no snapshot"));
    }
    let mut engine = recover(log, path, end)?;
    let policies = engine.list();
    let action_schema = engine.action_schema();
    if engine
        .checkpoint()
        .map_err(|error| Error::Durable(error.to_string()))?
        != end
        || engine.log_offset() != end
    {
        return Err(Error::Refused("checkpoint changed the log end"));
    }
    drop(engine);
    let log = DurableLog::open(path)?;
    let payload = snapshot_only(&log, end)?;
    if payload
        .bundle
        .policies
        .entries()
        .cloned()
        .collect::<Vec<_>>()
        != policies
        || action_schema.as_deref() != Some(&payload.bundle.action_schema)
    {
        return Err(Error::Refused(
            "checkpoint differs from the recovered policies or action schema",
        ));
    }
    // Pruning has removed full replay as an alternative to loading these exact monitor bytes.
    let engine = recover(log, path, end)?;
    matches_engine(&engine, &payload)?;
    drop(engine);
    if snapshot_only(&DurableLog::open(path)?, end)? != payload {
        return Err(Error::Refused(
            "checkpoint validation changed the saved snapshot",
        ));
    }
    Ok(report(payload, end))
}

fn report(payload: SnapshotPayload, offset: u64) -> Recovered {
    Recovered {
        version: Version::legacy(),
        policies: payload.bundle.policies.entries().cloned().collect(),
        next_id: payload.bundle.policies.next_id(),
        action_schema: payload.bundle.action_schema,
        last_ts: payload.last_ts,
        offset,
        engine_sha256: format!("{:x}", Sha256::digest(&payload.engine)),
    }
}

fn run() -> Result<(), Error> {
    let mode = Mode::parse(std::env::args_os().skip(1))?;
    let bytes = match mode {
        Mode::Describe => encode_response(&Version::legacy())?,
        Mode::Compile => encode_response(&compile(read_request(io::stdin().lock())?)?)?,
        Mode::Checkpoint | Mode::Validate => {
            let file = File::from(io::stdin().as_fd().try_clone_to_owned()?);
            encode_response(&database(&file, Path::new(STDIN_DATABASE), mode)?)?
        }
    };
    io::stdout().lock().write_all(&bytes)?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut output = BoundedBytes {
                bytes: Vec::new(),
                limit: MAX_ERROR - 1,
            };
            let _ = write!(&mut output, "{error}");
            // A rejected large Display fragment must still produce a useful bounded error.
            if output.bytes.is_empty() {
                output.bytes.extend_from_slice(
                    b"legacy migration refused: diagnostic exceeds its byte limit",
                );
            }
            output.bytes.push(b'\n');
            let _ = io::stderr().lock().write_all(&output.bytes);
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests;
