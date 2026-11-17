//! Explicit, descriptor-bound storage migration for published Dogwood 1.0.0 → 1.1.2.
//!
//! The caller must validate the semantic equivalence of every exact translation and
//! pass the same verified file used to open `original`. This module does not infer
//! authored intent or translate temporal binders. It never opens the original by
//! pathname, transfers its ownership, or falls back to empty history.
//!
//! Scratch files must be distinct, empty, private regular files. All scratch opens
//! use retained descriptor aliases. `&mut DurableLog` prevents another safe-Rust
//! borrower from writing through the same object during this operation. The caller
//! must also exclude independent file writers and keep the verified descriptor/log
//! association intact. Unknown original metadata is preserved by the final write set.

use dogwood_local_engine::{
    DurableConfig, DurableLog, DurableTemporalEngine, PolicyEntry, Record, Snapshot,
    SnapshotPayload, Write,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    os::fd::AsRawFd,
    os::unix::fs::{FileExt, MetadataExt},
    path::PathBuf,
};

pub(super) const RECEIPT_KEY: &str = "box.dogwood.storage-migration.receipt.v1";
const ENGINE_KEYS: [&str; 2] = ["dogwood_server_time_unit", "dogwood_server_service_schema"];
const RESERVED: [&str; 3] = ["snapshot", "next_offset", "base_offset"];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StatementTranslation {
    pub(super) old: String,
    pub(super) replacement: String,
}

/// Semantic approval is a caller responsibility. The core independently binds
/// these exact bytes and provenance to the observed store, snapshot, and marker.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationPlan {
    pub(super) migration_id: String,
    pub(super) from_version: String,
    pub(super) to_version: String,
    pub(super) provenance: String,
    pub(super) translations: Vec<StatementTranslation>,
    pub(super) expected_policies: Vec<PolicyEntry>,
    pub(super) application_metadata_key: String,
    pub(super) application_metadata_value: Vec<u8>,
}

/// Explicit bounds reject oversized inputs before mutation of the original store.
#[derive(Clone, Debug)]
pub(super) struct MigrationLimits {
    pub(super) max_image_bytes: u64,
    pub(super) max_record_bytes: usize,
    pub(super) max_records: usize,
    pub(super) max_snapshot_bytes: usize,
    pub(super) max_plan_bytes: usize,
}
impl Default for MigrationLimits {
    fn default() -> Self {
        Self {
            max_image_bytes: 1024 * 1024 * 1024,
            max_record_bytes: 256 * 1024 * 1024,
            max_records: 1_000_000,
            max_snapshot_bytes: 64 * 1024 * 1024,
            max_plan_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum Disposition {
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct MigrationReport {
    pub(super) disposition: Disposition,
    pub(super) migration_id: String,
    pub(super) plan_sha256: String,
    pub(super) source_capture_sha256: String,
    pub(super) source_metadata_sha256: String,
    pub(super) source_image_sha256: String,
    pub(super) snapshot_sha256: String,
    pub(super) original_base: u64,
    pub(super) original_next: u64,
    pub(super) record_count: usize,
    pub(super) translated_occurrences: usize,
    pub(super) source_device: u64,
    pub(super) source_inode: u64,
}

/// `commit_may_have_happened` requires reconciliation through the stored receipt;
/// callers must not assume rollback or retry under another migration identity.
#[derive(Debug, thiserror::Error)]
#[error("{stage}: {message}")]
pub(super) struct MigrationError {
    pub(super) stage: &'static str,
    pub(super) message: String,
    pub(super) commit_may_have_happened: bool,
}
type Result<T> = std::result::Result<T, MigrationError>;
pub(super) fn err(stage: &'static str, message: impl Into<String>) -> MigrationError {
    MigrationError {
        stage,
        message: message.into(),
        commit_may_have_happened: false,
    }
}
pub(super) fn at<T, E: fmt::Display>(
    stage: &'static str,
    value: std::result::Result<T, E>,
) -> Result<T> {
    value.map_err(|e| err(stage, e.to_string()))
}
pub(super) fn require(ok: bool, stage: &'static str, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(err(stage, message)) }
}
pub(super) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn field(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}
pub(super) fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/dev/fd/{}", file.as_raw_fd()))
}
pub(super) fn identity(file: &File) -> Result<(u64, u64)> {
    let m = at("file identity", file.metadata())?;
    require(m.is_file(), "file identity", "a regular file is required")?;
    Ok((m.dev(), m.ino()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SavedSnapshot {
    pub(super) up_to: u64,
    pub(super) payload: Vec<u8>,
}
impl SavedSnapshot {
    pub(super) fn sha(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.up_to.to_be_bytes());
        field(&mut h, &self.payload);
        format!("{:x}", h.finalize())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CapturedStore {
    pub(super) base: u64,
    pub(super) next: u64,
    pub(super) snapshot: Option<SavedSnapshot>,
    pub(super) records: Vec<(u64, Vec<u8>)>,
    pub(super) metadata: BTreeMap<String, Option<Vec<u8>>>,
}
impl CapturedStore {
    pub(super) fn metadata_sha(&self) -> String {
        let mut h = Sha256::new();
        for (k, v) in &self.metadata {
            field(&mut h, k.as_bytes());
            h.update([u8::from(v.is_some())]);
            if let Some(v) = v {
                field(&mut h, v);
            }
        }
        format!("{:x}", h.finalize())
    }
    pub(super) fn sha(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.base.to_be_bytes());
        h.update(self.next.to_be_bytes());
        field(&mut h, self.metadata_sha().as_bytes());
        if let Some(s) = &self.snapshot {
            h.update([1]);
            field(&mut h, s.sha().as_bytes());
        } else {
            h.update([0]);
        }
        for (offset, bytes) in &self.records {
            h.update(offset.to_be_bytes());
            field(&mut h, bytes);
        }
        format!("{:x}", h.finalize())
    }
}

fn capture(
    log: &DurableLog,
    plan: &MigrationPlan,
    limits: &MigrationLimits,
) -> Result<CapturedStore> {
    let base = log.base_offset();
    let next = log.next_offset();
    require(base <= next, "capture", "base exceeds log end")?;
    require(
        next - base <= limits.max_records as u64,
        "capture",
        "record count exceeds configured bound",
    )?;
    let snapshot = at("read snapshot", log.get_snapshot())?.map(|s| SavedSnapshot {
        up_to: s.up_to_offset,
        payload: s.payload,
    });
    if let Some(s) = &snapshot {
        require(
            s.payload.len() <= limits.max_snapshot_bytes,
            "capture",
            "snapshot exceeds configured bound",
        )?;
        require(
            base <= s.up_to && s.up_to <= next,
            "capture",
            "snapshot boundary does not cover the retained prefix",
        )?;
        at("decode snapshot", SnapshotPayload::decode(&s.payload))?;
    } else {
        require(base == 0, "capture", "pruned log has no snapshot")?;
    }
    let mut records = Vec::new();
    let mut total = 0usize;
    let mut failure = None;
    at(
        "scan records",
        log.scan_from(base, |offset, bytes| {
            if failure.is_some() {
                return;
            }
            let expected = base.checked_add(records.len() as u64);
            if expected != Some(offset) || offset >= next {
                failure =
                    Some("record offsets are missing or outside the captured range".to_string());
                return;
            }
            let Some(new_total) = total.checked_add(bytes.len()) else {
                failure = Some("record byte count overflow".to_string());
                return;
            };
            if records.len() >= limits.max_records || new_total > limits.max_record_bytes {
                failure = Some("record capture exceeds configured bound".to_string());
                return;
            }
            if let Err(e) = Record::decode(bytes) {
                failure = Some(format!("record {offset} is corrupt: {e}"));
                return;
            }
            records.push((offset, bytes.to_vec()));
            total = new_total;
        }),
    )?;
    if let Some(e) = failure {
        return Err(err("capture", e));
    }
    require(
        base.checked_add(records.len() as u64) == Some(next),
        "capture",
        "log end does not match the complete retained record range",
    )?;
    let mut metadata = BTreeMap::new();
    for key in ENGINE_KEYS
        .into_iter()
        .chain([RECEIPT_KEY, plan.application_metadata_key.as_str()])
    {
        metadata.insert(key.to_string(), at("read metadata", log.get_meta(key))?);
    }
    require(
        metadata[ENGINE_KEYS[0]].as_deref() == Some(b"nanos"),
        "capture",
        "unsupported or missing time unit metadata",
    )?;
    require(
        log.base_offset() == base && log.next_offset() == next,
        "capture",
        "source changed during capture",
    )?;
    Ok(CapturedStore {
        base,
        next,
        snapshot,
        records,
        metadata,
    })
}

/// Capture storage facts for the caller's separate authored-intent validation.
/// This does not fold management verbs: use the snapshot bundle plus records at
/// or after its boundary, or every record from zero when no snapshot exists.
pub(super) fn capture_plan_input(
    log: &DurableLog,
    application_metadata_key: &str,
    limits: &MigrationLimits,
) -> Result<CapturedStore> {
    require(
        !application_metadata_key.is_empty()
            && application_metadata_key != RECEIPT_KEY
            && !RESERVED.contains(&application_metadata_key)
            && !ENGINE_KEYS.contains(&application_metadata_key),
        "capture",
        "invalid application metadata key",
    )?;
    let plan = MigrationPlan {
        migration_id: "capture".into(),
        from_version: "1.0.0".into(),
        to_version: "1.1.2".into(),
        provenance: "capture only; no approval implied".into(),
        translations: vec![],
        expected_policies: vec![],
        application_metadata_key: application_metadata_key.into(),
        application_metadata_value: vec![],
    };
    capture(log, &plan, limits)
}
impl CapturedStore {
    /// Exact strings only; schema-aware interpretation remains the caller's job.
    pub(super) fn historical_statements(&self) -> Result<Vec<String>> {
        let mut statements = std::collections::BTreeSet::new();
        let replay_from = if self.base > 0 {
            let snap = self
                .snapshot
                .as_ref()
                .ok_or_else(|| err("capture", "pruned snapshot missing"))?;
            for e in at("decode snapshot", SnapshotPayload::decode(&snap.payload))?
                .bundle
                .policies
                .entries()
            {
                statements.insert(e.statement.clone());
            }
            snap.up_to
        } else {
            0
        };
        for (offset, bytes) in &self.records {
            if *offset < replay_from {
                continue;
            }
            match at("decode record", Record::decode(bytes))? {
                Record::Add { statement, .. } | Record::Update { statement, .. } => {
                    statements.insert(statement);
                }
                _ => (),
            }
        }
        Ok(statements.into_iter().collect())
    }
}

fn plan_hash(plan: &MigrationPlan, limits: &MigrationLimits) -> Result<String> {
    require(
        plan.from_version == "1.0.0" && plan.to_version == "1.1.2",
        "plan",
        "unsupported source or target version",
    )?;
    require(
        !plan.migration_id.is_empty()
            && plan.migration_id.len() <= 128
            && plan
                .migration_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "plan",
        "invalid migration ID",
    )?;
    require(
        !plan.provenance.trim().is_empty(),
        "plan",
        "explicit approval provenance is required",
    )?;
    let key = plan.application_metadata_key.as_str();
    require(
        !key.is_empty()
            && key.len() <= 256
            && !key.contains('\0')
            && key != RECEIPT_KEY
            && !RESERVED.contains(&key)
            && !ENGINE_KEYS.contains(&key),
        "plan",
        "application metadata key collides with reserved storage metadata",
    )?;
    let mut canonical = plan.clone();
    canonical.translations.sort_by(|a, b| a.old.cmp(&b.old));
    for (i, t) in canonical.translations.iter().enumerate() {
        require(
            !t.old.is_empty() && !t.replacement.is_empty() && t.old != t.replacement,
            "plan",
            "translation must contain distinct nonempty exact statements",
        )?;
        if i > 0 {
            require(
                canonical.translations[i - 1].old != t.old,
                "plan",
                "duplicate or ambiguous old statement",
            )?;
        }
    }
    let bytes = at("serialize plan", serde_json::to_vec(&canonical))?;
    require(
        bytes.len() <= limits.max_plan_bytes,
        "plan",
        "plan exceeds configured bound",
    )?;
    Ok(hash(&bytes))
}

pub(super) fn check_files(
    source: &File,
    a: &File,
    b: &File,
    limits: &MigrationLimits,
) -> Result<(u64, u64)> {
    let source_id = identity(source)?;
    let a_id = identity(a)?;
    let b_id = identity(b)?;
    require(
        source_id != a_id && source_id != b_id && a_id != b_id,
        "scratch files",
        "source and scratch files must not be aliases or hardlinks",
    )?;
    require(
        at("source metadata", source.metadata())?.len() <= limits.max_image_bytes,
        "scratch files",
        "source image exceeds configured bound",
    )?;
    for f in [a, b] {
        let m = at("scratch metadata", f.metadata())?;
        require(
            m.len() == 0 && m.nlink() == 1 && m.mode() & 0o077 == 0,
            "scratch files",
            "scratch files must be empty, private, and have one hardlink",
        )?;
    }
    Ok(source_id)
}

pub(super) fn image_hash(file: &File, max: u64) -> Result<(String, u64)> {
    let len = at("image metadata", file.metadata())?.len();
    require(len <= max, "image copy", "image exceeds configured bound")?;
    let mut h = Sha256::new();
    let mut offset = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    while offset < len {
        let wanted =
            usize::try_from((len - offset).min(buffer.len() as u64)).expect("bounded read");
        let read = at(
            "read verified image",
            file.read_at(&mut buffer[..wanted], offset),
        )?;
        require(read > 0, "image copy", "source image ended unexpectedly")?;
        h.update(&buffer[..read]);
        offset += read as u64;
    }
    require(
        at("image metadata", file.metadata())?.len() == len,
        "image copy",
        "image length changed",
    )?;
    Ok((format!("{:x}", h.finalize()), len))
}
pub(super) fn copy_image(source: &File, dest: &File, limits: &MigrationLimits) -> Result<String> {
    let (before, len) = image_hash(source, limits.max_image_bytes)?;
    at("truncate private scratch", dest.set_len(0))?;
    let mut offset = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    while offset < len {
        let wanted =
            usize::try_from((len - offset).min(buffer.len() as u64)).expect("bounded read");
        let read = at(
            "copy verified image",
            source.read_at(&mut buffer[..wanted], offset),
        )?;
        require(read > 0, "image copy", "source image ended unexpectedly")?;
        let mut written = 0;
        while written < read {
            let n = at(
                "write scratch image",
                dest.write_at(&buffer[written..read], offset + written as u64),
            )?;
            require(n > 0, "image copy", "scratch write made no progress")?;
            written += n;
        }
        offset += read as u64;
    }
    at("size scratch image", dest.set_len(len))?;
    at("sync scratch image", dest.sync_all())?;
    require(
        image_hash(source, limits.max_image_bytes)? == (before.clone(), len)
            && image_hash(dest, limits.max_image_bytes)? == (before.clone(), len),
        "image copy",
        "copied image does not match stable verified source",
    )?;
    Ok(before)
}
pub(super) fn scratch_log(file: &File) -> Result<DurableLog> {
    at("open scratch descriptor", DurableLog::open(fd_path(file)))
}
pub(super) fn recovered(
    log: DurableLog,
    file: &File,
    config: DurableConfig,
) -> Result<DurableTemporalEngine> {
    at(
        "recover scratch",
        DurableTemporalEngine::open_with_log_config(log, fd_path(file), config),
    )
}

fn replace(statement: &mut String, plan: &MigrationPlan, uses: &mut [usize]) {
    for (i, t) in plan.translations.iter().enumerate() {
        if statement == &t.old {
            *statement = t.replacement.clone();
            uses[i] += 1;
            return;
        }
    }
}
fn prepare_scratch(
    file: &File,
    copied: DurableLog,
    source: &CapturedStore,
    plan: &MigrationPlan,
    limits: &MigrationLimits,
) -> Result<usize> {
    let mut uses = vec![0; plan.translations.len()];
    if source.base == 0 {
        // Complete replay is selected deliberately; it is never an error fallback.
        // All retained offsets were verified contiguous from zero during capture.
        let mut output_records = Vec::with_capacity(source.records.len());
        let mut total = 0usize;
        for (offset, bytes) in &source.records {
            let old = at("decode historical record", Record::decode(bytes))?;
            let mut record = old.clone();
            match &mut record {
                Record::Add { statement, .. } | Record::Update { statement, .. } => {
                    replace(statement, plan, &mut uses)
                }
                _ => (),
            }
            let output = if record == old {
                bytes.clone()
            } else {
                record.encode()
            };
            total = total
                .checked_add(output.len())
                .ok_or_else(|| err("translated output bound", "byte count overflow"))?;
            require(
                total <= limits.max_record_bytes,
                "translated output bound",
                "translated records exceed configured byte bound",
            )?;
            output_records.push((*offset, output));
        }
        drop(copied);
        at("reset private scratch", file.set_len(0))?;
        let scratch = scratch_log(file)?;
        for key in ENGINE_KEYS {
            if let Some(value) = source.metadata[key].as_deref() {
                at(
                    "copy engine metadata",
                    scratch.commit(&[Write::Meta { key, value }]),
                )?;
            }
        }
        for (offset, output) in output_records {
            require(
                at("rebuild complete scratch", scratch.append(&output))? == offset,
                "rebuild complete scratch",
                "record offset changed",
            )?;
            require(
                at("scratch growth", file.metadata())?.len() <= limits.max_image_bytes,
                "scratch growth",
                "scratch image exceeds configured bound",
            )?;
        }
        drop(scratch);
    } else {
        // Covered retained records are not replayed after partial pruning.
        let original = source
            .snapshot
            .as_ref()
            .ok_or_else(|| err("prepare pruned scratch", "snapshot missing"))?;
        for (offset, bytes) in &source.records {
            if *offset < original.up_to {
                continue;
            }
            match at("decode suffix", Record::decode(bytes))? {
                Record::Add { statement, .. } | Record::Update { statement, .. } => require(
                    !plan.translations.iter().any(|t| t.old == statement),
                    "unsupported pruned suffix",
                    "a replayed Add/Update requires translation",
                )?,
                _ => (),
            }
        }
        let mut payload = at(
            "decode pruned snapshot",
            SnapshotPayload::decode(&original.payload),
        )?;
        let old_engine = payload.engine.clone();
        let old_ts = payload.last_ts;
        let old_schema = payload.bundle.action_schema.clone();
        let old_next = payload.bundle.policies.next_id();
        let entries: Vec<_> = payload.bundle.policies.entries().cloned().collect();
        for entry in &entries {
            let mut statement = entry.statement.clone();
            replace(&mut statement, plan, &mut uses);
            if statement != entry.statement {
                require(
                    payload
                        .bundle
                        .policies
                        .update_statement(entry.id, statement, entry.updated),
                    "prepare pruned scratch",
                    "policy disappeared",
                )?;
            }
        }
        require(
            payload.engine == old_engine
                && payload.last_ts == old_ts
                && payload.bundle.action_schema == old_schema
                && payload.bundle.policies.next_id() == old_next,
            "prepare pruned scratch",
            "state carrier changed unexpectedly",
        )?;
        let new_entries: Vec<_> = payload.bundle.policies.entries().collect();
        require(
            entries.len() == new_entries.len(),
            "prepare pruned scratch",
            "policy count changed",
        )?;
        for (a, b) in entries.iter().zip(new_entries) {
            require(
                a.id == b.id
                    && a.token == b.token
                    && a.created == b.created
                    && a.updated == b.updated,
                "prepare pruned scratch",
                "recorded policy identity changed",
            )?;
        }
        let transformed = Snapshot {
            up_to_offset: original.up_to,
            payload: at("encode transformed snapshot", payload.encode())?,
        };
        require(
            transformed.payload.len() <= limits.max_snapshot_bytes,
            "translated snapshot bound",
            "translated snapshot exceeds configured bound",
        )?;
        at(
            "write private transformed snapshot",
            copied.commit(&[Write::Snapshot(&transformed)]),
        )?;
        require(
            at("scratch growth", file.metadata())?.len() <= limits.max_image_bytes,
            "scratch growth",
            "scratch image exceeds configured bound",
        )?;
        drop(copied);
    }
    require(
        uses.iter().all(|n| *n > 0),
        "plan coverage",
        "an approved translation was not present in the captured store",
    )?;
    Ok(uses.iter().sum())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    format_version: u32,
    report: MigrationReport,
    application_key: String,
    application_sha256: String,
}

/// Verify the historical migration receipt and its application marker.
/// For a later checkpoint, this proves receipt/marker consistency and structural
/// boundaries, not current monitor-state validity. Normal recovery is still required.
pub(super) fn verify_application_receipt(
    log: &DurableLog,
    app_key: &str,
    app_bytes: &[u8],
) -> Result<MigrationReport> {
    let bytes = at("read migration receipt", log.get_meta(RECEIPT_KEY))?.ok_or_else(|| {
        err(
            "receipt verification",
            "storage migration receipt is missing",
        )
    })?;
    let receipt: Receipt = at("decode migration receipt", serde_json::from_slice(&bytes))?;
    require(
        receipt.format_version == 1
            && receipt.application_key == app_key
            && receipt.application_sha256 == hash(app_bytes),
        "receipt verification",
        "application metadata does not match the storage receipt",
    )?;
    require(
        at("read application marker", log.get_meta(app_key))?.as_deref() == Some(app_bytes),
        "receipt verification",
        "stored application marker differs",
    )?;
    let snapshot = at("read migrated snapshot", log.get_snapshot())?
        .ok_or_else(|| err("receipt verification", "migration snapshot missing"))?;
    require(
        log.base_offset() <= snapshot.up_to_offset
            && receipt.report.original_next <= snapshot.up_to_offset
            && snapshot.up_to_offset <= log.next_offset(),
        "receipt verification",
        "snapshot or log boundary regressed",
    )?;
    at(
        "decode migrated snapshot",
        SnapshotPayload::decode(&snapshot.payload),
    )?;
    if snapshot.up_to_offset == receipt.report.original_next {
        require(
            SavedSnapshot {
                up_to: snapshot.up_to_offset,
                payload: snapshot.payload,
            }
            .sha()
                == receipt.report.snapshot_sha256,
            "receipt verification",
            "original migration snapshot digest differs",
        )?;
    }
    Ok(receipt.report)
}

/// Apply one explicit migration while retaining the verified original log object.
/// No original write occurs until the final atomic snapshot-and-metadata commit.
/// The returned receipt describes observed bytes; it is not semantic approval.
pub(super) fn migrate(
    original: &mut DurableLog,
    verified_original: &File,
    scratch_prepare: &File,
    scratch_validate: &File,
    approved: &MigrationPlan,
    limits: &MigrationLimits,
) -> Result<MigrationReport> {
    migrate_observed(
        original,
        verified_original,
        scratch_prepare,
        scratch_validate,
        approved,
        limits,
        (|_| {}, || DurableConfig::new(0)),
    )
}
#[derive(Clone, Copy)]
enum CommitBoundary {
    Before,
    After,
}
fn migrate_observed(
    original: &mut DurableLog,
    verified_original: &File,
    scratch_prepare: &File,
    scratch_validate: &File,
    plan: &MigrationPlan,
    limits: &MigrationLimits,
    hooks: (impl FnMut(CommitBoundary), impl Fn() -> DurableConfig),
) -> Result<MigrationReport> {
    let (mut observe, make_config) = hooks;
    let plan_sha = plan_hash(plan, limits)?;
    let source_id = identity(verified_original)?;
    if at("read migration receipt", original.get_meta(RECEIPT_KEY))?.is_some() {
        let mut report = verify_application_receipt(
            original,
            &plan.application_metadata_key,
            &plan.application_metadata_value,
        )?;
        require(
            report.plan_sha256 == plan_sha,
            "idempotency",
            "an incompatible migration plan already completed",
        )?;
        capture(original, plan, limits)?;
        require(
            at("source metadata", verified_original.metadata())?.len() <= limits.max_image_bytes,
            "idempotency",
            "current image exceeds configured bound",
        )?;
        report.disposition = Disposition::AlreadyApplied;
        return Ok(report);
    }
    require(
        at(
            "read application marker",
            original.get_meta(&plan.application_metadata_key),
        )?
        .is_none(),
        "idempotency",
        "application marker exists without matching storage receipt",
    )?;
    require(
        source_id == check_files(verified_original, scratch_prepare, scratch_validate, limits)?,
        "file identity",
        "source identity changed",
    )?;
    let source = capture(original, plan, limits)?;
    let source_image = copy_image(verified_original, scratch_prepare, limits)?;
    let copied = scratch_log(scratch_prepare)?;
    require(
        capture(&copied, plan, limits)? == source,
        "verify copied source",
        "source descriptor image does not match the retained original log",
    )?;
    require(
        capture(original, plan, limits)? == source,
        "verify source stability",
        "original changed while copying",
    )?;
    let translated = prepare_scratch(scratch_prepare, copied, &source, plan, limits)?;
    let mut engine = recovered(
        scratch_log(scratch_prepare)?,
        scratch_prepare,
        make_config(),
    )?;
    require(
        engine.has_policy(),
        "prepare checkpoint",
        "recovered scratch has no installed policy",
    )?;
    let policies = engine.list();
    require(
        policies == plan.expected_policies,
        "approved policy identity",
        "recovered entries do not equal the exact approved policy set",
    )?;
    let leaf_keys = engine.leaf_keys();
    require(
        at("checkpoint scratch", engine.checkpoint())? == source.next,
        "checkpoint scratch",
        "checkpoint advanced the source offset",
    )?;
    drop(engine);
    require(
        at("scratch growth", scratch_prepare.metadata())?.len() <= limits.max_image_bytes,
        "scratch growth",
        "checkpoint scratch exceeds configured bound",
    )?;
    let prepared = scratch_log(scratch_prepare)?;
    require(
        prepared.next_offset() == source.next,
        "checkpoint scratch",
        "scratch log end changed",
    )?;
    let snapshot = at("read prepared snapshot", prepared.get_snapshot())?.ok_or_else(|| {
        err(
            "checkpoint scratch",
            "checkpoint did not produce a snapshot",
        )
    })?;
    require(
        snapshot.up_to_offset == source.next,
        "checkpoint scratch",
        "snapshot does not cover exactly the source log end",
    )?;
    require(
        snapshot.payload.len() <= limits.max_snapshot_bytes,
        "checkpoint scratch",
        "prepared snapshot exceeds configured bound",
    )?;
    at(
        "decode prepared snapshot",
        SnapshotPayload::decode(&snapshot.payload),
    )?;
    drop(prepared);
    // A second descriptor-bound copy validates the exact proposed commit against
    // the original record stream, including its unmodified legacy statements.
    require(
        copy_image(verified_original, scratch_validate, limits)? == source_image,
        "verify source stability",
        "source image changed before validation",
    )?;
    let validation = scratch_log(scratch_validate)?;
    require(
        capture(&validation, plan, limits)? == source,
        "verify validation copy",
        "second copy does not match original",
    )?;
    at(
        "write candidate validation snapshot",
        validation.commit(&[Write::Snapshot(&snapshot)]),
    )?;
    // Force use of this snapshot: a complete-log fallback must not mask failure.
    loop {
        let pruned = at(
            "prune validation copy",
            validation.prune_below(snapshot.up_to_offset, 4096),
        )?;
        if pruned.done {
            break;
        }
    }
    require(
        validation.base_offset() == snapshot.up_to_offset
            && validation.next_offset() == source.next,
        "validate snapshot",
        "validation offsets differ",
    )?;
    require(
        at("scratch growth", scratch_validate.metadata())?.len() <= limits.max_image_bytes,
        "scratch growth",
        "validation scratch exceeds configured bound",
    )?;
    let check = recovered(validation, scratch_validate, make_config())?;
    require(
        check.has_policy() && check.list() == policies && check.leaf_keys() == leaf_keys,
        "validate snapshot",
        "recovered snapshot policy or temporal leaf identity differs",
    )?;
    drop(check);
    require(
        capture(original, plan, limits)? == source,
        "precommit verification",
        "original changed during preparation",
    )?;
    require(
        identity(verified_original)? == source_id
            && image_hash(verified_original, limits.max_image_bytes)?.0 == source_image,
        "precommit verification",
        "verified original image changed",
    )?;
    let report = MigrationReport {
        disposition: Disposition::Applied,
        migration_id: plan.migration_id.clone(),
        plan_sha256: plan_sha,
        source_capture_sha256: source.sha(),
        source_metadata_sha256: source.metadata_sha(),
        source_image_sha256: source_image,
        snapshot_sha256: SavedSnapshot {
            up_to: snapshot.up_to_offset,
            payload: snapshot.payload.clone(),
        }
        .sha(),
        original_base: source.base,
        original_next: source.next,
        record_count: source.records.len(),
        translated_occurrences: translated,
        source_device: source_id.0,
        source_inode: source_id.1,
    };
    let receipt = Receipt {
        format_version: 1,
        report: report.clone(),
        application_key: plan.application_metadata_key.clone(),
        application_sha256: hash(&plan.application_metadata_value),
    };
    let marker = at("serialize migration receipt", serde_json::to_vec(&receipt))?;
    observe(CommitBoundary::Before);
    if let Err(e) = original.commit(&[
        Write::Snapshot(&snapshot),
        Write::Meta {
            key: RECEIPT_KEY,
            value: &marker,
        },
        Write::Meta {
            key: &plan.application_metadata_key,
            value: &plan.application_metadata_value,
        },
    ]) {
        return Err(MigrationError {
            stage: "publish migration",
            message: e.to_string(),
            commit_may_have_happened: true,
        });
    }
    observe(CommitBoundary::After);
    let verify = (|| {
        let after = capture(original, plan, limits)?;
        require(
            after.base == source.base
                && after.next == source.next
                && after.records == source.records,
            "commit readback",
            "original record stream changed",
        )?;
        for key in ENGINE_KEYS {
            require(
                after.metadata[key] == source.metadata[key],
                "commit readback",
                "engine metadata changed",
            )?;
        }
        require(
            after.snapshot
                == Some(SavedSnapshot {
                    up_to: snapshot.up_to_offset,
                    payload: snapshot.payload.clone(),
                }),
            "commit readback",
            "committed snapshot differs",
        )?;
        require(
            after.metadata[RECEIPT_KEY].as_deref() == Some(marker.as_slice())
                && after.metadata[&plan.application_metadata_key].as_deref()
                    == Some(plan.application_metadata_value.as_slice()),
            "commit readback",
            "migration metadata differs",
        )?;
        require(
            identity(verified_original)? == source_id,
            "commit readback",
            "verified file identity changed",
        )?;
        Ok(())
    })();
    verify.map_err(|mut e: MigrationError| {
        e.commit_may_have_happened = true;
        e
    })?;
    Ok(report)
}

#[cfg(test)]
mod tests;
