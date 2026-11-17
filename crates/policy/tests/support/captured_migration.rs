//! Reconstruct a captured 1.0.0 record stream without aging its finite windows.

use dogwood_local_engine::{DurableLog, Record, Write, event_from_json, event_to_json};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn write_fixture(path: &Path, name: &str) -> FixtureResult<()> {
    let (stream, metadata) = match name {
        "collision-1.0.0.redb" => (
            include_str!("../fixtures/dogwood_1_0_0/collision.jsonl"),
            include_str!("../fixtures/dogwood_1_0_0/collision.metadata.json"),
        ),
        "staged-forbid-1.0.0.redb" => (
            include_str!("../fixtures/dogwood_1_0_0/staged.jsonl"),
            include_str!("../fixtures/dogwood_1_0_0/staged.metadata.json"),
        ),
        "installed-duplicates-1.0.0.redb" => (
            include_str!("../fixtures/dogwood_1_0_0/duplicates.jsonl"),
            include_str!("../fixtures/dogwood_1_0_0/duplicates.metadata.json"),
        ),
        "reversible" => (
            include_str!("../fixtures/dogwood_1_0_0/reversible.jsonl"),
            include_str!("../fixtures/dogwood_1_0_0/reversible.metadata.json"),
        ),
        "reversible-duplicates" => (
            include_str!("../fixtures/dogwood_1_0_0/reversible-duplicates.jsonl"),
            include_str!("../fixtures/dogwood_1_0_0/reversible-duplicates.metadata.json"),
        ),
        _ => return Err(format!("unknown captured history fixture: {name}").into()),
    };
    assert!(
        !path.exists(),
        "fixture must not replace an existing history"
    );
    let records = stream
        .lines()
        .map(|line| {
            let record = Record::decode(line.as_bytes()).map_err(|error| error.to_string())?;
            // Guard against a newer codec silently dropping a captured field.
            let original: Value = serde_json::from_str(line)?;
            let encoded: Value = serde_json::from_slice(&record.encode())?;
            assert_eq!(
                original, encoded,
                "decoding changed a captured record field"
            );
            Ok(record)
        })
        .collect::<FixtureResult<Vec<_>>>()?;
    assert!(!records.is_empty(), "captured stream must contain history");
    assert!(
        records
            .windows(2)
            .all(|pair| pair[0].timestamp() <= pair[1].timestamp()),
        "captured record timestamps must be nondecreasing"
    );
    // One policy-operation batch may share a timestamp. Ingested events still
    // have strictly increasing timestamps; preserve both kinds of ordering.
    let event_times = records
        .iter()
        .filter_map(|record| match record {
            Record::Event(event) => Some(event.timestamp()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        event_times.windows(2).all(|pair| pair[0] < pair[1]),
        "captured event timestamps must be strictly increasing"
    );
    let first = records.first().unwrap().timestamp();
    let last = records.last().unwrap().timestamp();
    let span = last
        .checked_sub(first)
        .ok_or("captured timestamp span overflow")?;
    assert!(
        (0..=60_000_000_000).contains(&span),
        "capture exceeds its one-minute construction bound"
    );
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let newest = now
        .checked_sub(5_000_000_000)
        .ok_or("current clock predates fixture margin")?;
    let shift = newest
        .checked_sub(last)
        .ok_or("timestamp translation overflow")?;
    let mut encoded = Vec::new();
    for record in records {
        let old_timestamp = record.timestamp();
        let original = record.encode();
        let timestamp = old_timestamp
            .checked_add(shift)
            .ok_or("timestamp translation overflow")?;
        assert!(
            timestamp <= newest && now - timestamp <= 65_000_000_000,
            "translated history must stay in the bounded recent past"
        );
        let shifted = retimestamp(record, timestamp)?;
        // Reversing the timestamp translation must restore the complete record.
        let reversed = retimestamp(Record::decode(&shifted.encode())?, old_timestamp)?;
        assert_eq!(
            reversed.encode(),
            original,
            "translation changed more than record time"
        );
        encoded.push(shifted.encode());
    }
    let metadata: BTreeMap<String, Option<Vec<u8>>> = serde_json::from_str(metadata)?;
    assert_eq!(
        metadata.len(),
        2,
        "only the two captured engine metadata keys are expected"
    );
    assert!(metadata.contains_key("dogwood_server_time_unit"));
    assert!(metadata.contains_key("dogwood_server_service_schema"));
    let log = DurableLog::open(path)?;
    let mut writes = encoded
        .iter()
        .map(|record| Write::Append(record))
        .collect::<Vec<_>>();
    for (key, value) in &metadata {
        if let Some(value) = value {
            writes.push(Write::Meta { key, value });
        }
    }
    let offsets = log.commit(&writes)?;
    assert_eq!(offsets, (0..encoded.len() as u64).collect::<Vec<_>>());
    assert_eq!(log.base_offset(), 0);
    assert_eq!(log.next_offset(), encoded.len() as u64);
    assert!(
        log.get_snapshot()?.is_none(),
        "full replay is required for retimestamped history"
    );
    assert!(
        log.get_meta("box.dogwood.migration.v1")?.is_none(),
        "captured store must require explicit migration"
    );
    for (key, value) in metadata {
        assert_eq!(log.get_meta(&key)?, value);
    }
    Ok(())
}

fn retimestamp(mut record: Record, timestamp: i64) -> FixtureResult<Record> {
    match &mut record {
        Record::Event(event) => {
            // The public codec explicitly keeps the timestamp outside the event payload.
            let payload = event_to_json(event);
            *event = event_from_json(&payload, timestamp)?;
            assert_eq!(
                event_to_json(event),
                payload,
                "event fields changed during translation"
            );
        }
        Record::Add { ts, .. }
        | Record::Update { ts, .. }
        | Record::Delete { ts, .. }
        | Record::Reset { ts, .. }
        | Record::DeleteAll { ts }
        | Record::ResetAll { ts }
        | Record::SetActionSchema { ts, .. }
        | Record::AppendActionSchema { ts, .. } => *ts = timestamp,
    }
    Ok(record)
}
