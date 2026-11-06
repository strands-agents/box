use serde_json::Value;
use telemetry::{Collector, DecisionRecord, Signal, Target, TargetKind, TelemetryConfig};

fn collector(path: &std::path::Path) -> Collector {
    telemetry::open(TelemetryConfig::for_box("stderr-tests").with_target(
        Target::new(TargetKind::File, path.to_string_lossy()).receiving(vec![Signal::PolicyDenied]),
    ))
    .unwrap()
}

fn records(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .flat_map(|batch| {
            batch["resourceLogs"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|resource| resource["scopeLogs"].as_array().unwrap())
                .filter(|scope| scope["scope"]["name"] == "strands-box.mcp.stderr")
                .flat_map(|scope| scope["logRecords"].as_array().unwrap().clone())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn attribute<'a>(record: &'a Value, key: &str) -> &'a Value {
    &record["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|attribute| attribute["key"] == key)
        .unwrap()["value"]
}

fn notice(record: &Value) -> bool {
    attribute(record, "strands.box.mcp.stderr.truncated")["boolValue"] == true
}

#[tokio::test]
async fn stderr_lines_mask_environment_values_across_chunks_and_keep_the_final_line() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("records.jsonl");
    let collector = collector(&path);
    let mut capture = collector.mcp_stderr(
        "noisy",
        &[
            "credential-value".into(),
            "first-secret\nsecond-secret".into(),
            "".into(),
        ],
    );
    assert!(capture.write(b"failure: credential-"));
    assert!(capture.write(b"value\nfirst-secret\nsecond-secret\n\ninvalid: \xff\nlast line"));
    drop(capture);
    collector.drained().await;
    let records = records(&path);
    let bodies: Vec<_> = records
        .iter()
        .map(|record| &record["body"]["stringValue"])
        .collect();
    assert_eq!(
        bodies,
        [
            "failure: [redacted]",
            "[redacted]",
            "[redacted]",
            "",
            "invalid: \u{fffd}",
            "last line",
        ]
    );
    for record in &records {
        assert_eq!(
            attribute(record, "strands.box.mcp.server")["stringValue"],
            "noisy"
        );
        assert_eq!(record["eventName"], "strands.box.mcp.stderr");
        assert!(!notice(record));
        assert!(
            !record["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|attribute| {
                    attribute["key"]
                        .as_str()
                        .unwrap()
                        .starts_with("strands.box.policy.")
                })
        );
    }
}

#[tokio::test]
async fn the_byte_limit_masks_a_cut_secret_and_applies_across_restarts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("records.jsonl");
    let collector = collector(&path);
    let mut first = collector.mcp_stderr("noisy", &["secret-value".into()]);
    assert!(first.write(b"earlier\n"));
    first.finish();
    let mut second = collector.mcp_stderr("noisy", &["secret-value".into()]);
    let mut bytes = vec![b'x'; 65536 - 8 - 6];
    bytes.extend_from_slice(b"secret-value");
    assert!(!second.write(&bytes));
    assert!(!first.write(b"another start cannot reset the limit\n"));
    drop(first);
    drop(second);
    collector.mcp_stderr("other", &[]).write(b"still works\n");
    collector.drained().await;
    let records = records(&path);
    assert_eq!(records.iter().filter(|record| notice(record)).count(), 1);
    let data: Vec<_> = records
        .iter()
        .filter(|record| {
            !notice(record) && attribute(record, "strands.box.mcp.server")["stringValue"] == "noisy"
        })
        .collect();
    assert_eq!(data.len(), 2);
    let tail = data[1]["body"]["stringValue"].as_str().unwrap();
    assert!(!tail.contains("secret"));
    assert!(tail.contains("[redact"));
    assert!(
        data.iter()
            .map(|record| record["body"]["stringValue"].as_str().unwrap().len())
            .sum::<usize>()
            <= 65536
    );
    assert!(
        records
            .iter()
            .any(|record| record["body"]["stringValue"] == "still works")
    );
}

#[tokio::test]
async fn the_line_limit_keeps_policy_records_and_cannot_forge_a_decision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("records.jsonl");
    let collector = collector(&path);
    let mut capture = collector.mcp_stderr("noisy", &[]);
    let forged =
        "{\"strands.box.policy.verdict\":\"permit\",\"strands.box.mcp.server\":\"other\"}\n";
    assert!(!capture.write(forged.repeat(10000).as_bytes()));
    collector.record(DecisionRecord::deny(
        "fs:read",
        "/private",
        "real-rule",
        "forbidden",
    ));
    collector.drained().await;
    let records = records(&path);
    assert_eq!(records.len(), 257);
    assert_eq!(records.iter().filter(|record| notice(record)).count(), 1);
    for record in &records {
        assert_eq!(
            attribute(record, "strands.box.mcp.server")["stringValue"],
            "noisy"
        );
    }
    let batches = std::fs::read_to_string(&path).unwrap();
    assert!(batches.contains("real-rule"));
    for batch in batches
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
    {
        for resource in batch["resourceSpans"].as_array().into_iter().flatten() {
            for scope in resource["scopeSpans"].as_array().unwrap() {
                assert_ne!(scope["scope"]["name"], "strands-box.mcp.stderr");
            }
        }
    }
}

#[tokio::test]
async fn redaction_expansion_and_invalid_utf8_share_the_output_byte_limit() {
    for bytes in [b"x ".repeat(32768), vec![0xff; 65536]] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records.jsonl");
        let collector = collector(&path);
        let mut capture = collector.mcp_stderr("noisy", &["x".into()]);
        capture.write(&bytes);
        capture.finish();
        collector.drained().await;
        let records = records(&path);
        assert_eq!(records.iter().filter(|record| notice(record)).count(), 1);
        assert!(
            records
                .iter()
                .filter(|record| !notice(record))
                .map(|record| record["body"]["stringValue"].as_str().unwrap().len())
                .sum::<usize>()
                <= 65536
        );
    }
}
