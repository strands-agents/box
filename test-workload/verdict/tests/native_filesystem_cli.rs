use std::process::Command;

#[test]
fn missing_evidence_produces_failed_check_rows() {
    let absent = std::env::temp_dir().join(format!(
        "native-cli-absent-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    assert!(!absent.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_workload-oracle"))
        .arg("native-filesystem")
        .arg(absent)
        .arg("codex")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let rows: Vec<workload_verdict::Check> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for id in [
        "agent-completed",
        "native-protected-denial",
        "one-protected-attempt",
    ] {
        assert!(rows.iter().any(|row| row.id == id && !row.ok), "{id}");
    }
}

#[test]
fn missing_arguments_report_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_workload-oracle"))
        .arg("native-filesystem")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}
