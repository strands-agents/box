use super::Run;
use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Written by bootstrap.sh's build step, outside the run directory.
const BUILD_LOG: &str = "/tmp/box-build.log";

const ARTIFACTS: &[(&str, &str)] = &[
    ("verdict.json", "verdict.json"),
    ("agent-a/method_report.md", "method_report.md"),
    ("canary.jsonl", "canary.jsonl"),
    ("agent-a.log", "agent-a.log"),
    ("agent-a/turns.jsonl", "turns.jsonl"),
    ("finding.json", "finding.json"),
    ("agent-a/coverage.md", "coverage.md"),
];

pub(super) fn upload(dir: &Path, run: &Run, bucket: &str) -> io::Result<()> {
    let destination = format!(
        "s3://{bucket}/reports/{}/{}/indeterministic/{}/{}",
        run.box_commit.as_deref().unwrap_or("unknown"),
        run.run_id.as_deref().unwrap_or("unknown"),
        run.platform,
        run.dimension
    );
    let mut failed = vec![];
    let sources = ARTIFACTS
        .iter()
        .map(|&(source, key)| (dir.join(source), key))
        .chain([(PathBuf::from(BUILD_LOG), "box-build.log")]);
    for (source, key) in sources {
        if !source.is_file() {
            continue;
        }
        let result = Command::new("aws")
            .args(["s3", "cp"])
            .arg(&source)
            .arg(format!("{destination}/{key}"))
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .stdout(Stdio::null())
            .status();
        if !result.is_ok_and(|s| s.success()) {
            failed.push(key);
        }
    }
    println!("artifacts: {destination}");
    if failed.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "artifact upload failed: {}",
            failed.join(", ")
        )))
    }
}
