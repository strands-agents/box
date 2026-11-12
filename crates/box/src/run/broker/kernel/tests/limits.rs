//! Each limit the box sets on its Shell holds, because the Shell built on the box's kernel starts
//! with none.

use std::time::Duration;

use crate::run::broker::program::Program;
use crate::run::broker::protocol::MAX_CAPTURE_STREAM_BYTES;
use crate::run::broker::shell::{SHELL_MAX_FILE_SIZE, SHELL_MAX_INODES, SHELL_MAX_INPUT};

use super::{backend, fixture_on, run};

#[test]
fn captured_output_stops_at_the_output_limit() {
    let output = run(async {
        let mut shell = fixture_on(&backend(&[]));
        shell
            .run(&format!(
                "head -c {} /dev/zero",
                MAX_CAPTURE_STREAM_BYTES * 2
            ))
            .await
    });
    assert!(
        output.stdout.len() <= MAX_CAPTURE_STREAM_BYTES,
        "{}",
        output.stdout.len()
    );
    assert_ne!(output.status, 0, "{}", output.stderr);
}

#[test]
fn a_write_past_the_file_size_limit_fails_and_keeps_the_limit() {
    let (written, size) = run(async {
        let mut shell = fixture_on(&backend(&[]));
        let written = shell
            .run(&format!(
                "head -c {} /dev/zero > /tmp/big",
                SHELL_MAX_FILE_SIZE + 1
            ))
            .await;
        let size = shell.run("wc -c < /tmp/big").await;
        (written, size)
    });
    assert_ne!(written.status, 0, "{}", written.stderr);
    assert!(
        written.stderr.contains("file size limit exceeded"),
        "{}",
        written.stderr
    );
    assert_eq!(size.stdout.trim(), SHELL_MAX_FILE_SIZE.to_string());
}

#[test]
fn a_host_folder_has_no_file_size_limit() {
    let folder = tempfile::tempdir().expect("a host folder");
    let source = folder.path().display().to_string();
    let written = run(async {
        let mut shell = fixture_on(&backend(&[(&source, "/work")]));
        shell
            .run(&format!(
                "head -c {} /dev/zero > /work/big",
                SHELL_MAX_FILE_SIZE + 1
            ))
            .await
    });
    assert_eq!(written.status, 0, "{}", written.stderr);
    let size = std::fs::metadata(folder.path().join("big"))
        .expect("the file")
        .len();
    assert_eq!(
        size,
        (SHELL_MAX_FILE_SIZE + 1) as u64,
        "the bytes are on the host at status"
    );
}

#[test]
fn input_past_the_input_limit_is_refused() {
    let output = run(async {
        let mut shell = fixture_on(&backend(&[]));
        let comment = format!("# {}", "x".repeat(SHELL_MAX_INPUT));
        shell.run(&format!("echo ran\n{comment}")).await
    });
    assert_ne!(output.status, 0, "{}", output.stderr);
    assert!(!output.stdout.contains("ran"), "{}", output.stdout);
}

#[test]
fn files_past_the_inode_limit_are_refused() {
    let output = run(async {
        let mut shell = fixture_on(&backend(&[]));
        shell
            .run(&format!(
                "mkdir /tmp/many && i=0; while [ $i -lt {SHELL_MAX_INODES} ]; do \
                 : > /tmp/many/f$i || exit 9; i=$((i+1)); done"
            ))
            .await
    });
    assert_eq!(output.status, 9, "{}", output.stderr);
    assert!(
        output.stderr.contains("inode limit exceeded"),
        "{}",
        output.stderr
    );
}

#[test]
fn each_call_has_the_shell_timeout_from_its_own_start() {
    let (first, second) = run(async {
        let shell = fixture_on(&backend(&[]));
        let (mut program, _output, _control) =
            Program::adopt(shell, Some(Duration::from_secs(1))).expect("a program");
        let first = program.call("sleep 5").await.status;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let second = program.call("true").await.status;
        (first, second)
    });
    assert_ne!(first, 0, "a call past the timeout fails");
    assert_eq!(second, 0, "the next call starts with a fresh deadline");
}
