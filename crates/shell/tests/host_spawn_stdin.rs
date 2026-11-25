//! A host program reads the stdin of the command that runs it.

#![cfg(unix)]

mod support;

use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::time::Duration;

use box_shell::{HostSpawnOutcome, HostSpawner};
use tokio::io::AsyncReadExt as _;

/// What a spawner saw of its stdin.
#[derive(Clone, Copy)]
enum Reading {
    /// Read stdin to its end and print it.
    All,
    /// Read stdin to its end and print how many bytes it held.
    Count,
    /// Read nothing, and print whether a stdin was given.
    Nothing,
    /// As `Nothing`, after a pause, so the copy runs while the program does.
    NothingAfterPause,
}

/// A command that writes `LARGE_INPUT_BYTES` to stdout in six `printf`s, each under the 65535-byte cap.
const LARGE_INPUT: &str = "for i in 1 2 3 4 5 6; do printf '%060000d' 0; done";

/// More than the copy buffer and a pipe hold together.
const LARGE_INPUT_BYTES: usize = 360_000;

/// Run `command`, with `{probe}` replaced by a host program whose spawner reads as `reading` says.
fn run(reading: Reading, command: &str) -> strands_shell::Output {
    let folder = tempfile::tempdir().expect("host folder");
    let program = folder.path().join("probe");
    std::fs::write(&program, "#!/bin/sh\n").expect("a program");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let spawner: HostSpawner = Arc::new(move |mut spawn| {
        Box::pin(async move {
            let stdout = match reading {
                Reading::All => {
                    let mut read = Vec::new();
                    if let Some(stdin) = spawn.stdin.take() {
                        let mut stdin = tokio::net::unix::pipe::Receiver::from_owned_fd(stdin)?;
                        stdin.read_to_end(&mut read).await?;
                    }
                    format!("got=[{}]", String::from_utf8_lossy(&read))
                }
                Reading::Count => {
                    let mut read = Vec::new();
                    if let Some(stdin) = spawn.stdin.take() {
                        let mut stdin = tokio::net::unix::pipe::Receiver::from_owned_fd(stdin)?;
                        stdin.read_to_end(&mut read).await?;
                    }
                    format!("bytes={}", read.len())
                }
                Reading::Nothing => format!("stdin={}", spawn.stdin.is_some()),
                Reading::NothingAfterPause => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    format!("stdin={}", spawn.stdin.is_some())
                }
            };
            Ok(HostSpawnOutcome {
                status: 0,
                stdout: stdout.into_bytes(),
                stderr: Vec::new(),
            })
        })
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&runtime, async {
        let mut shell = support::builder()
            .bind_direct(folder.path().to_str().expect("UTF-8"), "/workspace")
            .host_spawner(spawner)
            .build()
            .expect("shell builds");
        let command = command.replace("{probe}", program.to_str().expect("UTF-8"));
        tokio::time::timeout(Duration::from_secs(10), shell.run(&command))
            .await
            .expect("the command must not wait on stdin the program does not read")
    })
}

#[test]
fn a_host_program_reads_the_stdin_piped_to_its_command() {
    let output = run(Reading::All, r#"printf '{"hook":1}' | {probe}"#);
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(output.stdout, r#"got=[{"hook":1}]"#);
}

#[test]
fn a_host_program_reads_stdin_larger_than_the_copy_buffer() {
    // The copy runs while the spawn runs, so the program drains what a full buffer holds back.
    let output = run(Reading::Count, &format!("{LARGE_INPUT} | {{probe}}"));
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(output.stdout, format!("bytes={LARGE_INPUT_BYTES}"));
}

#[test]
fn a_host_program_that_reads_no_stdin_is_not_held_by_it() {
    // The copy blocks on the full buffer, and the program's end stops it.
    let output = run(Reading::Nothing, &format!("{LARGE_INPUT} | {{probe}}"));
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(output.stdout, "stdin=true");
}

#[test]
fn a_closed_stdin_gives_the_host_program_none() {
    let output = run(Reading::Nothing, "{probe} <&-");
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(output.stdout, "stdin=false");
}

#[test]
fn the_stdin_a_host_program_leaves_unread_is_not_read_after_it() {
    let output = run(
        Reading::Nothing,
        r#"printf 'first\nsecond\n' | { {probe}; read A; printf '|after=[%s]' "$A"; }"#,
    );
    assert_eq!(output.stdout, "stdin=true|after=[]", "{}", output.stderr);
}

#[test]
fn a_stdin_that_fails_to_read_leaves_a_program_that_reads_none_its_own_status() {
    // A descriptor opened for writing fails to read, so the copy fails while the program runs.
    let output = run(Reading::NothingAfterPause, "{probe} 0<&1");
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(output.stdout, "stdin=true");
    assert!(output.stderr.contains("read stdin"), "{}", output.stderr);
}
