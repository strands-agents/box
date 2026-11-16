//! A Program's installed output writers through a redirected group, as Claude Code's preamble
//! uses them.

use bytes::Bytes;
use strands_shell::os::{STDERR, STDOUT};
use tokio::sync::mpsc;

use super::{backend, fixture_on, run};

/// Run `command` with a writer installed on each stream, and return the status and both streams.
fn with_writers(command: &str) -> (i32, String, String) {
    run(async {
        let mut shell = fixture_on(&backend(&[]));
        let (stdout_tx, mut stdout_rx) = mpsc::channel::<Bytes>(64);
        let (stderr_tx, mut stderr_rx) = mpsc::channel::<Bytes>(64);
        shell.proc.set_channel_writer(STDOUT, stdout_tx);
        shell.proc.set_channel_writer(STDERR, stderr_tx);
        let collect = async {
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            loop {
                tokio::select! {
                    Some(chunk) = stdout_rx.recv() => stdout.extend_from_slice(&chunk),
                    Some(chunk) = stderr_rx.recv() => stderr.extend_from_slice(&chunk),
                    else => break,
                }
            }
            (stdout, stderr)
        };
        let call = async {
            let status = shell.run(command).await.status;
            drop(shell);
            status
        };
        let (status, (stdout, stderr)) = tokio::join!(call, collect);
        (
            status,
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
        )
    })
}

#[test]
fn a_group_redirected_to_dev_null_writes_nothing_to_an_installed_writer() {
    let (status, stdout, stderr) =
        with_writers("{ echo out; ls /nope; unalias missing; } >/dev/null 2>&1; echo done");
    assert_eq!(status, 0, "{stderr}");
    assert_eq!(stdout, "done\n");
    assert!(stderr.is_empty(), "{stderr:?}");
}

#[test]
fn a_group_writing_many_stderr_lines_to_dev_null_finishes_silently() {
    let (status, stdout, stderr) = with_writers(
        "{ i=0; while [ $i -lt 300 ]; do echo line$i >&2; i=$((i+1)); done; } 2>/dev/null; echo done",
    );
    assert_eq!(status, 0, "{stderr}");
    assert_eq!(stdout, "done\n");
    assert!(stderr.is_empty(), "{stderr:?}");
}

#[test]
fn a_group_writing_many_stderr_lines_to_stdout_keeps_every_line() {
    let (status, stdout, stderr) = with_writers(
        "{ i=0; while [ $i -lt 300 ]; do echo line$i >&2; i=$((i+1)); done; } 2>&1 | tail -2",
    );
    assert_eq!(status, 0, "{stderr}");
    assert_eq!(stdout, "line298\nline299\n");
    assert!(stderr.is_empty(), "{stderr:?}");
}

#[test]
fn a_command_redirected_to_dev_null_writes_nothing_to_an_installed_writer() {
    let (status, stdout, stderr) =
        with_writers("ls /nope 2>/dev/null; unalias missing 2>/dev/null; echo done");
    assert_eq!(status, 0, "{stderr}");
    assert_eq!(stdout, "done\n");
    assert!(stderr.is_empty(), "{stderr:?}");
}
