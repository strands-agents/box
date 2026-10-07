//! A channel writer installed on the shell's own process must reach a builtin's output.
//!
//! `Process::set_channel_writer` is public and `Process::out_msg` checks a `ChannelWriter` on
//! `STDOUT` before its captured and real-stdout fallbacks — so installing one is the documented
//! way for an embedder to receive output as it is produced.
//!
//! The single-builtin path did not honour it. It forks an `io_proc`, installs its *own* pipes over
//! `STDOUT` and `STDERR`, and drains them either into a captured `String` or to the host's real
//! stdout, so a writer installed by the caller was discarded for exactly the commands that matter.
//! `transfer_fd(STDIN, …)` sits two lines away in the same arm, carrying the caller's stdin into
//! the fork; the stdout and stderr equivalent was missing.
//!
//! These tests assert the inheritance, and that a caller who installs nothing is unaffected.

use bytes::Bytes;
use strands_shell::Shell;
use strands_shell::os::{STDERR, STDOUT};

fn rt() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    (rt, tokio::task::LocalSet::new())
}

/// Drain a receiver without blocking, joining what has arrived.
fn drained(rx: &mut tokio::sync::mpsc::Receiver<Bytes>) -> String {
    let mut text = String::new();
    while let Ok(chunk) = rx.try_recv() {
        text.push_str(&String::from_utf8_lossy(&chunk));
    }
    text
}

/// A builtin's stdout reaches a writer the caller installed.
///
/// The load-bearing case: `printf` is a builtin, so it takes the single-builtin path that used to
/// replace the caller's writer.
#[test]
fn a_builtins_stdout_reaches_an_installed_channel_writer() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let (tx, mut rx) = strands_shell::os::pipe(64);
        shell.proc.set_channel_writer(STDOUT, tx);

        let output = shell.run("printf INHERITED").await;

        assert_eq!(
            drained(&mut rx),
            "INHERITED",
            "a builtin's stdout must reach the writer the caller installed; captured stdout \
             was {:?} and status {}",
            output.stdout,
            output.status
        );
    }));
}

/// A builtin's stderr reaches a writer the caller installed.
#[test]
fn a_builtins_stderr_reaches_an_installed_channel_writer() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let (tx, mut rx) = strands_shell::os::pipe(64);
        shell.proc.set_channel_writer(STDERR, tx);

        // A builtin that writes to stderr rather than exiting non-zero for another reason.
        let output = shell.run("printf OOPS >&2").await;

        assert!(
            drained(&mut rx).contains("OOPS"),
            "a builtin's stderr must reach the writer the caller installed; captured stderr \
             was {:?} and status {}",
            output.stderr,
            output.status
        );
    }));
}

/// Bytes of one stream arrive in the order the program produced them.
#[test]
fn an_installed_writer_receives_bytes_in_order() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let (tx, mut rx) = strands_shell::os::pipe(64);
        shell.proc.set_channel_writer(STDOUT, tx);

        shell.run("printf A; printf B; printf C").await;

        assert_eq!(
            drained(&mut rx),
            "ABC",
            "the writer must preserve the order the program produced"
        );
    }));
}

/// A byte sequence that is not valid UTF-8 survives the channel.
///
/// This is why the box's frame payload is base64 rather than a `String`: a build's or a REPL's
/// output is not guaranteed UTF-8, and a `String` field would make those unrepresentable.
#[test]
fn an_installed_writer_carries_bytes_that_are_not_utf8() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let (tx, mut rx) = strands_shell::os::pipe(64);
        shell.proc.set_channel_writer(STDOUT, tx);

        // A lone 0x80 continuation byte is not valid UTF-8 in any position. Written through the
        // channel directly rather than via a `printf` escape, because this builtin does not
        // interpret octal escapes — an earlier version of this test asserted against the literal
        // bytes of `\377` and proved nothing about the channel.
        let (raw_tx, mut raw_rx) = strands_shell::os::pipe(4);
        raw_tx.try_send(Bytes::from_static(&[0x80])).unwrap();
        drop(raw_tx);
        let mut bytes = Vec::new();
        while let Ok(chunk) = raw_rx.try_recv() {
            bytes.extend_from_slice(&chunk);
        }
        assert_eq!(
            bytes,
            vec![0x80],
            "the channel carries Bytes, so a byte that is not valid UTF-8 must survive it"
        );

        // And the inherited writer is what a builtin's output reaches, so the two together mean
        // non-UTF-8 program output is representable end to end.
        shell.run("printf ok").await;
        assert_eq!(drained(&mut rx), "ok");
    }));
}

/// A caller who installs no writer is unaffected.
///
/// The inheritance must be additive. Every existing consumer of this crate installs nothing on
/// `shell.proc`, so the captured path has to behave exactly as before.
#[test]
fn capture_is_unchanged_when_no_writer_is_installed() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();

        let output = shell.run("printf CAPTURED").await;

        assert_eq!(
            output.stdout, "CAPTURED",
            "with no writer installed, output must still be captured as before"
        );
        assert_eq!(output.status, 0, "and the status must be unchanged");
    }));
}

/// A builtin that takes fd 1 as a writer, rather than using `out_msg`, still reaches the sink.
///
/// `cat` and `ls` call `io::stdout()`, which is `Process::take_writer(STDOUT)` — it *removes* the
/// descriptor and hands back a writer. `printf` and `echo` go through `out_msg`, which only borrows.
/// So the two families exercise different halves of the inheritance and a fix for one can miss the
/// other.
#[test]
fn a_writer_taking_builtin_reaches_an_installed_channel_writer() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        // No `tempfile` dev-dependency in this crate; a pid-scoped directory keeps concurrent
        // test binaries from colliding without adding one.
        let dir = std::env::temp_dir().join(format!("cwi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.txt"), "FILEBYTES").unwrap();
        let mut shell = Shell::builder()
            .bind_direct(dir.to_str().unwrap(), "/w")
            .build()
            .unwrap();
        let (tx, mut rx) = strands_shell::os::pipe(64);
        shell.proc.set_channel_writer(STDOUT, tx);

        let output = shell.run("cat /w/f.txt").await;

        assert_eq!(
            drained(&mut rx),
            "FILEBYTES",
            "a writer-taking builtin must reach the installed sink; captured was {:?}, status {}",
            output.stdout,
            output.status
        );
    }));
}
