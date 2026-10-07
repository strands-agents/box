//! One contained program's private state, and the two ends reachable while a Call runs.
//!
//! | Level | Lifetime | What it owns |
//! |---|---|---|
//! | Kernel | per box | policy, temporal history, the mount — shared, because a filesystem being shared *is* the semantics |
//! | **Program** | **per program** | **cwd, environment, functions, aliases, fds, background jobs — private** |
//! | Call | per submission | the deadline and the output caps, re-armed each time |

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use strands_shell::os::{STDERR, STDIN, STDOUT};
use tokio::sync::mpsc;

use super::protocol::{MAX_CALL_OUTPUT_BYTES, MAX_CHUNK_BYTES, Stream};

/// The stdin channel depth. One frame in flight is enough; the client waits for progress.
const INPUT_CHANNEL_DEPTH: usize = 16;

/// The output channel depth, per stream. Bounded, so a Program that outruns its client stalls
/// itself rather than growing a queue inside the daemon.
const OUTPUT_CHANNEL_DEPTH: usize = 64;

/// One program: the private state a Call mutates.
pub(crate) struct Program {
    shell: strands_shell::Shell,
    cancel: Arc<AtomicBool>,
}

/// The half a concurrent task holds while a Call is in flight.
#[derive(Clone)]
pub(crate) struct ProgramControl {
    stdin_tx: Arc<std::sync::Mutex<Option<mpsc::Sender<Bytes>>>>,
    /// Set when a `Signal` arrives, and read by the Call loop, which stops by **dropping** the Call
    /// future.
    cancel: Arc<AtomicBool>,
}

/// One piece of a Program's output, tagged with the stream that produced it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Chunk {
    pub(crate) stream: Stream,
    pub(crate) data: Bytes,
}

/// One Call's result. The status only — its bytes left through [`ProgramOutput`] as they were
/// produced.
pub(crate) struct CallOutcome {
    pub(crate) status: i32,
}

/// A Program's output as it is produced, against its lifetime budget.
pub(crate) struct ProgramOutput {
    stdout_rx: mpsc::Receiver<Bytes>,
    stderr_rx: mpsc::Receiver<Bytes>,
    emitted: usize,
}

impl Program {
    /// Wrap a freshly built Shell, installing the three standard channel descriptors.
    pub(crate) fn adopt(
        mut shell: strands_shell::Shell,
    ) -> io::Result<(Self, ProgramOutput, ProgramControl)> {
        let (stdin_tx, stdin_rx) = mpsc::channel(INPUT_CHANNEL_DEPTH);
        let (stdout_tx, stdout_rx) = mpsc::channel(OUTPUT_CHANNEL_DEPTH);
        let (stderr_tx, stderr_rx) = mpsc::channel(OUTPUT_CHANNEL_DEPTH);

        // The writers reach a builtin only because the vendored fork inherits them — see
        // `shell/UPSTREAM.md`.
        shell.proc.set_channel_reader(STDIN, stdin_rx);
        shell.proc.set_channel_writer(STDOUT, stdout_tx);
        shell.proc.set_channel_writer(STDERR, stderr_tx);

        let cancel = Arc::new(AtomicBool::new(false));
        Ok((
            Self {
                shell,
                cancel: Arc::clone(&cancel),
            },
            ProgramOutput {
                stdout_rx,
                stderr_rx,
                emitted: 0,
            },
            ProgramControl {
                stdin_tx: Arc::new(std::sync::Mutex::new(Some(stdin_tx))),
                cancel,
            },
        ))
    }

    /// Run one Call and return its status. Its bytes reach [`ProgramOutput`] while this future is
    /// pending, so a caller must poll both concurrently.
    pub(crate) async fn call(&mut self, command: &str) -> CallOutcome {
        self.cancel.store(false, Ordering::SeqCst);
        let output = self.shell.run(command).await;
        CallOutcome {
            status: output.status,
        }
    }

    pub(crate) fn use_shell(&mut self, mut shell: strands_shell::Shell) {
        std::mem::swap(&mut self.shell.proc, &mut shell.proc);
        self.shell = shell;
    }
}

impl ProgramOutput {
    /// Wait for the next chunk either stream produces.
    pub(crate) async fn next_chunk(&mut self) -> Chunk {
        loop {
            let (stream, data) = tokio::select! {
                biased;
                Some(data) = self.stdout_rx.recv() => (Stream::Stdout, data),
                Some(data) = self.stderr_rx.recv() => (Stream::Stderr, data),
            };
            if data.is_empty() {
                continue;
            }
            return Chunk { stream, data };
        }
    }

    /// Take a chunk only if one is already buffered.
    pub(crate) fn drain_ready(&mut self) -> Option<Chunk> {
        loop {
            let (stream, data) = match self.stdout_rx.try_recv() {
                Ok(data) => (Stream::Stdout, data),
                Err(_) => match self.stderr_rx.try_recv() {
                    Ok(data) => (Stream::Stderr, data),
                    Err(_) => return None,
                },
            };
            if data.is_empty() {
                continue;
            }
            return Some(Chunk { stream, data });
        }
    }

    /// Split one produced chunk into pieces of at most [`MAX_CHUNK_BYTES`], against the Program's
    /// [`MAX_CALL_OUTPUT_BYTES`] lifetime budget.
    pub(crate) fn admit(&mut self, chunk: Chunk, sink: &mut Vec<Chunk>) -> DrainOutcome {
        for piece in chunk.data.chunks(MAX_CHUNK_BYTES) {
            if self.emitted.saturating_add(piece.len()) > MAX_CALL_OUTPUT_BYTES {
                return DrainOutcome::CapReached;
            }
            self.emitted += piece.len();
            sink.push(Chunk {
                stream: chunk.stream,
                data: Bytes::copy_from_slice(piece),
            });
        }
        DrainOutcome::Within
    }
}

/// A `ProgramControl` lock poisoned by a panic in another holder.
fn poisoned() -> io::Error {
    io::Error::other("the program's stdin lock is poisoned")
}

/// Whether a drain stayed inside the Program's output budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainOutcome {
    Within,
    CapReached,
}

impl ProgramControl {
    /// Feed bytes to the Program's standard input.
    pub(crate) fn feed_stdin(&self, data: &[u8]) -> io::Result<()> {
        let guard = self.stdin_tx.lock().map_err(|_| poisoned())?;
        let sender = guard
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stdin is closed"))?;
        sender
            .try_send(Bytes::copy_from_slice(data))
            .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error))
    }

    /// Close the Program's standard input, so a reader sees end-of-file.
    pub(crate) fn close_stdin(&self) {
        if let Ok(mut guard) = self.stdin_tx.lock() {
            guard.take();
        }
    }

    /// Ask the running Call to end, leaving the Program open.
    pub(crate) fn signal(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// Whether a `Signal` has asked the running Call to stop.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }
}
