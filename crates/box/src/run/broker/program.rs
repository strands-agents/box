//! One contained program's private state, and the two ends reachable while a Call runs.
//!
//! | Level | Lifetime | What it owns |
//! |---|---|---|
//! | Kernel | per box | policy, temporal history, the mount — shared, because a filesystem being shared *is* the semantics |
//! | **Program** | **per program** | **cwd, environment, functions, aliases, fds, background jobs — private** |
//! | Call | per submission | the deadline and the output caps, re-armed each time |

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use strands_shell::os::{STDERR, STDIN, STDOUT};
use tokio::sync::mpsc;

use super::protocol::{MAX_CALL_OUTPUT_BYTES, MAX_CHUNK_BYTES, Stream};

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
    /// The stdin bytes accepted so far, against `input_limit`.
    input_received: Arc<AtomicUsize>,
    /// The most stdin the Program receives.
    input_limit: usize,
    /// Set when stdin reached `input_limit`, so the rest is discarded and no end-of-file follows.
    input_capped: Arc<AtomicBool>,
    /// Set when input was refused, so no later Call runs on partial input.
    input_refused: Arc<AtomicBool>,
}

/// Why [`ProgramControl::feed_stdin`] refused input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputRefusal {
    /// Nothing reads the stdin any more, or it was already closed; the bytes are dropped.
    Closed,
    /// The stdin queue is full.
    Full,
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
        input_limit: usize,
    ) -> io::Result<(Self, ProgramOutput, ProgramControl)> {
        // One slot per byte of the limit: every queued frame holds at least one byte, so the queue
        // fills only past the limit, which `try_feed` never queues.
        let depth = input_limit.clamp(1, tokio::sync::Semaphore::MAX_PERMITS);
        let (stdin_tx, stdin_rx) = mpsc::channel(depth);
        let (stdout_tx, stdout_rx) = mpsc::channel(OUTPUT_CHANNEL_DEPTH);
        let (stderr_tx, stderr_rx) = mpsc::channel(OUTPUT_CHANNEL_DEPTH);

        // The writers reach a builtin only because the vendored fork inherits them — see
        // `shell/UPSTREAM.md`.
        shell.proc.set_outside_reader(STDIN, stdin_rx);
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
                input_received: Arc::new(AtomicUsize::new(0)),
                input_limit,
                input_capped: Arc::new(AtomicBool::new(false)),
                input_refused: Arc::new(AtomicBool::new(false)),
            },
        ))
    }

    pub(crate) fn prepare_call(&mut self) {
        self.cancel.store(false, Ordering::SeqCst);
    }

    /// Run one Call and return its status. Its bytes reach [`ProgramOutput`] while this future is
    /// pending, so a caller must poll both concurrently.
    pub(crate) async fn call(&mut self, command: &str) -> CallOutcome {
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

/// Whether a drain stayed inside the Program's output budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainOutcome {
    Within,
    CapReached,
}

impl ProgramControl {
    /// Feed bytes to the Program's standard input, up to its stdin limit; past the limit the rest
    /// is discarded. A refusal stops the running Call and refuses every later one. Returns the
    /// bytes accepted.
    pub(crate) fn feed_stdin(&self, data: &[u8]) -> Result<usize, InputRefusal> {
        let accepted = self.try_feed(data);
        if matches!(accepted, Err(InputRefusal::Full)) {
            self.refuse_input();
        }
        accepted
    }

    fn try_feed(&self, data: &[u8]) -> Result<usize, InputRefusal> {
        let Ok(guard) = self.stdin_tx.lock() else {
            return Err(InputRefusal::Closed);
        };
        let sender = guard.as_ref().ok_or(InputRefusal::Closed)?;
        if self.input_refused.load(Ordering::SeqCst) || self.input_capped.load(Ordering::SeqCst) {
            return Ok(0);
        }
        let received = self.input_received.load(Ordering::SeqCst);
        let room = self.input_limit.saturating_sub(received);
        let taken = &data[..data.len().min(room)];
        if !taken.is_empty() {
            sender
                .try_send(Bytes::copy_from_slice(taken))
                .map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => InputRefusal::Full,
                    mpsc::error::TrySendError::Closed(_) => InputRefusal::Closed,
                })?;
            self.input_received
                .store(received + taken.len(), Ordering::SeqCst);
        }
        if taken.len() < data.len() {
            self.input_capped.store(true, Ordering::SeqCst);
        }
        Ok(taken.len())
    }

    /// Treat stdin as having reached its limit: later input is discarded and end-of-file withheld.
    pub(crate) fn cap_input(&self) {
        self.input_capped.store(true, Ordering::SeqCst);
    }

    /// Whether stdin reached the Program's limit, so its end-of-file never comes.
    pub(crate) fn input_capped(&self) -> bool {
        self.input_capped.load(Ordering::SeqCst)
    }

    /// The most stdin the Program receives.
    pub(crate) fn input_limit(&self) -> usize {
        self.input_limit
    }

    /// Refuse all further input, stop the running Call, and refuse every later Call. Later input is
    /// dropped and stdin stays open, so the running Call never reads more of its input or its end.
    pub(crate) fn refuse_input(&self) {
        let _sender = self.stdin_tx.lock();
        self.input_refused.store(true, Ordering::SeqCst);
        self.signal();
    }

    /// Whether input to this Program was refused.
    pub(crate) fn input_refused(&self) -> bool {
        self.input_refused.load(Ordering::SeqCst)
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
