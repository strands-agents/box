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

use bytes::{Bytes, BytesMut};
use strands_shell::os::{STDERR, STDIN, STDOUT};
use tokio::sync::mpsc;

use super::protocol::{MAX_CALL_OUTPUT_BYTES, MAX_CHUNK_BYTES, Stream};

/// The stdin channel depth, in frames. Bytes wait in the Program's [`StdinQueue`], which merges
/// them, so a frame count never limits a writer.
const INPUT_CHANNEL_DEPTH: usize = 2;

/// The output channel depth, per stream. Bounded, so a Program that outruns its client stalls
/// itself rather than growing a queue inside the daemon.
const OUTPUT_CHANNEL_DEPTH: usize = 64;

/// One program: the private state a Call mutates.
pub(crate) struct Program {
    shell: strands_shell::Shell,
    kernel: Arc<box_shell::ShellKernel>,
    cancel: Arc<AtomicBool>,
    /// The Shell's own bound on one Call, re-armed when each Call starts.
    timeout: Option<std::time::Duration>,
    /// The streams a Call's diagnostics that the Shell captured rather than wrote are sent to.
    stdout: mpsc::WeakSender<Bytes>,
    stderr: mpsc::WeakSender<Bytes>,
}

/// The half a concurrent task holds while a Call is in flight.
#[derive(Clone)]
pub(crate) struct ProgramControl {
    stdin: Arc<StdinQueue>,
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
}

/// A Program's accepted stdin that its Shell has not taken yet, merged into one buffer.
#[derive(Default)]
struct StdinQueue {
    state: std::sync::Mutex<StdinState>,
    ready: tokio::sync::Notify,
}

#[derive(Default)]
struct StdinState {
    pending: BytesMut,
    closed: bool,
    reader_gone: bool,
}

impl StdinQueue {
    fn lock(&self) -> std::sync::MutexGuard<'_, StdinState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Move the queue's bytes into the Shell's stdin channel in frames of at most [`MAX_CHUNK_BYTES`],
/// and close the channel once the queue is closed and empty.
async fn pump_stdin(queue: Arc<StdinQueue>, sender: mpsc::Sender<Bytes>) {
    loop {
        tokio::select! {
            () = queue.ready.notified() => {}
            () = sender.closed() => {
                queue.lock().reader_gone = true;
                return;
            }
        }
        loop {
            let (frame, closed) = {
                let mut state = queue.lock();
                let size = state.pending.len().min(MAX_CHUNK_BYTES);
                (state.pending.split_to(size).freeze(), state.closed)
            };
            if !frame.is_empty() {
                if sender.send(frame).await.is_err() {
                    queue.lock().reader_gone = true;
                    return;
                }
                continue;
            }
            if closed {
                return;
            }
            break;
        }
    }
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
        hosted: super::shell::HostedShell,
        timeout: Option<std::time::Duration>,
        input_limit: usize,
    ) -> io::Result<(Self, ProgramOutput, ProgramControl)> {
        let super::shell::HostedShell { mut shell, kernel } = hosted;
        let (stdin_tx, stdin_rx) = mpsc::channel(INPUT_CHANNEL_DEPTH);
        let stdin = Arc::new(StdinQueue::default());
        tokio::spawn(pump_stdin(Arc::clone(&stdin), stdin_tx));
        let (stdout_tx, stdout_rx) = mpsc::channel(OUTPUT_CHANNEL_DEPTH);
        let (stderr_tx, stderr_rx) = mpsc::channel(OUTPUT_CHANNEL_DEPTH);

        shell.proc.set_channel_reader(STDIN, stdin_rx);
        let (stdout, stderr) = (stdout_tx.downgrade(), stderr_tx.downgrade());
        shell.proc.set_channel_writer(STDOUT, stdout_tx);
        shell.proc.set_channel_writer(STDERR, stderr_tx);

        let cancel = Arc::new(AtomicBool::new(false));
        Ok((
            Self {
                shell,
                kernel,
                cancel: Arc::clone(&cancel),
                timeout,
                stdout,
                stderr,
            },
            ProgramOutput {
                stdout_rx,
                stderr_rx,
                emitted: 0,
            },
            ProgramControl {
                stdin,
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
        match super::shell::deadline(self.timeout) {
            Ok(deadline) => self.shell.proc.deadline = deadline,
            Err(error) => {
                Self::forward(&self.stderr, format!("strands-box: {error}\n")).await;
                return CallOutcome { status: 1 };
            }
        }
        let output = self.shell.run(command).await;
        self.kernel.settle();
        Self::forward(&self.stdout, output.stdout).await;
        Self::forward(&self.stderr, output.stderr).await;
        CallOutcome {
            status: output.status,
        }
    }

    /// Send text the Shell captured to the stream it belongs to.
    async fn forward(stream: &mpsc::WeakSender<Bytes>, text: String) {
        if text.is_empty() {
            return;
        }
        if let Some(sender) = stream.upgrade() {
            let _ = sender.send(Bytes::from(text)).await;
        }
    }

    pub(crate) fn use_shell(&mut self, hosted: super::shell::HostedShell) {
        let super::shell::HostedShell { mut shell, kernel } = hosted;
        std::mem::swap(&mut self.shell.proc, &mut shell.proc);
        self.shell = shell;
        self.kernel = kernel;
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
    /// is discarded. Returns the bytes accepted. The bytes the Shell has not taken stay in one
    /// buffer, so a Program holds at most its limit however many frames brought it.
    pub(crate) fn feed_stdin(&self, data: &[u8]) -> Result<usize, InputRefusal> {
        let mut state = self.stdin.lock();
        if state.closed || state.reader_gone {
            return Err(InputRefusal::Closed);
        }
        if self.input_refused.load(Ordering::SeqCst) || self.input_capped.load(Ordering::SeqCst) {
            return Ok(0);
        }
        let received = self.input_received.load(Ordering::SeqCst);
        let room = self.input_limit.saturating_sub(received);
        let taken = &data[..data.len().min(room)];
        if !taken.is_empty() {
            state.pending.extend_from_slice(taken);
            self.input_received
                .store(received + taken.len(), Ordering::SeqCst);
            self.stdin.ready.notify_one();
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
        let _state = self.stdin.lock();
        self.input_refused.store(true, Ordering::SeqCst);
        self.signal();
    }

    /// Whether input to this Program was refused.
    pub(crate) fn input_refused(&self) -> bool {
        self.input_refused.load(Ordering::SeqCst)
    }

    /// Close the Program's standard input, so a reader sees end-of-file.
    pub(crate) fn close_stdin(&self) {
        self.stdin.lock().closed = true;
        self.stdin.ready.notify_one();
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A large backlog reaches the Shell in frames no larger than one chunk.
    #[test]
    fn a_large_backlog_leaves_in_chunk_sized_frames() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let queue = Arc::new(StdinQueue::default());
            let size = MAX_CHUNK_BYTES * 5 + 7;
            {
                let mut state = queue.lock();
                state.pending.extend_from_slice(&vec![b'x'; size]);
                state.closed = true;
            }
            let (sender, mut receiver) = mpsc::channel(INPUT_CHANNEL_DEPTH);
            queue.ready.notify_one();
            let pump = tokio::spawn(pump_stdin(Arc::clone(&queue), sender));
            let mut bytes = 0;
            while let Some(frame) = receiver.recv().await {
                assert!(frame.len() <= MAX_CHUNK_BYTES, "{} bytes", frame.len());
                bytes += frame.len();
            }
            pump.await.unwrap();
            assert_eq!(bytes, size);
        });
    }

    /// Many small frames that nothing reads are held as one buffer of their bytes, not as frames.
    #[test]
    fn small_frames_merge_while_the_shell_does_not_read() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let queue = Arc::new(StdinQueue::default());
            let (sender, mut receiver) = mpsc::channel(INPUT_CHANNEL_DEPTH);
            let pump = tokio::spawn(pump_stdin(Arc::clone(&queue), sender));
            for _ in 0..600 {
                {
                    let mut state = queue.lock();
                    state.pending.extend_from_slice(b"x");
                }
                queue.ready.notify_one();
                tokio::task::yield_now().await;
            }
            let held = queue.lock().pending.len();
            assert!(
                held >= 600 - (INPUT_CHANNEL_DEPTH + 1),
                "the bytes wait in the buffer: {held}"
            );
            queue.lock().closed = true;
            queue.ready.notify_one();
            let mut frames = 0;
            let mut bytes = 0;
            while let Some(frame) = receiver.recv().await {
                frames += 1;
                bytes += frame.len();
            }
            pump.await.unwrap();
            assert_eq!(bytes, 600);
            assert!(frames <= INPUT_CHANNEL_DEPTH + 2, "{frames} frames");
        });
    }
}
