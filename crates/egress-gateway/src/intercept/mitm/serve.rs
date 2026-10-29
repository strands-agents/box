//! The count of what each stream of an exchange accepted, and the outcome of each permit that
//! the count gives.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

use crate::effect::EffectOutcome;

/// The outcome of the request permit, from what the upstream stream accepted.
fn request_outcome(sent: Writes, status: Option<u16>) -> EffectOutcome {
    let accepted_bytes = sent.accepted;
    if sent.flushed {
        match status {
            Some(status) => EffectOutcome::Replied {
                accepted_bytes,
                status,
            },
            None => EffectOutcome::Completed(accepted_bytes),
        }
    } else if sent.flush_error && sent.body_taken {
        EffectOutcome::Indeterminate { accepted_bytes }
    } else {
        unsent(accepted_bytes, sent.error)
    }
}

/// The outcome of the release permit, from what the client stream accepted since the claim.
fn release_outcome(written: Writes, start: usize, delivered: bool) -> EffectOutcome {
    let accepted_bytes = written.accepted.saturating_sub(start);
    if delivered {
        EffectOutcome::Completed(accepted_bytes)
    } else if written.flush_error {
        EffectOutcome::Indeterminate { accepted_bytes }
    } else {
        unsent(accepted_bytes, written.error)
    }
}

/// The outcome of a message that did not leave whole.
fn unsent(accepted_bytes: usize, error: Option<io::ErrorKind>) -> EffectOutcome {
    let error_kind = error.unwrap_or(io::ErrorKind::Other);
    if accepted_bytes == 0 {
        EffectOutcome::Failed {
            accepted_bytes: 0,
            error_kind,
        }
    } else {
        EffectOutcome::Partial {
            accepted_bytes,
            error_kind,
        }
    }
}

/// What one stream accepted, as its writer saw it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Writes {
    /// The bytes that the stream accepted.
    pub(super) accepted: usize,
    /// Whether hyper has taken the whole body of the message.
    pub(super) body_taken: bool,
    /// Whether a flush succeeded after the body was taken: the whole message left.
    pub(super) flushed: bool,
    /// The kind of the first write or flush error.
    pub(super) error: Option<io::ErrorKind>,
    /// Whether that error came from a flush, after every byte was accepted.
    pub(super) flush_error: bool,
}

/// The write count of one stream, shared by the stream and the exchange.
pub(super) struct WriteCount(watch::Sender<Writes>);

impl WriteCount {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self(watch::Sender::new(Writes::default())))
    }

    /// What the stream has accepted so far.
    pub(super) fn snapshot(&self) -> Writes {
        *self.0.borrow()
    }

    /// hyper has taken the whole body. It buffers the body before its next flush.
    pub(super) fn body_taken(&self) {
        self.0.send_modify(|writes| writes.body_taken = true);
    }

    fn accepted(&self, bytes: usize) {
        self.0.send_modify(|writes| writes.accepted += bytes);
    }

    /// hyper flushes only an empty write buffer, so a flush after the body was taken means that
    /// the whole message left.
    fn flushed(&self) {
        self.0.send_if_modified(|writes| {
            let left = writes.body_taken && writes.accepted > 0 && !writes.flushed;
            writes.flushed |= left;
            left
        });
    }

    fn failed(&self, kind: io::ErrorKind, during_flush: bool) {
        self.0.send_if_modified(|writes| {
            let first = writes.error.is_none();
            if first {
                writes.error = Some(kind);
                writes.flush_error = during_flush;
            }
            first
        });
    }

    /// Wait until the whole message has left, or a write or flush has failed.
    async fn settled(&self) {
        let mut writes = self.0.subscribe();
        let _ = writes
            .wait_for(|writes| writes.flushed || writes.error.is_some())
            .await;
    }
}

/// A stream that reports what it accepted to a [`WriteCount`].
pub(super) struct Counted<S> {
    inner: S,
    writes: Arc<WriteCount>,
}

impl<S> Counted<S> {
    fn new(inner: S, writes: Arc<WriteCount>) -> Self {
        Self { inner, writes }
    }

    fn count(&self, written: Poll<io::Result<usize>>) -> Poll<io::Result<usize>> {
        match &written {
            Poll::Ready(Ok(bytes)) => self.writes.accepted(*bytes),
            Poll::Ready(Err(error)) => self.writes.failed(error.kind(), false),
            Poll::Pending => {}
        }
        written
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.count(written)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.count(written)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let flushed = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        match &flushed {
            Ok(()) => this.writes.flushed(),
            Err(error) => this.writes.failed(error.kind(), true),
        }
        Poll::Ready(flushed)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writes(accepted: usize, body_taken: bool, flushed: bool) -> Writes {
        Writes {
            accepted,
            body_taken,
            flushed,
            ..Writes::default()
        }
    }

    fn failed(accepted: usize, kind: io::ErrorKind, flush_error: bool) -> Writes {
        Writes {
            accepted,
            body_taken: true,
            error: Some(kind),
            flush_error,
            ..Writes::default()
        }
    }

    /// **The request outcome follows the write count**: one row for each way a request ends.
    #[test]
    fn request_outcome_follows_the_write_count() {
        use io::ErrorKind::{BrokenPipe, InvalidData, Other, TimedOut};
        let rows = [
            (
                writes(90, true, true),
                Some(200),
                EffectOutcome::Replied {
                    accepted_bytes: 90,
                    status: 200,
                },
            ),
            (writes(90, true, true), None, EffectOutcome::Completed(90)),
            (
                failed(0, InvalidData, false),
                None,
                EffectOutcome::Failed {
                    accepted_bytes: 0,
                    error_kind: InvalidData,
                },
            ),
            (
                failed(3, TimedOut, false),
                Some(413),
                EffectOutcome::Partial {
                    accepted_bytes: 3,
                    error_kind: TimedOut,
                },
            ),
            (
                failed(90, BrokenPipe, true),
                None,
                EffectOutcome::Indeterminate { accepted_bytes: 90 },
            ),
            (
                writes(40, false, false),
                None,
                EffectOutcome::Partial {
                    accepted_bytes: 40,
                    error_kind: Other,
                },
            ),
        ];
        for (sent, status, outcome) in rows {
            assert_eq!(request_outcome(sent, status), outcome, "{sent:?}");
        }
    }

    /// **The release counts only the bytes after its claim**, so an interim `100 Continue` that
    /// hyper wrote first is not part of the reply.
    #[test]
    fn the_release_counts_only_reply_bytes() {
        let written = writes(125, false, false);
        assert_eq!(
            release_outcome(written, 25, true),
            EffectOutcome::Completed(100)
        );
        let cut = Writes {
            accepted: 60,
            error: Some(io::ErrorKind::TimedOut),
            ..Writes::default()
        };
        assert_eq!(
            release_outcome(cut, 25, false),
            EffectOutcome::Partial {
                accepted_bytes: 35,
                error_kind: io::ErrorKind::TimedOut
            }
        );
        assert_eq!(
            release_outcome(cut, 60, false),
            EffectOutcome::Failed {
                accepted_bytes: 0,
                error_kind: io::ErrorKind::TimedOut
            }
        );
    }

    /// **A flush counts as the end of a message only after hyper took its body.** hyper flushes an
    /// empty buffer before it has a message too.
    #[test]
    fn a_flush_before_the_body_is_taken_is_not_the_end_of_the_message() {
        let count = WriteCount::new();
        count.flushed();
        count.accepted(40);
        count.flushed();
        assert!(!count.snapshot().flushed, "the head alone left");
        count.body_taken();
        count.accepted(10);
        count.flushed();
        assert!(count.snapshot().flushed);
        assert_eq!(count.snapshot().accepted, 50);
    }
}
