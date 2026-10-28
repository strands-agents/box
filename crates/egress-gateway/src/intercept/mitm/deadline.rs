//! The idle bound on each socket of an exchange.
//!
//! A bound counts the time with no byte, never the total time: a body or a reply that keeps moving
//! passes, whatever its length. Reads and writes have one clock each, and a byte in either direction
//! restarts both. So a read that waits does not end a write that moves, and the reverse: hyper waits
//! for the reply head while it still writes the request body.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// The text of the error when the client idle bound passes.
pub(super) const CLIENT_IDLE_PASSED: &str = "client idle bound passed";

/// The text of the error when the upstream idle bound passes.
pub(super) const UPSTREAM_IDLE_PASSED: &str = "upstream idle bound passed";

/// A stream whose reads and writes fail with `TimedOut` once one of them has waited `idle` with no
/// byte in either direction.
pub(super) struct Idle<S> {
    inner: S,
    idle: Duration,
    passed: &'static str,
    read: Clock,
    write: Clock,
}

/// The clock of one direction.
#[derive(Default)]
struct Clock {
    /// When the wait of the current call ends; `None` when no call waits.
    wait: Option<Pin<Box<Sleep>>>,
    /// Whether a wait reached the bound. A later call in this direction then fails at once.
    passed: bool,
}

impl<S> Idle<S> {
    /// Bound each read and each write of `inner` by `idle`. `passed` is the text of the error.
    pub(super) fn new(inner: S, idle: Duration, passed: &'static str) -> Self {
        Self {
            inner,
            idle,
            passed,
            read: Clock::default(),
            write: Clock::default(),
        }
    }

    /// Restart the read clock when a write moved a byte.
    fn wrote(&mut self, written: &Poll<io::Result<usize>>) {
        if matches!(written, Poll::Ready(Ok(bytes)) if *bytes > 0) {
            self.read.restart(self.idle);
        }
    }
}

impl Clock {
    /// Restart the wait of the current call, because a byte moved in the other direction.
    fn restart(&mut self, idle: Duration) {
        if let Some(wait) = self.wait.as_mut() {
            wait.as_mut().reset(Instant::now() + idle);
        }
    }

    /// The result of one call of a direction: `Ready` resets the clock, and `Pending` starts it or
    /// checks it.
    fn bound<T>(
        &mut self,
        cx: &mut Context<'_>,
        idle: Duration,
        passed: &'static str,
        call: impl FnOnce(&mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if self.passed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, passed)));
        }
        match call(cx) {
            Poll::Ready(result) => {
                self.wait = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let wait = self.wait.get_or_insert_with(|| {
                    Box::pin(tokio::time::sleep_until(Instant::now() + idle))
                });
                ready!(wait.as_mut().poll(cx));
                self.wait = None;
                self.passed = true;
                Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, passed)))
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Idle<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        let before = buf.filled().len();
        let read = this.read.bound(cx, this.idle, this.passed, |cx| {
            Pin::new(inner).poll_read(cx, buf)
        });
        // A read that moved a byte restarts the write clock.
        if matches!(read, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.write.restart(this.idle);
        }
        read
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Idle<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        let written = this.write.bound(cx, this.idle, this.passed, |cx| {
            Pin::new(inner).poll_write(cx, buf)
        });
        this.wrote(&written);
        written
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        let written = this.write.bound(cx, this.idle, this.passed, |cx| {
            Pin::new(inner).poll_write_vectored(cx, bufs)
        });
        this.wrote(&written);
        written
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.write.bound(cx, this.idle, this.passed, |cx| {
            Pin::new(inner).poll_flush(cx)
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.write.bound(cx, this.idle, this.passed, |cx| {
            Pin::new(inner).poll_shutdown(cx)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Run `future` on a current-thread runtime with timers and I/O.
    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    const IDLE: Duration = Duration::from_millis(200);

    /// **A read that waits the bound fails with `TimedOut`, and the next read fails at once.**
    #[test]
    fn a_read_that_waits_the_bound_times_out() {
        block_on(async {
            let (gateway, _peer) = tokio::io::duplex(64);
            let mut idle = Idle::new(gateway, IDLE, UPSTREAM_IDLE_PASSED);
            let started = Instant::now();
            let error = idle.read(&mut [0; 8]).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(error.to_string(), UPSTREAM_IDLE_PASSED);
            assert!(started.elapsed() >= IDLE);
            let again = Instant::now();
            let error = idle.read(&mut [0; 8]).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(again.elapsed() < IDLE, "the second read fails at once");
        });
    }

    /// **A stream that keeps moving is never cut, whatever its total time.** Each byte arrives
    /// under the bound, and the whole read takes more than three bounds.
    #[test]
    fn a_stream_that_keeps_moving_has_no_total_bound() {
        block_on(async {
            let (gateway, mut peer) = tokio::io::duplex(64);
            let mut idle = Idle::new(gateway, IDLE, UPSTREAM_IDLE_PASSED);
            let dripper = tokio::spawn(async move {
                for _ in 0..5 {
                    tokio::time::sleep(IDLE * 3 / 4).await;
                    peer.write_all(b"x").await.unwrap();
                }
                peer
            });
            let started = Instant::now();
            let mut got = [0; 5];
            idle.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"xxxxx");
            assert!(started.elapsed() > IDLE * 3, "{:?}", started.elapsed());
            drop(dripper.await.unwrap());
        });
    }

    /// **A read that waits while writes move is not cut.** hyper waits for the reply head while it
    /// still writes the request body, so each written byte restarts the read clock. The reply comes
    /// after the last write, more than three bounds after the read started.
    #[test]
    fn a_read_that_waits_while_writes_move_is_not_cut() {
        block_on(async {
            let (gateway, mut peer) = tokio::io::duplex(64);
            let idle = Idle::new(gateway, IDLE, UPSTREAM_IDLE_PASSED);
            let (mut reads, mut writes) = tokio::io::split(idle);
            let started = Instant::now();
            let reader = tokio::spawn(async move {
                let mut got = [0; 2];
                reads.read_exact(&mut got).await.map(|_| got)
            });
            for _ in 0..5 {
                tokio::time::sleep(IDLE * 3 / 4).await;
                writes.write_all(b"x").await.unwrap();
            }
            tokio::time::sleep(IDLE / 2).await;
            peer.write_all(b"ok").await.unwrap();
            assert_eq!(&reader.await.unwrap().unwrap(), b"ok");
            assert!(started.elapsed() > IDLE * 3, "{:?}", started.elapsed());
            let mut sent = [0; 5];
            peer.read_exact(&mut sent).await.unwrap();
            assert_eq!(&sent, b"xxxxx");
        });
    }

    /// **A write that waits the bound fails, and a read on the same stream still works.** A client
    /// that stops reading its reply is cut, and one direction does not end the other.
    #[test]
    fn a_write_that_waits_the_bound_leaves_reads_working() {
        block_on(async {
            let (gateway, mut peer) = tokio::io::duplex(4);
            let mut idle = Idle::new(gateway, IDLE, CLIENT_IDLE_PASSED);
            let error = idle.write_all(&[0; 64]).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(error.to_string(), CLIENT_IDLE_PASSED);
            peer.write_all(b"ok").await.unwrap();
            let mut got = [0; 2];
            idle.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"ok");
        });
    }
}
