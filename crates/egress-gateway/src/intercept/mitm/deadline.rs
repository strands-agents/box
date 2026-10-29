//! The upstream deadline of one exchange: each read and each write waits at most the deadline, and
//! no read or write starts once the deadline has passed since the exchange started.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// The text of the error when a read waits the deadline, or starts after it.
pub(super) const UPSTREAM_READ_PASSED: &str = "upstream read deadline passed";

/// The text of the error when a write waits the deadline, or starts after it.
pub(super) const UPSTREAM_WRITE_PASSED: &str = "upstream write deadline passed";

/// An upstream stream whose reads and writes fail with `TimedOut` when one of them waits `each`
/// with no byte, or when one of them starts at or after `end`.
pub(super) struct Deadline<S> {
    inner: S,
    each: Duration,
    end: Instant,
    read: Clock,
    write: Clock,
}

/// The clock of one direction.
#[derive(Default)]
struct Clock {
    /// When the wait of the current call ends; `None` when no call waits.
    wait: Option<Pin<Box<Sleep>>>,
}

impl<S> Deadline<S> {
    /// Bound each read and each write of `inner` by `each`, and the start of each by `end`.
    pub(super) fn new(inner: S, each: Duration, end: Instant) -> Self {
        Self {
            inner,
            each,
            end,
            read: Clock::default(),
            write: Clock::default(),
        }
    }
}

impl Clock {
    /// One call of a direction. A call that starts at or after `end` fails at once; a call that
    /// waits fails when its wait reaches `each`. `Ready` ends the call.
    fn bound<T>(
        &mut self,
        cx: &mut Context<'_>,
        each: Duration,
        end: Option<Instant>,
        passed: &'static str,
        call: impl FnOnce(&mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if self.wait.is_none() && end.is_some_and(|end| Instant::now() >= end) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, passed)));
        }
        match call(cx) {
            Poll::Ready(result) => {
                self.wait = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let wait = self
                    .wait
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(each)));
                ready!(wait.as_mut().poll(cx));
                self.wait = None;
                Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, passed)))
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Deadline<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.read
            .bound(cx, this.each, Some(this.end), UPSTREAM_READ_PASSED, |cx| {
                Pin::new(inner).poll_read(cx, buf)
            })
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Deadline<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.write
            .bound(cx, this.each, Some(this.end), UPSTREAM_WRITE_PASSED, |cx| {
                Pin::new(inner).poll_write(cx, buf)
            })
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.write
            .bound(cx, this.each, Some(this.end), UPSTREAM_WRITE_PASSED, |cx| {
                Pin::new(inner).poll_write_vectored(cx, bufs)
            })
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    /// A flush is not checked against the end; its wait is bounded.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.write
            .bound(cx, this.each, None, UPSTREAM_WRITE_PASSED, |cx| {
                Pin::new(inner).poll_flush(cx)
            })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.write
            .bound(cx, this.each, None, UPSTREAM_WRITE_PASSED, |cx| {
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

    const EACH: Duration = Duration::from_millis(200);

    /// A deadline that only the wait of each call can reach.
    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// **A read that waits the deadline fails with `TimedOut`.**
    #[test]
    fn a_read_that_waits_the_deadline_times_out() {
        block_on(async {
            let (gateway, _peer) = tokio::io::duplex(64);
            let mut upstream = Deadline::new(gateway, EACH, far());
            let started = Instant::now();
            let error = upstream.read(&mut [0; 8]).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(error.to_string(), UPSTREAM_READ_PASSED);
            assert!(started.elapsed() >= EACH);
        });
    }

    /// **A write that waits the deadline fails with `TimedOut`, and a read still works.** One
    /// direction does not end the other.
    #[test]
    fn a_write_that_waits_the_deadline_times_out() {
        block_on(async {
            let (gateway, mut peer) = tokio::io::duplex(4);
            let mut upstream = Deadline::new(gateway, EACH, far());
            let error = upstream.write_all(&[0; 64]).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(error.to_string(), UPSTREAM_WRITE_PASSED);
            peer.write_all(b"ok").await.unwrap();
            let mut got = [0; 2];
            upstream.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"ok");
        });
    }

    /// **A stream that keeps moving is cut at the end of the exchange.** Each byte arrives well
    /// under the wait of one read, but no read starts after the end, so the whole read fails at
    /// about the end. A write after the end fails at once.
    #[test]
    fn no_read_or_write_starts_after_the_end_of_the_exchange() {
        block_on(async {
            let (gateway, mut peer) = tokio::io::duplex(64);
            let total = Duration::from_millis(300);
            let mut upstream =
                Deadline::new(gateway, Duration::from_secs(60), Instant::now() + total);
            let dripper = tokio::spawn(async move {
                for _ in 0..20 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    if peer.write_all(b"x").await.is_err() {
                        break;
                    }
                }
                peer
            });
            let started = Instant::now();
            let error = upstream.read_exact(&mut [0; 20]).await.unwrap_err();
            let took = started.elapsed();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(error.to_string(), UPSTREAM_READ_PASSED);
            assert!(
                took >= total && took < Duration::from_millis(900),
                "{took:?}"
            );
            let error = upstream.write_all(b"late").await.unwrap_err();
            assert_eq!(error.to_string(), UPSTREAM_WRITE_PASSED);
            drop(dripper.await.unwrap());
        });
    }

    /// **The end of the exchange is checked when a call starts.** A read that started before the
    /// end gets the byte that arrives after it, and the next read fails at once.
    #[test]
    fn a_read_that_started_before_the_end_keeps_its_own_wait() {
        block_on(async {
            let (gateway, mut peer) = tokio::io::duplex(64);
            let end = Instant::now() + Duration::from_millis(100);
            let mut upstream = Deadline::new(gateway, Duration::from_secs(5), end);
            let writer = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                peer.write_all(b"y").await.unwrap();
                peer
            });
            let mut got = [0; 1];
            assert_eq!(upstream.read(&mut got).await.unwrap(), 1);
            assert!(Instant::now() >= end);
            let again = Instant::now();
            let error = upstream.read(&mut got).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(again.elapsed() < Duration::from_millis(100));
            drop(writer.await.unwrap());
        });
    }
}
