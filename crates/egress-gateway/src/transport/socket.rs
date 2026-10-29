//! The sockets of one connection, and what each one accepted.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::effect::EffectOutcome;
use crate::error::{ProxyError, Result};

/// Run `future` on a runtime for this connection only, so a slow policy call blocks only it.
pub(crate) fn block_on<F: Future>(future: F) -> Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| ProxyError::Io(format!("connection runtime: {e}")))?;
    Ok(runtime.block_on(future))
}

/// A blocking socket from the accept loop, made async inside the connection's runtime.
pub(crate) trait Socket {
    type Async: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn into_async(self) -> io::Result<Self::Async>;
}

impl Socket for std::net::TcpStream {
    type Async = tokio::net::TcpStream;

    fn into_async(self) -> io::Result<Self::Async> {
        self.set_nonblocking(true)?;
        tokio::net::TcpStream::from_std(self)
    }
}

impl Socket for std::os::unix::net::UnixStream {
    type Async = tokio::net::UnixStream;

    fn into_async(self) -> io::Result<Self::Async> {
        self.set_nonblocking(true)?;
        tokio::net::UnixStream::from_std(self)
    }
}

/// What one stream accepted for writing, and how its writes ended.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Writes {
    /// Bytes the stream accepted.
    pub(crate) accepted: usize,
    /// Whether a flush succeeded after the last accepted byte.
    flushed: bool,
    /// The first write or flush error, and whether it came from a flush.
    failure: Option<(io::ErrorKind, bool)>,
}

impl Writes {
    /// The outcome of a message that starts at `start`, in an exchange that ended with `error`.
    pub(crate) fn outcome(self, start: usize, error: Option<io::ErrorKind>) -> EffectOutcome {
        let accepted_bytes = self.accepted.saturating_sub(start);
        let short = match (self.failure, error) {
            (Some((_, true)), _) => return EffectOutcome::Indeterminate { accepted_bytes },
            (Some((kind, false)), _) => kind,
            (None, Some(kind)) if !self.flushed => kind,
            (None, _) => return EffectOutcome::Completed(accepted_bytes),
        };
        if accepted_bytes == 0 {
            EffectOutcome::Failed {
                accepted_bytes,
                error_kind: short,
            }
        } else {
            EffectOutcome::Partial {
                accepted_bytes,
                error_kind: short,
            }
        }
    }
}

/// The [`Writes`] of one stream, shared by the stream and the exchange that reads them.
#[derive(Clone, Debug, Default)]
pub(crate) struct WriteCount(Arc<Mutex<Writes>>);

impl WriteCount {
    pub(crate) fn get(&self) -> Writes {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn note<T>(&self, result: &io::Result<T>, accepted: usize, flush: bool) {
        let mut writes = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match result {
            Ok(_) if flush => writes.flushed = true,
            Ok(_) if accepted > 0 => {
                writes.accepted += accepted;
                writes.flushed = false;
            }
            Ok(_) => {}
            Err(error) => {
                writes.failure.get_or_insert((error.kind(), flush));
            }
        }
    }
}

/// The raw first request head, so the box can refuse a request that states two framings.
#[derive(Clone, Debug, Default)]
pub(crate) struct HeadCopy(Arc<Mutex<Head>>);

#[derive(Debug, Default)]
struct Head {
    bytes: Vec<u8>,
    /// `Some(true)` once the head is whole within [`MAX_HEAD_BYTES`]; `Some(false)` once it is not.
    whole: Option<bool>,
    /// Where the reads are in the request line.
    line: Line,
}

impl HeadCopy {
    /// Take the head, or `None` when it passed [`MAX_HEAD_BYTES`].
    pub(crate) fn take(&self) -> Option<Vec<u8>> {
        let mut head = self.0.lock().unwrap_or_else(|e| e.into_inner());
        (head.whole == Some(true)).then(|| std::mem::take(&mut head.bytes))
    }

    /// Copy `bytes`, mask the target that hyper reads, and report whether the head is done.
    fn note(&self, bytes: &mut [u8]) -> bool {
        let mut head = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if head.whole.is_some() {
            return true;
        }
        let from = head.bytes.len().saturating_sub(2);
        head.bytes.extend_from_slice(bytes);
        head.line.mask(bytes);
        // Parse only when the new bytes can end a head, as hyper does.
        let blank_line = head.bytes[from..]
            .windows(2)
            .any(|pair| pair == b"\n\n" || pair == b"\n\r");
        if blank_line {
            let mut fields = [httparse::EMPTY_HEADER; 64];
            if let Ok(httparse::Status::Complete(end)) =
                httparse::Request::new(&mut fields).parse(&head.bytes)
            {
                head.bytes.truncate(end);
                head.whole = Some(end <= MAX_HEAD_BYTES);
                return true;
            }
        }
        if head.bytes.len() > MAX_HEAD_BYTES {
            head.whole = Some(false);
        }
        head.whole.is_some()
    }
}

/// A place in the request line.
#[derive(Clone, Copy, Debug)]
enum Line {
    /// In the method, after any blank lines: its length, and whether it still spells `CONNECT`.
    Method { len: usize, connect: bool },
    /// In the target.
    Target { connect: bool },
    /// Past the target.
    Done,
}

impl Default for Line {
    fn default() -> Self {
        Line::Method {
            len: 0,
            connect: true,
        }
    }
}

impl Line {
    /// Replace the target bytes that hyper's URI parser refuses; the box forwards the raw copy.
    /// A CONNECT target stays, because the box reads its authority from hyper.
    fn mask(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *self = match (*self, *byte) {
                (Line::Done, _) => return,
                (Line::Method { len: 0, .. }, b'\r' | b'\n') => continue,
                (Line::Method { len, connect }, b' ') => Line::Target {
                    connect: connect && len == b"CONNECT".len(),
                },
                (Line::Method { .. }, b'\r' | b'\n')
                | (Line::Target { .. }, b' ' | b'\r' | b'\n') => Line::Done,
                (Line::Method { len, connect }, next) => Line::Method {
                    len: len + 1,
                    connect: connect && b"CONNECT".get(len) == Some(&next),
                },
                (Line::Target { connect: false }, b'"' | b'<' | b'>' | b'`') => {
                    *byte = b'_';
                    continue;
                }
                (line, _) => line,
            };
        }
    }
}

/// The largest head the box reads.
pub(crate) const MAX_HEAD_BYTES: usize = 64 * 1024;

/// A stream that counts what it accepts, and can copy the first head it reads.
pub(crate) struct Counted<S> {
    inner: S,
    writes: WriteCount,
    head: Option<HeadCopy>,
}

impl<S> Counted<S> {
    pub(crate) fn new(inner: S, writes: WriteCount, head: Option<HeadCopy>) -> Self {
        Self {
            inner,
            writes,
            head,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = ready!(Pin::new(&mut this.inner).poll_read(cx, buf));
        if let Some(head) = &this.head
            && head.note(&mut buf.filled_mut()[before..])
        {
            this.head = None;
        }
        Poll::Ready(result)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = ready!(Pin::new(&mut this.inner).poll_write(cx, buf));
        this.writes
            .note(&result, *result.as_ref().unwrap_or(&0), false);
        Poll::Ready(result)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = ready!(Pin::new(&mut this.inner).poll_write_vectored(cx, bufs));
        this.writes
            .note(&result, *result.as_ref().unwrap_or(&0), false);
        Poll::Ready(result)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        this.writes.note(&result, 0, true);
        Poll::Ready(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The kind of the first I/O error in `error`'s chain.
pub(crate) fn error_kind(error: &(dyn std::error::Error + 'static)) -> io::ErrorKind {
    let mut source = Some(error);
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return error.kind();
        }
        source = error.source();
    }
    io::ErrorKind::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writes(accepted: usize, flushed: bool, failure: Option<(io::ErrorKind, bool)>) -> Writes {
        Writes {
            accepted,
            flushed,
            failure,
        }
    }

    #[test]
    fn the_head_copy_ends_where_httparse_ends_the_head() {
        let head = HeadCopy::default();
        assert!(!head.note(&mut b"POST / HTTP/1.1\r\nContent-Length: 4\r".to_vec()));
        assert!(!head.note(&mut b"\nTransfer-Encoding: chunked\r\n\r".to_vec()));
        assert!(head.note(&mut b"\nbody".to_vec()));
        assert_eq!(
            head.take().unwrap(),
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
        );

        // Blank lines before the request line are part of the head, as hyper's parser skips them.
        let leading = HeadCopy::default();
        leading.note(&mut b"\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\nrest".to_vec());
        assert_eq!(
            leading.take().unwrap(),
            b"\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n"
        );

        let bare = HeadCopy::default();
        bare.note(&mut b"GET / HTTP/1.1\nHost: h\n\nrest".to_vec());
        assert_eq!(bare.take().unwrap(), b"GET / HTTP/1.1\nHost: h\n\n");

        let large = HeadCopy::default();
        large.note(&mut b"GET / HTTP/1.1\r\nX-Big: ".to_vec());
        large.note(&mut vec![b'a'; MAX_HEAD_BYTES]);
        large.note(&mut b"\r\n\r\n".to_vec());
        assert_eq!(large.take(), None, "a head over the limit is refused");
    }

    #[test]
    fn hyper_reads_a_masked_target_and_the_copy_keeps_the_raw_one() {
        let raw = b"GET /s?q=stars:>100&r=\"<a>`\" HTTP/1.1\r\nX: <>\r\n\r\n";
        let head = HeadCopy::default();
        let mut read = raw.to_vec();
        assert!(head.note(&mut read));
        assert_eq!(
            read,
            b"GET /s?q=stars:_100&r=__a___ HTTP/1.1\r\nX: <>\r\n\r\n"
        );
        assert_eq!(head.take().unwrap(), raw);
        assert!("/s?q=stars:>100".parse::<hyper::Uri>().is_err());
        assert!("/s?q=stars:_100&r=__a___".parse::<hyper::Uri>().is_ok());

        // A target split across reads, after a blank line.
        let split = HeadCopy::default();
        let (mut first, mut second) = (b"\r\nGET /a<".to_vec(), b"b HTTP/1.1\r\n\r\n".to_vec());
        split.note(&mut first);
        split.note(&mut second);
        assert_eq!([first, second].concat(), b"\r\nGET /a_b HTTP/1.1\r\n\r\n");

        // The box reads a CONNECT authority from hyper, so it stays as sent.
        let connect = HeadCopy::default();
        let mut read = b"CONNECT <h>:443 HTTP/1.1\r\n\r\n".to_vec();
        connect.note(&mut read);
        assert_eq!(read, b"CONNECT <h>:443 HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn a_message_flushed_whole_is_completed() {
        assert_eq!(
            writes(7, true, None).outcome(0, None),
            EffectOutcome::Completed(7)
        );
        // The response failed after the request left whole.
        assert_eq!(
            writes(7, true, None).outcome(0, Some(io::ErrorKind::ConnectionReset)),
            EffectOutcome::Completed(7)
        );
        // Bytes accepted before the message started are not its own.
        assert_eq!(
            writes(32, true, None).outcome(25, None),
            EffectOutcome::Completed(7)
        );
    }

    #[test]
    fn a_write_error_is_failed_or_partial() {
        let broken = Some((io::ErrorKind::BrokenPipe, false));
        assert_eq!(
            writes(0, false, broken).outcome(0, Some(io::ErrorKind::Other)),
            EffectOutcome::Failed {
                accepted_bytes: 0,
                error_kind: io::ErrorKind::BrokenPipe,
            }
        );
        assert_eq!(
            writes(3, false, broken).outcome(0, Some(io::ErrorKind::Other)),
            EffectOutcome::Partial {
                accepted_bytes: 3,
                error_kind: io::ErrorKind::BrokenPipe,
            }
        );
    }

    #[test]
    fn a_failed_flush_is_indeterminate() {
        assert_eq!(
            writes(7, false, Some((io::ErrorKind::TimedOut, true))).outcome(0, None),
            EffectOutcome::Indeterminate { accepted_bytes: 7 }
        );
    }

    #[test]
    fn a_message_cut_short_takes_the_error_that_ended_the_exchange() {
        assert_eq!(
            writes(3, false, None).outcome(0, Some(io::ErrorKind::TimedOut)),
            EffectOutcome::Partial {
                accepted_bytes: 3,
                error_kind: io::ErrorKind::TimedOut,
            }
        );
        assert_eq!(
            writes(0, false, None).outcome(0, Some(io::ErrorKind::TimedOut)),
            EffectOutcome::Failed {
                accepted_bytes: 0,
                error_kind: io::ErrorKind::TimedOut,
            }
        );
    }
}
