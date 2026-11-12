//! Response bodies with bounded, ordered credential redaction.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use credentials::ResponseRedactor;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::{Body, Bytes, Frame, SizeHint};

use crate::client::http::UpstreamBody;
use crate::effect::ReplyObserver;

type Stream = UnsyncBoxBody<Bytes, io::Error>;

/// The input block size for each transform, independent of its credential matching state.
const REDACTION_BLOCK_BYTES: usize = 8 * 1024;

/// A captured response or a stream processed by the selected credential controls.
pub(crate) enum ResponseBody {
    Captured(Full<Bytes>),
    Streaming(Stream),
}

impl ResponseBody {
    pub(crate) fn streaming(body: UpstreamBody, redactors: Vec<ResponseRedactor>) -> Self {
        let mut body = body.boxed_unsync();
        for redactor in redactors {
            let finished = body.is_end_stream();
            body = RedactedBody {
                source: body,
                redactor: Some(redactor),
                pending: Bytes::new(),
                finished,
            }
            .boxed_unsync();
        }
        Self::Streaming(body)
    }

    /// Hand a copy of every byte that reaches the workload, up to `limit`, to `observer`.
    pub(crate) fn observed(self, observer: Box<dyn ReplyObserver>, limit: usize) -> Self {
        let source = match self {
            Self::Captured(body) => body.map_err(|never| match never {}).boxed_unsync(),
            Self::Streaming(body) => body,
        };
        Self::Streaming(
            ObservedBody {
                source,
                copy: Vec::new(),
                limit,
                observer: Some(observer),
            }
            .boxed_unsync(),
        )
    }
}

/// Copies a reply as it streams, and reports it when the stream ends or is dropped.
struct ObservedBody {
    source: Stream,
    copy: Vec<u8>,
    limit: usize,
    observer: Option<Box<dyn ReplyObserver>>,
}

impl Body for ObservedBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.source).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && this.observer.is_some()
                {
                    if this.copy.len() + data.len() > this.limit {
                        this.abandon();
                    } else {
                        this.copy.extend_from_slice(data);
                    }
                }
                // A server may hold the stream open after its answer, so finish as soon as the
                // observer has it rather than waiting for an end that may never come. A server
                // writing a sized body stops polling once the last byte is out, so the reply also
                // finishes when the source says it has ended, not only on a final `None`.
                let copy = &this.copy;
                if this
                    .observer
                    .as_mut()
                    .is_some_and(|observer| observer.complete(copy))
                    || this.source.is_end_stream()
                {
                    this.finish();
                }
            }
            Poll::Ready(None) => this.finish(),
            Poll::Ready(Some(Err(_))) => this.abandon(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.source.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.source.size_hint()
    }
}

impl ObservedBody {
    /// Hand the copy to the observer and free it.
    fn finish(&mut self) {
        if let Some(observer) = self.observer.take() {
            observer.finished(&std::mem::take(&mut self.copy));
        }
    }

    /// Tell the observer the reply did not finish, and free the copy.
    fn abandon(&mut self) {
        self.copy = Vec::new();
        if let Some(observer) = self.observer.take() {
            observer.abandoned();
        }
    }
}

impl Drop for ObservedBody {
    fn drop(&mut self) {
        self.abandon();
    }
}

impl From<Vec<u8>> for ResponseBody {
    fn from(body: Vec<u8>) -> Self {
        Self::Captured(Full::new(Bytes::from(body)))
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        match self.get_mut() {
            Self::Captured(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|frame| frame.map(|frame| frame.map_err(|never| match never {}))),
            Self::Streaming(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Captured(body) => body.is_end_stream(),
            Self::Streaming(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Captured(body) => body.size_hint(),
            Self::Streaming(body) => body.size_hint(),
        }
    }
}

/// One transform that retains at most one source frame and a credential-sized tail.
struct RedactedBody {
    source: Stream,
    redactor: Option<ResponseRedactor>,
    pending: Bytes,
    finished: bool,
}

impl Body for RedactedBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        for _ in 0..16 {
            if this.finished {
                return Poll::Ready(None);
            }
            if !this.pending.is_empty() {
                let chunk = this
                    .pending
                    .split_to(this.pending.len().min(REDACTION_BLOCK_BYTES));
                let output = this.redactor.as_mut().unwrap().push(&chunk);
                if !output.is_empty() {
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(output)))));
                }
                continue;
            }
            match ready!(Pin::new(&mut this.source).poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        this.pending = data;
                    }
                }
                Some(Err(error)) => {
                    this.finished = true;
                    return Poll::Ready(Some(Err(error)));
                }
                None => {
                    this.finished = true;
                    let output = this.redactor.take().unwrap().finish();
                    return Poll::Ready(
                        (!output.is_empty()).then(|| Ok(Frame::data(Bytes::from(output)))),
                    );
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }

    fn size_hint(&self) -> SizeHint {
        if self.finished {
            SizeHint::with_exact(0)
        } else {
            SizeHint::default()
        }
    }
}
