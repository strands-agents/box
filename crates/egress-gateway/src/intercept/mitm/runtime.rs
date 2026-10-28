//! The gateway's own multi-thread runtime, on one thread that the adapter starts.
//!
//! The runtime is not the caller's. A box creates and drops its [`MitmHandle`](super::MitmHandle)
//! inside async code, and tokio panics when a runtime drops in an async context. A runtime that the
//! box shares would also make gateway latency depend on the box's own load, and the reverse. So one
//! named thread owns this runtime for its whole life, and the runtime drops on that thread.

use std::io;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

use tokio::sync::{Semaphore, watch};

use super::SharedState;
use super::listener::{self, BoundListener};
use crate::error::{ProxyError, Result};

/// The thread that runs the gateway, and the two signals that `MitmHandle` uses to stop it.
pub(super) struct GatewayThread {
    /// Set to `true` to stop the accept loop.
    stop: watch::Sender<bool>,
    /// Answered when the accept loop has dropped its listener and its state.
    accept_ended: Mutex<Option<Receiver<()>>>,
}

impl GatewayThread {
    /// Start the gateway thread, and return when its runtime serves `listener` or the start failed.
    pub(super) fn start(listener: BoundListener, state: Arc<SharedState>) -> Result<Self> {
        let (stop, stopping) = watch::channel(false);
        let (ready, started) = mpsc::sync_channel::<io::Result<()>>(1);
        let (ended, accept_ended) = mpsc::sync_channel::<()>(1);
        std::thread::Builder::new()
            .name("strands-box-egress".to_string())
            .spawn(move || serve(listener, state, stopping, ready, ended))
            .map_err(|e| ProxyError::Io(format!("starting the egress gateway thread: {e}")))?;
        match started.recv() {
            Ok(Ok(())) => Ok(Self {
                stop,
                accept_ended: Mutex::new(Some(accept_ended)),
            }),
            Ok(Err(e)) => Err(ProxyError::Io(format!(
                "starting the egress gateway runtime: {e}"
            ))),
            Err(_) => Err(ProxyError::Io(
                "the egress gateway thread ended before it served".to_string(),
            )),
        }
    }

    /// Ask the accept loop to stop. A memory write and a wakeup: no I/O, so a signal cannot
    /// interrupt it, and it needs no file descriptor and no free connection slot.
    pub(super) fn stop(&self) {
        self.stop.send_replace(true);
    }

    /// Block until the accept loop has dropped its listener and its state. Returns at once when
    /// the gateway thread has ended, because its sender is then gone.
    pub(super) fn wait_for_accept_end(&mut self) {
        let ended = self
            .accept_ended
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(ended) = ended {
            let _ = ended.recv();
        }
    }
}

/// The body of the gateway thread: build the runtime, serve until stopped, then drain.
fn serve(
    listener: BoundListener,
    state: Arc<SharedState>,
    stopping: watch::Receiver<bool>,
    ready: SyncSender<io::Result<()>>,
    ended: SyncSender<()>,
) {
    let slots = slot_count(state.config.max_connections);
    let workers = worker_count();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        // Each connection runs at most one blocking section at a time, and each worker can hand
        // its core away once, so this keeps the thread bound of one thread per connection.
        .max_blocking_threads(slots.saturating_add(workers))
        .thread_name("strands-box-egress-worker")
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    runtime.block_on(async move {
        let listener = match listener.into_tokio() {
            Ok(listener) => listener,
            Err(e) => {
                let _ = ready.send(Err(e));
                return;
            }
        };
        let semaphore = Arc::new(Semaphore::new(slots));
        let _ = ready.send(Ok(()));
        listener::accept_loop(listener, state, Arc::clone(&semaphore), stopping).await;
        let _ = ended.send(());
        // Every connection holds one slot until it ends, so all slots back means no connection
        // is open, and the runtime can drop with no task in flight.
        let _ = semaphore.acquire_many(slots as u32).await;
    });
    // The runtime drops here, on its own thread, outside any async context.
}

/// Two to four workers. Policy calls and heavy work leave the worker, so more workers add little.
fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(2, 4)
}

/// The connection cap as a semaphore size: zero means one, as before, and a value above
/// `u32::MAX` means no practical limit, inside the bounds of `Semaphore` and `acquire_many`.
pub(super) fn slot_count(max_connections: usize) -> usize {
    max_connections
        .clamp(1, u32::MAX as usize)
        .min(Semaphore::MAX_PERMITS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slot_count_keeps_zero_as_one_and_bounds_a_huge_cap() {
        assert_eq!(slot_count(0), 1);
        assert_eq!(slot_count(256), 256);
        assert_eq!(
            slot_count(usize::MAX),
            (u32::MAX as usize).min(Semaphore::MAX_PERMITS)
        );
    }

    #[test]
    fn the_worker_count_is_two_to_four() {
        assert!((2..=4).contains(&worker_count()));
    }
}
