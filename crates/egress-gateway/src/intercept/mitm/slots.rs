//! The connection slots, and the queue of the connections that wait between two requests.
//!
//! A kept-alive connection holds its slot while it waits for its next request. When a new
//! connection finds no free slot, the oldest waiting connection gives its slot back: one for each
//! connection that waits. A connection inside an exchange never gives its slot back for pressure, so
//! a steady load near the cap does not end keep-alive for the busy connections.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError, watch};

/// The connection cap, and the connections that wait between requests.
pub(super) struct Slots {
    permits: Arc<Semaphore>,
    total: usize,
    queue: Mutex<Queue>,
}

/// The waits that the slot rules keep.
#[derive(Default)]
struct Queue {
    /// The connections that wait between requests, oldest first, each with the signal that asks
    /// it to close.
    idle: VecDeque<(u64, Arc<Notify>)>,
    /// The new connections that wait for a slot and found no idle connection to close.
    waiting: VecDeque<u64>,
    /// The id of the next slot or waiter.
    next: u64,
}

impl Queue {
    fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }
}

impl Slots {
    /// `total` slots; the caller keeps it at least one.
    pub(super) fn new(total: usize) -> Arc<Self> {
        Arc::new(Self {
            permits: Arc::new(Semaphore::new(total)),
            total,
            queue: Mutex::new(Queue::default()),
        })
    }

    fn queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One slot for a new connection. With no free slot, ask the oldest idle connection to close,
    /// or, with none, wait for a busy one to end. `None` once the slots are closed. `stopping` is
    /// the gateway stop, which the slot passes to its connection.
    pub(super) async fn acquire(
        self: &Arc<Self>,
        stopping: &watch::Receiver<bool>,
    ) -> Option<Slot> {
        let permit = match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::Closed) => return None,
            Err(TryAcquireError::NoPermits) => {
                let _waiter = Waiter::new(self);
                Arc::clone(&self.permits).acquire_owned().await.ok()?
            }
        };
        let id = self.queue().id();
        Some(Slot {
            _permit: permit,
            id,
            slots: Arc::clone(self),
            release: Arc::new(Notify::new()),
            stopping: stopping.clone(),
        })
    }

    /// Wait until every slot is free: no connection is open.
    pub(super) async fn all_free(&self) {
        let _ = self.permits.acquire_many(self.total as u32).await;
    }
}

/// One new connection that waits for a slot. It leaves the queue when its wait ends.
struct Waiter<'a> {
    slots: &'a Slots,
    id: Option<u64>,
}

impl<'a> Waiter<'a> {
    /// Close the oldest idle connection for this waiter, or queue the waiter when there is none.
    fn new(slots: &'a Slots) -> Self {
        let mut queue = slots.queue();
        if let Some((_, release)) = queue.idle.pop_front() {
            release.notify_one();
            return Self { slots, id: None };
        }
        let id = queue.id();
        queue.waiting.push_back(id);
        Self {
            slots,
            id: Some(id),
        }
    }
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.slots.queue().waiting.retain(|waiting| *waiting != id);
        }
    }
}

/// One held connection slot. The slot frees when this value drops: at the end of the connection,
/// on any error, or in a panic unwind.
///
/// It also carries the two reasons for its connection to close early: the gateway stops, or a new
/// connection needs the slot while this one waits between requests.
pub(super) struct Slot {
    _permit: OwnedSemaphorePermit,
    id: u64,
    slots: Arc<Slots>,
    release: Arc<Notify>,
    stopping: watch::Receiver<bool>,
}

impl Slot {
    /// The connection waits for its next request: it closes at once for a new connection that
    /// waits with no idle connection to close, else it joins the idle queue.
    pub(super) fn idle(&self) {
        let mut queue = self.slots.queue();
        if queue.waiting.pop_front().is_some() {
            self.release.notify_one();
        } else {
            queue.idle.push_back((self.id, Arc::clone(&self.release)));
        }
    }

    /// The next request of the connection has started: it leaves the idle queue.
    pub(super) fn busy(&self) {
        self.slots.queue().idle.retain(|(id, _)| *id != self.id);
    }

    /// The gateway stop, which also ends a relay after the HTTP phase of the connection.
    pub(super) fn stopping(&self) -> watch::Receiver<bool> {
        self.stopping.clone()
    }

    /// Resolve when the connection should close: the gateway stops, or a new connection asked for
    /// this slot while the connection waited.
    pub(super) fn released(&self) -> impl Future<Output = ()> + '_ {
        let mut stopping = self.stopping.clone();
        async move {
            tokio::select! {
                () = self.release.notified() => {}
                _ = stopping.wait_for(|stop| *stop) => {}
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.busy();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// Whether `slot` was asked to close within a short wait.
    async fn asked_to_close(slot: &Slot) -> bool {
        tokio::time::timeout(Duration::from_millis(50), slot.released())
            .await
            .is_ok()
    }

    /// **A new connection with no free slot closes only the oldest idle connection.** A busy
    /// connection and a newer idle one stay open, and the slot that the closed one frees goes to
    /// the new connection.
    #[test]
    fn a_waiting_connection_closes_only_the_oldest_idle_one() {
        block_on(async {
            let (_stop, stopping) = watch::channel(false);
            let slots = Slots::new(3);
            let busy = slots.acquire(&stopping).await.unwrap();
            let older = slots.acquire(&stopping).await.unwrap();
            let newer = slots.acquire(&stopping).await.unwrap();
            older.idle();
            newer.idle();

            let waiting = tokio::spawn({
                let (slots, stopping) = (Arc::clone(&slots), stopping.clone());
                async move { slots.acquire(&stopping).await.is_some() }
            });
            tokio::task::yield_now().await;
            assert!(asked_to_close(&older).await, "the oldest idle connection");
            assert!(!asked_to_close(&newer).await, "a newer idle connection");
            assert!(!asked_to_close(&busy).await, "a busy connection");
            drop(older);
            assert!(waiting.await.unwrap(), "the freed slot goes to the new one");
        });
    }

    /// **A connection that goes idle while a new connection waits with no idle one to close
    /// closes at once**, and a connection whose next request started leaves the idle queue.
    #[test]
    fn an_idle_connection_yields_to_a_queued_waiter_and_a_busy_one_leaves_the_queue() {
        block_on(async {
            let (_stop, stopping) = watch::channel(false);
            let slots = Slots::new(2);
            let first = slots.acquire(&stopping).await.unwrap();
            let second = slots.acquire(&stopping).await.unwrap();
            second.idle();
            second.busy();

            let waiting = tokio::spawn({
                let (slots, stopping) = (Arc::clone(&slots), stopping.clone());
                async move { slots.acquire(&stopping).await.is_some() }
            });
            tokio::task::yield_now().await;
            assert!(
                !asked_to_close(&second).await,
                "a connection that left the queue keeps its slot"
            );
            first.idle();
            assert!(asked_to_close(&first).await, "the queued waiter takes it");
            drop(first);
            assert!(waiting.await.unwrap());
            second.idle();
            assert!(
                !asked_to_close(&second).await,
                "the waiter was served, so a later idle connection stays"
            );
        });
    }

    /// **The gateway stop asks every connection to close.**
    #[test]
    fn the_stop_releases_every_slot() {
        block_on(async {
            let (stop, stopping) = watch::channel(false);
            let slots = Slots::new(2);
            let slot = slots.acquire(&stopping).await.unwrap();
            assert!(!asked_to_close(&slot).await);
            stop.send_replace(true);
            assert!(asked_to_close(&slot).await);
            drop(stop);
            let other = slots.acquire(&stopping).await.unwrap();
            assert!(asked_to_close(&other).await, "a dropped stop is a stop");
        });
    }
}
