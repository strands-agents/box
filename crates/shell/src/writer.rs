//! A write descriptor the kernel serves, whose outcome is recorded when its last copy closes.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Mutex as StdMutex;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::effect::EffectResult;
use crate::kernel::Permit;

/// The task that moves a writer's bytes and ends with how the write ended.
pub(crate) type Drain = Pin<Box<dyn Future<Output = EffectResult> + Send>>;

/// A write descriptor the kernel serves, and the drain that ends after its last copy closes.
pub(crate) struct ServedWriter {
    /// Upgrades while any copy of the descriptor is open.
    pub(crate) sender: mpsc::WeakSender<Bytes>,
    pub(crate) drain: Drain,
}

/// One served write whose outcome is recorded after its drain ends.
struct Pending {
    sender: mpsc::WeakSender<Bytes>,
    recorded: oneshot::Receiver<io::Result<()>>,
}

/// The served writes of one Call whose outcome is not yet known to be recorded.
#[derive(Default)]
pub(crate) struct Writes {
    pending: StdMutex<Vec<Pending>>,
    /// Held by the one caller that waits; a concurrent decision waits behind it.
    settling: tokio::sync::Mutex<()>,
}

/// A closed write taken out to wait on, put back when its waiter is cancelled.
struct Taken<'a> {
    writes: &'a Writes,
    write: Option<Pending>,
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        if let Some(write) = self.write.take() {
            self.writes.lock().push(write);
        }
    }
}

impl Writes {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Run `writer`'s drain, then record its outcome through `permit`.
    pub(crate) fn record_at_close(&self, writer: ServedWriter, permit: Permit) {
        let ServedWriter { sender, drain } = writer;
        let (recorded_tx, recorded) = oneshot::channel();
        tokio::task::spawn_local(async move {
            let result = drain.await;
            let _ = recorded_tx.send(permit.record(result).await);
        });
        self.lock().push(Pending { sender, recorded });
    }

    /// One write whose every copy is closed, taken out to wait on.
    fn take_closed(&self) -> Option<Taken<'_>> {
        let mut pending = self.lock();
        let index = pending
            .iter()
            .position(|write| write.sender.upgrade().is_none())?;
        let write = pending.swap_remove(index);
        Some(Taken {
            writes: self,
            write: Some(write),
        })
    }

    /// Wait until each write whose every copy is closed has recorded its outcome.
    ///
    /// A write still open is not waited for. A recording failure is returned once. Callers wait
    /// one at a time, and a cancelled caller leaves its write for the next one.
    pub(crate) async fn record_closed(&self) -> io::Result<()> {
        let _settling = self.settling.lock().await;
        let mut failure = None;
        while let Some(mut taken) = self.take_closed() {
            if let Some(write) = taken.write.as_mut() {
                // A drain dropped before it recorded leaves its permit to record indeterminate.
                if let Ok(Err(error)) = (&mut write.recorded).await {
                    failure.get_or_insert(error);
                }
            }
            taken.write = None;
        }
        failure.map_or(Ok(()), Err)
    }
}
