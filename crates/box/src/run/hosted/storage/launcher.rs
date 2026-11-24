//! Preserve the original caller's namespace-creation authority for contained child starts.
//!
//! Hosted filesystem effects never run here. The only input is an already-built private
//! containment command; the existing owner admission lock serializes its synchronous spawn.

use std::io;
use std::sync::mpsc::{self, SyncSender};

use tokio::process::{Child, Command};

struct Request {
    command: Command,
    runtime: tokio::runtime::Handle,
    result: SyncSender<io::Result<Child>>,
}

pub(super) struct Launcher {
    closed: bool,
    sender: Option<SyncSender<Request>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Launcher {
    /// Call before the broker serving thread drops capabilities.
    pub(super) fn start() -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Request>(0);
        let thread = std::thread::Builder::new()
            .name("box-leaf-launch".into())
            .spawn(move || {
                while let Ok(mut request) = receiver.recv() {
                    // Register the child's I/O with the caller's existing runtime. Entering
                    // a handle changes no credentials and runs no filesystem effects here.
                    let _runtime = request.runtime.enter();
                    let result = request.command.spawn();
                    if let Err(mpsc::SendError(Ok(mut child))) = request.result.send(result) {
                        // The caller normally cannot cancel this synchronous handoff. If it
                        // unwinds, stop the complete group before dropping its child handle.
                        if let Some(pid) = child.id() {
                            // SAFETY: this trusted command creates its own process group.
                            unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
                        }
                        let _ = child.start_kill();
                    }
                }
            })?;
        Ok(Self {
            closed: false,
            sender: Some(sender),
            thread: Some(thread),
        })
    }

    pub(super) fn spawn(&self, command: Command) -> io::Result<Child> {
        if self.closed {
            return Err(io::Error::other("contained launch authority is closed"));
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let (result, receiver) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| io::Error::other("contained launch authority is closed"))?
            .send(Request {
                command,
                runtime,
                result,
            })
            .map_err(|_| io::Error::other("contained launch authority stopped"))?;
        receiver
            .recv()
            .map_err(|_| io::Error::other("contained launch authority did not return a child"))?
    }

    /// Refuse new commands while keeping the spawning thread alive for its children.
    pub(super) fn close(&mut self) {
        self.closed = true;
    }

    /// The broker has stopped its native groups before the owner calls this method.
    pub(super) fn finish(&mut self) -> io::Result<()> {
        self.close();
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| io::Error::other("contained launch authority panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Launcher {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}
