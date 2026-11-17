//! Child ownership and bounded waits for the harness.

use super::shutdown;
use std::{
    io,
    ops::{Deref, DerefMut},
    os::unix::process::CommandExt,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

const SIGKILL: i32 = 9;

unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}

fn send(pid: i32, signal: i32) -> io::Result<()> {
    // SAFETY: kill(2) takes plain integers and touches no memory of ours.
    if unsafe { kill(pid, signal) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// A child that leads its own process group, and takes the whole group with it when
/// dropped.
pub(super) struct Owned(Child);

impl Owned {
    pub(super) fn spawn_group(command: &mut Command) -> io::Result<Self> {
        Ok(Self(command.process_group(0).spawn()?))
    }
}

impl Deref for Owned {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl DerefMut for Owned {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = send(-(self.0.id() as i32), SIGKILL);
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Call `ready` every `interval` until it yields a value, or return `None` once
/// `deadline` passes. A requested shutdown ends the wait with an error.
pub(super) fn wait_until<T>(
    deadline: Instant,
    interval: Duration,
    mut ready: impl FnMut() -> io::Result<Option<T>>,
) -> io::Result<Option<T>> {
    loop {
        shutdown::check()?;
        if let Some(value) = ready()? {
            return Ok(Some(value));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(interval);
    }
}

pub(super) fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, what)
}
