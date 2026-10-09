//! Child ownership and bounded waits shared by the harness and its oracle.

use super::shutdown;
use std::{
    io,
    ops::{Deref, DerefMut},
    os::unix::process::CommandExt,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

const SIGINT: i32 = 2;
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

/// A child that is killed and reaped when dropped. A group child takes its whole
/// process group with it.
pub(super) struct Owned {
    child: Child,
    group: bool,
}

impl Owned {
    pub(super) fn spawn(command: &mut Command) -> io::Result<Self> {
        Ok(Self {
            child: command.spawn()?,
            group: false,
        })
    }

    /// Spawn the child as the leader of a new process group.
    pub(super) fn spawn_group(command: &mut Command) -> io::Result<Self> {
        Ok(Self {
            child: command.process_group(0).spawn()?,
            group: true,
        })
    }

    pub(super) fn interrupt(&self) -> io::Result<()> {
        send(self.child.id() as i32, SIGINT)
    }
}

impl Deref for Owned {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}

impl DerefMut for Owned {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if self.group {
            let _ = send(-(self.child.id() as i32), SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wait_until_deadline() {
        let mut calls = 0;
        let value = wait_until(
            Instant::now() + Duration::from_secs(1),
            Duration::ZERO,
            || {
                calls += 1;
                Ok((calls == 3).then_some(calls))
            },
        );
        assert_eq!(value.unwrap(), Some(3));
        let never = wait_until(Instant::now(), Duration::ZERO, || Ok(None::<()>));
        assert_eq!(never.unwrap(), None);
    }
    #[test]
    fn group_drop_kills_descendants() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30 & echo $!; wait"]);
        command.stdout(std::process::Stdio::piped());
        let mut child = Owned::spawn_group(&mut command).unwrap();
        let mut line = String::new();
        io::BufRead::read_line(
            &mut io::BufReader::new(child.stdout.take().unwrap()),
            &mut line,
        )
        .unwrap();
        let grandchild: i32 = line.trim().parse().unwrap();
        drop(child);
        let gone = wait_until(
            Instant::now() + Duration::from_secs(2),
            Duration::from_millis(10),
            || Ok(send(grandchild, 0).is_err().then_some(())),
        );
        assert_eq!(gone.unwrap(), Some(()));
    }
}
