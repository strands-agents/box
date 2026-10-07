//! One box, one owner: the `flock` that proves it, and the record naming who holds it.
//!
//! **The kernel releases an `flock` however the holder dies**, so a `kill -9`ed owner leaves no box
//! another `run` cannot take. That is why ownership is a lock rather than a stored process id: the
//! operating system reuses a pid, so a pid probe answers "is something alive" and never "is *that*
//! owner alive".
//!
//! The OS user boundary and the file mode are the only authorization.

use std::os::unix::io::AsRawFd as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{BoxError, DaemonError};
use crate::record::layout::BoxRoot;

/// The `live.json` format this build writes and accepts.
pub(crate) const LIVE_VERSION: u32 = 4;

/// An exclusive `flock`, held for as long as the value lives.
pub(crate) struct Lock {
    file: std::fs::File,
}

impl Lock {
    #[cfg(test)]
    pub(crate) fn try_acquire(path: &Path) -> Result<Option<Self>, BoxError> {
        Self::try_acquire_as(path, path)
    }

    /// Take the lock through `opened_path`, and report `display_path` on failure.
    #[cfg(test)]
    pub(crate) fn try_acquire_as(
        opened_path: &Path,
        display_path: &Path,
    ) -> Result<Option<Self>, BoxError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(opened_path)
            .map_err(|source| DaemonError::Lock {
                path: display_path.to_path_buf(),
                source,
            })?;
        Self::take(file, display_path)
    }

    /// Take the lock on an already-open file.
    pub(crate) fn try_acquire_file(
        file: std::fs::File,
        display_path: &Path,
    ) -> Result<Option<Self>, BoxError> {
        Self::take(file, display_path)
    }

    /// Whether another process holds the lock on `path`.
    #[cfg(test)]
    pub(crate) fn is_held(path: &Path) -> Result<bool, BoxError> {
        let file = match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(source) => {
                return Err(DaemonError::Lock {
                    path: path.to_path_buf(),
                    source,
                }
                .into());
            }
        };
        Ok(Self::take(file, path)?.is_none())
    }

    /// Take the lock on an already-open file, keeping it as a guard.
    fn take(file: std::fs::File, path: &Path) -> Result<Option<Self>, BoxError> {
        Ok(Self::try_take(&file, path)?.then_some(Self { file }))
    }

    /// One non-blocking attempt on a borrowed descriptor. `true` means this call now holds it.
    fn try_take(file: &std::fs::File, path: &Path) -> Result<bool, BoxError> {
        // SAFETY: flock only takes a descriptor this File owns.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EWOULDBLOCK) => Ok(false),
            _ => Err(DaemonError::Lock {
                path: path.to_path_buf(),
                source: error,
            }
            .into()),
        }
    }

    /// Release the lock on a borrowed descriptor.
    fn release(file: &std::fs::File) {
        // SAFETY: unlocking a descriptor this File owns.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        Self::release(&self.file);
    }
}

/// Which process owns this box, and the port its workload may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoxLive {
    /// The format's version, so a stale file from another build is a refusal.
    pub(crate) version: u32,

    /// The `run` process that owns this box.
    pub(crate) owner_pid: u32,

    /// The loopback port the containment profile permits for this box.
    pub(crate) proxy_port: u16,
}

impl BoxLive {
    /// Publish this process as the box's owner.
    pub(crate) fn publish(root: &BoxRoot, proxy_port: u16) -> Result<(), BoxError> {
        let record = Self {
            version: LIVE_VERSION,
            owner_pid: std::process::id(),
            proxy_port,
        };
        let text = serde_json::to_string_pretty(&record)
            .map_err(|source| DaemonError::LiveParse { source })?;
        root.write_private_file(&root.live_record(), &text, 0o600)
    }

    /// Read the record, or `None` when there is none this build accepts.
    #[cfg(test)]
    pub(crate) fn read(root: &BoxRoot) -> Option<Self> {
        let text = root.read_text(&root.live_record()).ok()?;
        let record: Self = serde_json::from_str(&text).ok()?;
        (record.version == LIVE_VERSION).then_some(record)
    }

    /// Remove the record. A missing file is success, because the point is that none remains.
    pub(crate) fn withdraw(root: &BoxRoot) {
        let _ = root.remove_file(&root.live_record());
    }
}
