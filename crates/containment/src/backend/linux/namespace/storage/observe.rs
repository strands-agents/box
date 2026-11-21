//! Event-driven observation of one declared root in the receiving mount namespace.

use std::fs::File;
use std::io::{Seek as _, SeekFrom};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use super::mountinfo::{MountTable, SourceObservation};
use super::{failure, identity, io_failure, open_child, transport};
use crate::ContainmentError;

/// A pinned candidate whose opened mount identity matches the receiver's mount table.
pub(super) struct Observation {
    pub(super) source: OwnedFd,
    pub(super) filesystem: String,
    #[cfg_attr(
        not(any(test, feature = "test-support")),
        allow(dead_code, reason = "qualification receipts consume observer counters")
    )]
    pub(super) pending_observations: u64,
    #[cfg_attr(
        not(any(test, feature = "test-support")),
        allow(dead_code, reason = "qualification receipts consume observer counters")
    )]
    pub(super) notification_wakeups: u64,
}

/// Wait for a supported attachment without treating the underlying directory as storage.
pub(super) fn wait(
    root: &Path,
    parent: &OwnedFd,
    control: &UnixStream,
    observe_pending: bool,
) -> Result<Observation, ContainmentError> {
    let name = root
        .file_name()
        .ok_or_else(|| failure("storage root has no final component"))?;
    let mut mounts = File::open("/proc/self/mountinfo").map_err(io_failure)?;
    let mut pending_observations = 0_u64;
    let mut notification_wakeups = 0_u64;
    loop {
        // Arm the event cursor before reading the table so an attachment during observation wakes
        // the next wait. Kernel mount notifications do not establish filesystem responsiveness.
        poll_change(&mounts, control, 0)?;
        mounts.seek(SeekFrom::Start(0)).map_err(io_failure)?;
        let table = MountTable::read(&mut mounts).map_err(|error| failure(error.to_string()))?;
        // Acquiring this descriptor can block in a filesystem provider; it stays in the dedicated
        // helper, outside the workload, query supervisor, and invocation path.
        let source = open_child(parent, Path::new(name))?;
        let opened = identity(&source)?;
        if let SourceObservation::Candidate(record) = table.classify(root, opened.mount) {
            return Ok(Observation {
                source,
                filesystem: record.filesystem.to_string_lossy().into_owned(),
                pending_observations,
                notification_wakeups,
            });
        }
        drop(source);
        pending_observations = pending_observations.saturating_add(1);
        if observe_pending && pending_observations == 1 {
            transport::send_json(
                control,
                &serde_json::json!({
                    "status": "pending",
                    "pending_observations": pending_observations,
                    "notification_wakeups": notification_wakeups,
                }),
            )?;
        }
        if poll_change(&mounts, control, -1)? {
            notification_wakeups = notification_wakeups.saturating_add(1);
        }
    }
}

fn poll_change(
    mounts: &File,
    control: &UnixStream,
    timeout: libc::c_int,
) -> Result<bool, ContainmentError> {
    let mut descriptors = [
        libc::pollfd {
            fd: mounts.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        },
        libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: both descriptors stay owned and the array is writable for the complete poll call.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io_failure(error));
        }
        if descriptors[1].revents != 0 {
            return Err(failure(
                "storage controller closed or sent data before source capture",
            ));
        }
        // POLLERR accompanies a mount change on procfs and is not a failure here.
        if descriptors[0].revents & (libc::POLLNVAL | libc::POLLHUP) != 0 {
            return Err(failure(
                "storage mount notification descriptor became unavailable",
            ));
        }
        return Ok(descriptors[0].revents & (libc::POLLPRI | libc::POLLERR) != 0);
    }
}
