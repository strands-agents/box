//! Bounded mount observations and private framing for protected storage admission.
//!
//! These foundations are exercised in the library tests until the receiver supplies a
//! production caller. They do not enable storage configuration or change workload mounts.

use super::apply_failure;
use crate::ContainmentError;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

mod mountinfo;
mod transport;

const CONTROL_LIMIT: usize = 1024 * 1024;

fn failure(reason: impl Into<String>) -> ContainmentError {
    apply_failure(format!("storage admission: {}", reason.into()))
}

pub(super) fn clone_private_tree(source: &OwnedFd) -> Result<OwnedFd, ContainmentError> {
    const OPEN_TREE_CLONE: u32 = 1;
    // SAFETY: open_tree consumes a live descriptor and an empty, terminated pathname.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            source.as_raw_fd(),
            c"".as_ptr(),
            OPEN_TREE_CLONE
                | libc::O_CLOEXEC as u32
                | libc::AT_EMPTY_PATH as u32
                | libc::AT_RECURSIVE as u32,
        )
    };
    let cloned = own(raw)?;
    #[repr(C)]
    struct MountAttr {
        set: u64,
        clear: u64,
        propagation: u64,
        userns_fd: u64,
    }
    let attr = MountAttr {
        set: 0,
        clear: 0,
        propagation: libc::MS_PRIVATE,
        userns_fd: 0,
    };
    // SAFETY: the sized attribute structure and empty path remain valid for the syscall.
    if unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            cloned.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_RECURSIVE,
            &attr,
            std::mem::size_of_val(&attr),
        )
    } != 0
    {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    Ok(cloned)
}

fn own(raw: libc::c_long) -> Result<OwnedFd, ContainmentError> {
    if raw < 0 {
        Err(io_failure(std::io::Error::last_os_error()))
    }
    // SAFETY: a successful descriptor-creating syscall returns a new owned descriptor.
    else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) })
    }
}

fn io_failure(error: std::io::Error) -> ContainmentError {
    failure(error.to_string())
}
