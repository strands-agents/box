//! The ownership floor for host filesystem effects from the trusted process.

use std::io;

const ROOT_CREATION_REFUSAL: &str =
    "root launch cannot create or move host filesystem entries; run Box as a non-root account";

/// Whether the Linux process has a root real or effective user identity.
pub(super) fn is_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: these calls read the process user IDs and cannot fail.
        unsafe { libc::getuid() == 0 || libc::geteuid() == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Refuse an operation that can introduce a host filesystem entry as root.
pub(super) fn require_nonroot_creation() -> io::Result<()> {
    if is_root() {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            ROOT_CREATION_REFUSAL,
        ))
    } else {
        Ok(())
    }
}
