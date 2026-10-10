//! Hand the trampoline a target environment the way the box does: through an inherited descriptor,
//! never on argv. Shared by the tests that pass a non-empty environment.

use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

/// Add `--target-env-fd` for `environment` to `command`. Keep the returned file alive until the
/// command has spawned: dropping it closes the descriptor the child is meant to inherit.
pub fn attach(command: &mut Command, environment: &impl serde::Serialize) -> std::fs::File {
    let mut file = tempfile::tempfile().expect("target environment file");
    file.write_all(
        serde_json::to_string(environment)
            .expect("target environment JSON")
            .as_bytes(),
    )
    .expect("write target environment");
    let descriptor = file.as_raw_fd();
    command.arg("--target-env-fd").arg(descriptor.to_string());
    // SAFETY: the closure only clears FD_CLOEXEC on the child's copy of an already-open
    // descriptor, and allocates nothing.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags == -1
                || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    file
}
