//! Closing every descriptor the alias inherited, before it does anything else. Shared with the
//! test probe via `#[path]`, so it depends only on `libc` and `std`. The alias treats any `Err`
//! here as fatal and exits before connecting to the broker.

use std::io;

/// The first descriptor every path here closes: everything above stderr.
#[cfg(unix)]
pub(crate) const FIRST_INHERITED_DESCRIPTOR: libc::c_int = libc::STDERR_FILENO + 1;

/// Which mechanism closed the descriptors. Read only by the test probe, so a blocked close_range
/// can't pass the fast-path test through the fallback.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClosePath {
    CloseRange,
    /// Enumerated the descriptor directory (`/proc/self/fd` or `/dev/fd`).
    Proc,
    Bounded,
}

/// Close every descriptor above stdio before doing anything else. One `close_range` syscall does
/// it in constant time, so the cost no longer scales with `RLIMIT_NOFILE` (the old loop to
/// `getdtablesize()` cost minutes at a ~1e9 limit). Called by syscall number; see the commit message.
#[cfg(target_os = "linux")]
pub(crate) fn close_inherited_descriptors() -> io::Result<()> {
    close_inherited_descriptors_reporting().map(|_path| ())
}

/// Same as `close_inherited_descriptors`, reporting which mechanism actually closed the
/// descriptors. See `ClosePath`'s own doc for why this exists.
#[cfg(target_os = "linux")]
pub(crate) fn close_inherited_descriptors_reporting() -> io::Result<ClosePath> {
    // SAFETY: SYS_close_range takes the same three scalar args as the libc wrapper; the upper
    // bound u32::MAX covers every descriptor at or above the first.
    let closed = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            FIRST_INHERITED_DESCRIPTOR as libc::c_uint,
            libc::c_uint::MAX,
            0 as libc::c_uint,
        )
    };
    if closed == 0 {
        return Ok(ClosePath::CloseRange);
    }
    // Fall back on any error, not a fixed errno set (a seccomp filter can return anything); the
    // fallback can itself drop to the bounded loop, so this is safer than exiting here.
    close_inherited_descriptors_fallback_reporting()
}

/// The directory naming this process's open descriptors: `/proc/self/fd` on Linux, `/dev/fd` on
/// macOS and the other unix targets (the same choice `contain_trampoline` makes).
#[cfg(target_os = "linux")]
const DESCRIPTOR_DIRECTORY: &str = "/proc/self/fd";
#[cfg(all(unix, not(target_os = "linux")))]
const DESCRIPTOR_DIRECTORY: &str = "/dev/fd";

/// Close every open descriptor above stdio by enumerating the descriptor directory, falling back
/// to the bounded loop if it cannot be read. Costs one `close()` per open descriptor, so it keeps
/// independence from `RLIMIT_NOFILE` when `close_range` is unavailable (and on macOS, where there
/// is no `close_range`).
#[cfg(unix)]
pub(crate) fn close_inherited_descriptors_fallback_reporting() -> io::Result<ClosePath> {
    let directory = match std::fs::read_dir(DESCRIPTOR_DIRECTORY) {
        Ok(directory) => directory,
        // Fall back only here, not on a per-entry error below: a failed open means `/proc` is
        // absent (use another mechanism); a mid-scan error means it is present but unreadable.
        Err(_) => return close_inherited_descriptors_bounded_reporting(),
    };
    // Collect numbers first, then close: closing mid-iteration would race the read. The directory
    // handle drops when the loop ends, before the close loop, so its own number reads as closed.
    let mut descriptors = Vec::new();
    for entry in directory {
        // A mid-scan error returns before everything is closed, which the caller treats as fatal.
        let entry = entry?;
        let name = entry.file_name();
        let Some(number) = name
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
        else {
            continue;
        };
        if number > libc::STDERR_FILENO {
            descriptors.push(number);
        }
    }
    for descriptor in descriptors {
        close_one(descriptor)?;
    }
    Ok(ClosePath::Proc)
}

/// Close every descriptor above stdio up to `getdtablesize()` with a bounded loop: the historical
/// last resort, used only after the descriptor directory cannot be read. Best-effort: a descriptor
/// above a soft limit later lowered by `setrlimit` survives this loop.
#[cfg(unix)]
pub(crate) fn close_inherited_descriptors_bounded_reporting() -> io::Result<ClosePath> {
    // SAFETY: getdtablesize takes no arguments and only reads the current soft RLIMIT_NOFILE.
    let maximum = unsafe { libc::getdtablesize() };
    if maximum < 0 {
        return Err(io::Error::last_os_error());
    }
    for descriptor in FIRST_INHERITED_DESCRIPTOR..maximum {
        close_one(descriptor)?;
    }
    Ok(ClosePath::Bounded)
}

/// Close one descriptor, treating `EBADF` (already closed) as success.
#[cfg(unix)]
fn close_one(descriptor: libc::c_int) -> io::Result<()> {
    // SAFETY: close only receives a descriptor number. EBADF means the descriptor was already
    // closed, which is the desired state.
    if unsafe { libc::close(descriptor) } == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBADF) {
            return Err(error);
        }
    }
    Ok(())
}

/// Close every descriptor above stdio before doing anything else. Non-Linux unix targets have no
/// `close_range` call here, so they enumerate `/dev/fd` and keep the bounded loop only as the
/// fallback when that directory cannot be read.
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn close_inherited_descriptors() -> io::Result<()> {
    close_inherited_descriptors_fallback_reporting().map(|_path| ())
}

#[cfg(not(unix))]
pub(crate) fn close_inherited_descriptors() -> io::Result<()> {
    Ok(())
}
