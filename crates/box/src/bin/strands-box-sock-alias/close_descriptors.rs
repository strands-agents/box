//! Descriptor cleanup shared by the socket alias and its test probe.

use std::io;

/// The first descriptor every path here closes: everything above stderr.
#[cfg(unix)]
pub(crate) const FIRST_INHERITED_DESCRIPTOR: libc::c_int = libc::STDERR_FILENO + 1;

/// Which mechanism closed the descriptors, reported to the test probe.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClosePath {
    CloseRange,
    Proc,
    ProcessInfo,
    Directory,
    Bounded,
}

/// Close every descriptor above stdio without work proportional to `RLIMIT_NOFILE`. Linux first
/// asks the kernel to close the range in one syscall.
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

/// Close open descriptors by enumerating `/proc/self/fd`, or use the bounded fallback when the
/// directory cannot be opened.
#[cfg(target_os = "linux")]
pub(crate) fn close_inherited_descriptors_fallback_reporting() -> io::Result<ClosePath> {
    close_from_directory("/proc/self/fd", ClosePath::Proc)
}

/// Close descriptors reported by macOS for this process, or use the bounded fallback when the
/// kernel does not provide a complete list.
#[cfg(target_os = "macos")]
pub(crate) fn close_inherited_descriptors_process_info_reporting() -> io::Result<ClosePath> {
    let Some(descriptors) = macos_descriptors() else {
        return close_inherited_descriptors_bounded_reporting();
    };
    close_descriptors(descriptors)?;
    Ok(ClosePath::ProcessInfo)
}

/// List this process's descriptors through the macOS process-information API.
#[cfg(target_os = "macos")]
pub(crate) fn macos_descriptors() -> Option<Vec<libc::c_int>> {
    let pid = libc::c_int::try_from(std::process::id()).ok()?;
    // SAFETY: a null buffer of size zero asks how many bytes the list needs.
    let needed =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return None;
    }
    let capacity = usize::try_from(needed / libc::PROC_PIDLISTFD_SIZE)
        .ok()?
        .checked_add(16)?;
    let mut buffer = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        capacity
    ];
    let size =
        libc::c_int::try_from(capacity.checked_mul(std::mem::size_of::<libc::proc_fdinfo>())?)
            .ok()?;
    // SAFETY: `buffer` owns `size` writable bytes for the duration of the call.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            size,
        )
    };
    if written <= 0 || written >= size {
        return None;
    }
    let reported = usize::try_from(written / libc::PROC_PIDLISTFD_SIZE).ok()?;
    Some(
        buffer[..reported.min(capacity)]
            .iter()
            .map(|entry| entry.proc_fd)
            .collect(),
    )
}

/// Close open descriptors by enumerating a descriptor directory, or use the bounded fallback when
/// the directory cannot be opened.
#[cfg(all(unix, not(target_os = "macos")))]
fn close_from_directory(directory: &str, path: ClosePath) -> io::Result<ClosePath> {
    let directory = match std::fs::read_dir(directory) {
        Ok(directory) => directory,
        Err(_) => return close_inherited_descriptors_bounded_reporting(),
    };
    let mut descriptors = Vec::new();
    for entry in directory {
        let entry = entry?;
        let name = entry.file_name();
        let Some(number) = name
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
        else {
            continue;
        };
        descriptors.push(number);
    }
    close_descriptors(descriptors)?;
    Ok(path)
}

/// Close descriptor numbers above the standard streams.
#[cfg(unix)]
fn close_descriptors(descriptors: impl IntoIterator<Item = libc::c_int>) -> io::Result<()> {
    for descriptor in descriptors {
        if descriptor > libc::STDERR_FILENO {
            close_one(descriptor)?;
        }
    }
    Ok(())
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

/// Close every descriptor above stdio. macOS uses `proc_pidinfo` because the alias's sandbox does
/// not grant read access to `/dev/fd`; other non-Linux unix targets enumerate `/dev/fd`.
#[cfg(target_os = "macos")]
pub(crate) fn close_inherited_descriptors() -> io::Result<()> {
    close_inherited_descriptors_process_info_reporting().map(|_path| ())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn close_inherited_descriptors() -> io::Result<()> {
    close_from_directory("/dev/fd", ClosePath::Directory).map(|_path| ())
}

#[cfg(not(unix))]
pub(crate) fn close_inherited_descriptors() -> io::Result<()> {
    Ok(())
}
