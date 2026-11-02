use std::io;
use std::path::PathBuf;

#[cfg(not(target_os = "macos"))]
pub(super) fn executable() -> io::Result<PathBuf> {
    std::env::current_exe()
}

#[cfg(target_os = "macos")]
pub(super) fn executable() -> io::Result<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt as _;

    let mut buffer = [0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is writable for the supplied length, and getpid selects this process.
    let length = unsafe {
        libc::proc_pidpath(
            libc::getpid(),
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return Err(io::Error::last_os_error());
    }
    let path = CStr::from_bytes_until_nul(&buffer)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(PathBuf::from(OsStr::from_bytes(path.to_bytes())))
}
