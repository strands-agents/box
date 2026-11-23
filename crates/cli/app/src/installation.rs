use std::io;
use std::path::{Path, PathBuf};

#[cfg(not(target_os = "macos"))]
pub(crate) fn executable() -> io::Result<PathBuf> {
    std::env::current_exe()
}

#[cfg(target_os = "macos")]
pub(crate) fn executable() -> io::Result<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt as _;

    use nix::libc;

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

fn bundle_root(executable: &Path) -> Option<&Path> {
    executable
        .ends_with("Box.app/Contents/MacOS/box")
        .then(|| executable.ancestors().nth(4))
        .flatten()
}

/// The installed package directory that a later run trusts.
pub(crate) fn root(executable: &Path) -> Option<PathBuf> {
    bundle_root(executable)
        .or_else(|| executable.parent())
        .map(Path::to_path_buf)
}

/// The resource directory of a flat installation or the signed app bundle.
pub(crate) fn resources(executable: &Path) -> Option<PathBuf> {
    if let Some(directory) = bundle_root(executable) {
        Some(directory.join("Box.app/Contents/Resources/resources"))
    } else {
        executable
            .parent()
            .map(|directory| directory.join("resources"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_native_layout_uses_the_package_root() {
        let package = Path::new("/installed/package");
        let native = package.join("Box.app/Contents/MacOS/box");
        assert_eq!(root(&native).as_deref(), Some(package));
        assert_eq!(
            resources(&native),
            Some(package.join("Box.app/Contents/Resources/resources"))
        );
        for relative in [
            "box",
            "Other.app/Contents/MacOS/box",
            "box.app/Contents/MacOS/box",
            "Box.app/Contents/MacOS/another",
            "Contents/MacOS/box",
        ] {
            let executable = package.join(relative);
            assert_eq!(root(&executable).as_deref(), executable.parent());
            assert_eq!(
                resources(&executable),
                Some(executable.parent().unwrap().join("resources"))
            );
        }
    }
}
