use std::ffi::{CString, OsStr};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path};

use nix::libc;

use crate::error::Error;

pub(crate) fn open_regular(path: &Path) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(file)
}

pub fn read_regular(path: &Path) -> std::io::Result<String> {
    std::io::read_to_string(open_regular(path)?)
}

/// Whether `path` is a regular file with one link, not a symbolic link, that already holds exactly
/// `text`.
pub fn holds(path: &Path, text: &str) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.nlink() == 1)
        && std::fs::read_to_string(path).is_ok_and(|current| current == text)
}

pub fn io_error(action: &'static str, path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

/// Create `path` as a private directory, refusing a symbolic link at it or at any ancestor below
/// `base`.
pub fn create_real_directory(path: &Path, base: &Path) -> Result<(), Error> {
    for ancestor in path
        .ancestors()
        .filter(|ancestor| ancestor.starts_with(base) && *ancestor != base)
    {
        if std::fs::symlink_metadata(ancestor)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(Error::Symlink {
                path: ancestor.to_path_buf(),
            });
        }
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|source| io_error("create", path, source))
}

/// Remove `path` and everything below it, and return whether it existed. A link is removed without
/// its target.
pub fn remove_if_present(path: &Path) -> Result<bool, Error> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(io_error("inspect", path, source)),
    };
    let removed = if metadata.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match removed {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("remove", path, source)),
    }
}

fn c_name(name: impl AsRef<OsStr>) -> std::io::Result<CString> {
    CString::new(name.as_ref().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

pub fn open_directory(path: &Path) -> std::io::Result<OwnedFd> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map(OwnedFd::from)
}

/// Open each directory from `base` to `path` without following a link.
pub fn open_directory_below(path: &Path, base: &Path) -> std::io::Result<OwnedFd> {
    let relative = path
        .strip_prefix(base)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut directory = open_directory(base)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        directory = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    }
    Ok(directory)
}

pub fn metadata_at(directory: &OwnedFd, name: &str) -> std::io::Result<libc::stat> {
    let name = c_name(name)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor and name are valid, and `metadata` is writable storage.
    let status = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful `fstatat` initialized `metadata`.
    Ok(unsafe { metadata.assume_init() })
}

/// Open `name` in `directory` with `flags`, never through a link.
pub fn open_at(
    directory: &OwnedFd,
    name: impl AsRef<OsStr>,
    flags: libc::c_int,
    mode: u32,
) -> std::io::Result<OwnedFd> {
    let name = c_name(name)?;
    // SAFETY: `name` is a valid C string, and the descriptor is owned and open.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn rename_at(directory: &OwnedFd, from: &str, to: &str) -> std::io::Result<()> {
    let (from, to) = (c_name(from)?, c_name(to)?);
    // SAFETY: both names are valid C strings, and the descriptor is owned and open.
    let status = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Publish a protected staged file relative to an open destination directory.
pub(crate) fn publish_at(
    staged: &Path,
    directory: &OwnedFd,
    name: &str,
    replace: bool,
) -> std::io::Result<()> {
    let staged = CString::new(staged.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let name = c_name(name)?;
    // SAFETY: both names are valid C strings, and the descriptor is owned and open.
    let status = unsafe {
        if replace {
            libc::renameat(
                libc::AT_FDCWD,
                staged.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
            )
        } else {
            libc::linkat(
                libc::AT_FDCWD,
                staged.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
                0,
            )
        }
    };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(crate) fn make_directory_at(directory: &OwnedFd, name: &str, mode: u32) -> std::io::Result<()> {
    let name = c_name(name)?;
    // SAFETY: `name` is a valid C string, and the descriptor is owned and open.
    let status =
        unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn unlink_at(directory: &OwnedFd, name: &str) -> std::io::Result<()> {
    let name = c_name(name)?;
    // SAFETY: `name` is a valid C string, and the descriptor is owned and open.
    let status = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
