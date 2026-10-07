//! An approved path, reached from `/` with no symbolic link followed in any component.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};

/// The flags that open one directory on the walk to the leaf.
#[cfg(target_os = "linux")]
const WALK: libc::c_int = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
#[cfg(target_os = "macos")]
const WALK: libc::c_int = libc::O_SEARCH | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// The parent directory of an approved path, held open, and the leaf name inside it.
pub(super) struct HeldPath {
    parent: File,
    leaf: CString,
}

impl HeldPath {
    /// Hold the parent of `approved`, refusing a symbolic link in any component of it.
    pub(super) fn of(approved: &Path) -> io::Result<Self> {
        let mut components = approved.components();
        if components.next() != Some(Component::RootDir) {
            return Err(not_canonical(approved));
        }
        let leaf = match components.next_back() {
            Some(Component::Normal(leaf)) => c_name(leaf.as_bytes())?,
            _ => return Err(not_canonical(approved)),
        };
        let mut parent = open_at(libc::AT_FDCWD, c"/", WALK & !libc::O_NOFOLLOW)?;
        for component in components {
            let Component::Normal(name) = component else {
                return Err(not_canonical(approved));
            };
            parent = open_at(parent.as_raw_fd(), &c_name(name.as_bytes())?, WALK)?;
        }
        Ok(Self { parent, leaf })
    }

    /// Open the leaf itself, never through a symbolic link.
    pub(super) fn open(&self, flags: libc::c_int) -> io::Result<File> {
        open_at(
            self.parent.as_raw_fd(),
            &self.leaf,
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    }

    /// The leaf's own metadata, a symbolic link's included.
    pub(super) fn stat(&self) -> io::Result<libc::stat> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the parent and the leaf are owned, valid handles, and `metadata` is writable.
        let result = unsafe {
            libc::fstatat(
                self.parent.as_raw_fd(),
                self.leaf.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fstatat` returned 0, so it filled `metadata`.
        Ok(unsafe { metadata.assume_init() })
    }

    pub(super) fn create_directory(&self) -> io::Result<()> {
        // SAFETY: the parent and the leaf are owned, valid handles.
        checked(unsafe { libc::mkdirat(self.parent.as_raw_fd(), self.leaf.as_ptr(), 0o777) })
    }

    pub(super) fn remove_file(&self) -> io::Result<()> {
        // SAFETY: the parent and the leaf are owned, valid handles.
        checked(unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.leaf.as_ptr(), 0) })
    }

    pub(super) fn remove_directory(&self) -> io::Result<()> {
        // SAFETY: the parent and the leaf are owned, valid handles.
        checked(unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.leaf.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        })
    }

    pub(super) fn rename_to(&self, destination: &Self) -> io::Result<()> {
        // SAFETY: both parent and leaf pairs are owned, valid handles.
        checked(unsafe {
            libc::renameat(
                self.parent.as_raw_fd(),
                self.leaf.as_ptr(),
                destination.parent.as_raw_fd(),
                destination.leaf.as_ptr(),
            )
        })
    }

    /// The entry names of the leaf directory, without `.` and `..`.
    pub(super) fn entry_names(&self) -> io::Result<Vec<String>> {
        let directory = self.open(libc::O_RDONLY | libc::O_DIRECTORY)?;
        let descriptor = std::os::fd::IntoRawFd::into_raw_fd(directory);
        // SAFETY: `descriptor` is an owned directory descriptor, and the stream takes it over.
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: `fdopendir` failed, so `descriptor` is still owned here.
            drop(unsafe { File::from_raw_fd(descriptor) });
            return Err(error);
        }
        let mut names = Vec::new();
        let outcome = loop {
            clear_errno();
            // SAFETY: `stream` is an open directory stream.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                break match error.raw_os_error() {
                    Some(0) | None => Ok(()),
                    Some(_) => Err(error),
                };
            }
            // SAFETY: `readdir` returned an entry whose `d_name` is NUL-terminated.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                names.push(String::from_utf8_lossy(name).into_owned());
            }
        };
        // SAFETY: `stream` is open, and closing it also closes `descriptor`.
        unsafe { libc::closedir(stream) };
        outcome.map(|()| names)
    }
}

fn open_at(directory: libc::c_int, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: `name` is a valid C string. The returned descriptor is checked.
    let descriptor =
        unsafe { libc::openat(directory, name.as_ptr(), flags, 0o666 as libc::c_uint) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned this owned descriptor, and `File` closes it once.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn checked(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn c_name(name: &[u8]) -> io::Result<CString> {
    CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a path contains a NUL byte"))
}

fn not_canonical(approved: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{}: is not a canonical absolute path", approved.display()),
    )
}

fn clear_errno() {
    // SAFETY: the thread's own `errno` is always writable.
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0;
    }
    // SAFETY: the thread's own `errno` is always writable.
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error() = 0;
    }
}
