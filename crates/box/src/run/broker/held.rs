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

/// Why a walk did not reach the parent of an approved path.
pub(super) enum Unreached {
    /// A component is missing, cannot be searched, or is a file, which answers the question about the path.
    Answered(io::Error),
    /// The walk refused a component that is a symbolic link, or a path it cannot walk.
    Refused(io::Error),
}

impl Unreached {
    pub(super) fn into_error(self) -> io::Error {
        match self {
            Self::Answered(error) | Self::Refused(error) => error,
        }
    }
}

/// The parent directory of an approved path, held open, and the leaf name inside it.
pub(super) struct HeldPath {
    parent: File,
    leaf: CString,
}

impl HeldPath {
    /// Hold the parent of `approved`, refusing a symbolic link in any component of it.
    pub(super) fn of(approved: &Path) -> io::Result<Self> {
        Self::reach(approved).map_err(Unreached::into_error)
    }

    /// Hold the parent of `approved`, and tell an answer about the path from a refusal.
    pub(super) fn reach(approved: &Path) -> Result<Self, Unreached> {
        let mut components = approved.components();
        if components.next() != Some(Component::RootDir) {
            return Err(Unreached::Refused(not_canonical(approved)));
        }
        let leaf = match components.next_back() {
            Some(Component::Normal(leaf)) => c_name(leaf.as_bytes()).map_err(Unreached::Refused)?,
            _ => return Err(Unreached::Refused(not_canonical(approved))),
        };
        let mut parent =
            open_at(libc::AT_FDCWD, c"/", WALK & !libc::O_NOFOLLOW).map_err(Unreached::Refused)?;
        for component in components {
            let Component::Normal(name) = component else {
                return Err(Unreached::Refused(not_canonical(approved)));
            };
            let name = c_name(name.as_bytes()).map_err(Unreached::Refused)?;
            parent = match open_at(parent.as_raw_fd(), &name, WALK) {
                Ok(next) => next,
                Err(error) => return Err(unreached(&parent, &name, error)),
            };
        }
        Ok(Self { parent, leaf })
    }

    /// Open the leaf itself, never through a symbolic link.
    pub(super) fn open(&self, flags: libc::c_int) -> io::Result<File> {
        let existing_only = flags & libc::O_CREAT != 0 && super::ownership::is_root();
        let flags = if existing_only {
            flags & !libc::O_CREAT
        } else {
            flags
        };
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
        super::ownership::require_nonroot_creation()?;
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
        super::ownership::require_nonroot_creation()?;
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

    /// Move the leaf only if the destination name is still unbound.
    pub(super) fn rename_to_new(&self, destination: &Self) -> io::Result<()> {
        super::ownership::require_nonroot_creation()?;
        // SAFETY: both parent and leaf pairs are owned, valid handles.
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                self.parent.as_raw_fd(),
                self.leaf.as_ptr(),
                destination.parent.as_raw_fd(),
                destination.leaf.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        // SAFETY: both parent and leaf pairs are owned, valid handles.
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                self.parent.as_raw_fd(),
                self.leaf.as_ptr(),
                destination.parent.as_raw_fd(),
                destination.leaf.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        checked(result)
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

/// Classify a failed step of the walk by what the component is, without following it.
fn unreached(parent: &File, name: &CStr, error: io::Error) -> Unreached {
    if matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    ) {
        return Unreached::Answered(error);
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the parent and the name are owned, valid handles, and `metadata` is writable.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Unreached::Refused(error);
    }
    // SAFETY: `fstatat` returned 0, so it filled `metadata`.
    let kind = unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT;
    if kind == libc::S_IFLNK {
        Unreached::Refused(error)
    } else {
        Unreached::Answered(error)
    }
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("a scratch dir");
        let base = dir.path().canonicalize().expect("the scratch dir resolves");
        (dir, base)
    }

    /// A walk that reaches the parent holds it.
    #[test]
    fn a_walk_to_an_existing_parent_holds_it() {
        let (_dir, base) = scratch();
        std::fs::create_dir(base.join("d")).expect("a directory");
        assert!(HeldPath::reach(&base.join("d/f.txt")).is_ok());
    }

    /// A missing component is an answer about the path.
    #[test]
    fn a_missing_component_is_an_answer() {
        let (_dir, base) = scratch();
        let reached = HeldPath::reach(&base.join("absent/f.txt"));
        assert!(matches!(reached, Err(Unreached::Answered(_))));
    }

    /// A regular file where a directory belongs is an answer about the path.
    #[test]
    fn a_regular_file_component_is_an_answer() {
        let (_dir, base) = scratch();
        std::fs::write(base.join("notes.txt"), "x").expect("a regular file");
        let reached = HeldPath::reach(&base.join("notes.txt/child"));
        assert!(matches!(reached, Err(Unreached::Answered(_))));
    }

    /// A symbolic link where a directory belongs is a refusal.
    #[test]
    fn a_symbolic_link_component_is_a_refusal() {
        let (_dir, base) = scratch();
        std::fs::create_dir(base.join("target")).expect("a directory");
        std::os::unix::fs::symlink(base.join("target"), base.join("link")).expect("a link");
        let reached = HeldPath::reach(&base.join("link/f.txt"));
        assert!(matches!(reached, Err(Unreached::Refused(_))));
    }

    /// A dangling symbolic link where a directory belongs is a refusal.
    #[test]
    fn a_dangling_symbolic_link_component_is_a_refusal() {
        let (_dir, base) = scratch();
        std::os::unix::fs::symlink(base.join("gone"), base.join("link")).expect("a link");
        let reached = HeldPath::reach(&base.join("link/f.txt"));
        assert!(matches!(reached, Err(Unreached::Refused(_))));
    }

    /// A directory the host will not search answers the question about the path.
    #[test]
    fn a_directory_the_host_will_not_search_is_an_answer() {
        // SAFETY: `geteuid` reads the calling process's effective user id and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: root ignores a directory's permission bits");
            return;
        }
        let (_dir, base) = scratch();
        let locked = base.join("locked");
        std::fs::create_dir_all(locked.join("inner")).expect("nested directories");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("lock the directory");
        let reached = HeldPath::reach(&locked.join("inner/f.txt"));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("unlock the directory");
        assert!(matches!(reached, Err(Unreached::Answered(_))));
    }

    /// A path that is not canonical and absolute is a refusal.
    #[test]
    fn a_relative_path_is_a_refusal() {
        assert!(matches!(
            HeldPath::reach(Path::new("relative/f.txt")),
            Err(Unreached::Refused(_))
        ));
    }

    /// `of` refuses every path that `reach` does not hold.
    #[test]
    fn of_refuses_every_unreached_path() {
        let (_dir, base) = scratch();
        std::fs::write(base.join("notes.txt"), "x").expect("a regular file");
        assert!(HeldPath::of(&base.join("absent/f.txt")).is_err());
        assert!(HeldPath::of(&base.join("notes.txt/child")).is_err());
    }
}
