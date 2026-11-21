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
    open_real_directory(path, base).map(|_| ())
}

/// Create `path` as [`create_real_directory`] does and open it: each directory below `base` is
/// made and opened relative to the open directory above it, never through a link.
pub fn open_real_directory(path: &Path, base: &Path) -> Result<OwnedFd, Error> {
    let (start, below) = match path.strip_prefix(base) {
        Ok(below) => (base, below),
        Err(_) => (path, Path::new("")),
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(start)
        .map_err(|source| io_error("create", start, source))?;
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(start)
        .map(OwnedFd::from)
        .map_err(|source| io_error("open", start, source))?;
    let mut walked = start.to_path_buf();
    for component in below.components() {
        let Component::Normal(name) = component else {
            let invalid = std::io::Error::from(std::io::ErrorKind::InvalidInput);
            return Err(io_error("create", path, invalid));
        };
        walked.push(name);
        directory = match open_or_make_directory_at(&directory, name) {
            Ok(next) => next,
            Err(source) => {
                let link = metadata_at(&directory, name)
                    .is_ok_and(|metadata| metadata.st_mode & libc::S_IFMT == libc::S_IFLNK);
                return Err(if link {
                    Error::Symlink { path: walked }
                } else {
                    io_error("create", &walked, source)
                });
            }
        };
    }
    Ok(directory)
}

/// Open the directory `name` in `directory`, made private when it is absent, never through a link.
fn open_or_make_directory_at(directory: &OwnedFd, name: &OsStr) -> std::io::Result<OwnedFd> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    match open_at(directory, name, flags, 0) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match make_directory_at(directory, name, 0o700) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            open_at(directory, name, flags, 0)
        }
        opened => opened,
    }
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

pub fn metadata_at(directory: &OwnedFd, name: impl AsRef<OsStr>) -> std::io::Result<libc::stat> {
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
    rename_between(directory, OsStr::new(from), directory, OsStr::new(to))
}

fn rename_between(
    source: &OwnedFd,
    from: &OsStr,
    directory: &OwnedFd,
    to: &OsStr,
) -> std::io::Result<()> {
    let (from, to) = (c_name(from)?, c_name(to)?);
    // SAFETY: both names are valid C strings, and both descriptors are owned and open.
    let status = unsafe {
        libc::renameat(
            source.as_raw_fd(),
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

/// Move `from` in `source` to `to` in `directory` without replacing anything, and return whether
/// it moved: what `to` already names is kept, and a link there is not followed.
pub(crate) fn move_new_at(
    source: &OwnedFd,
    from: &OsStr,
    directory: &OwnedFd,
    to: &OsStr,
) -> std::io::Result<bool> {
    match rename_new(source, from, directory, to) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP)
            ) =>
        {
            claim_then_rename(source, from, directory, to)
        }
        Err(error) => Err(error),
    }
}

/// The rename of [`move_new_at`] as one system call, which fails when `to` exists.
fn rename_new(
    source: &OwnedFd,
    from: &OsStr,
    directory: &OwnedFd,
    to: &OsStr,
) -> std::io::Result<()> {
    let (from, to) = (c_name(from)?, c_name(to)?);
    // SAFETY: both names are valid C strings, and both descriptors are owned and open.
    #[cfg(target_os = "macos")]
    let status = unsafe {
        libc::renameatx_np(
            source.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    // SAFETY: as above; the call takes two descriptors, two C strings, and one flag word.
    #[cfg(not(target_os = "macos"))]
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            source.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// [`move_new_at`] for a filesystem without that system call: make an empty entry at `to`, which
/// fails when `to` exists, then rename over it.
fn claim_then_rename(
    source: &OwnedFd,
    from: &OsStr,
    directory: &OwnedFd,
    to: &OsStr,
) -> std::io::Result<bool> {
    let folder = metadata_at(source, from)?.st_mode & libc::S_IFMT == libc::S_IFDIR;
    let claimed = if folder {
        make_directory_at(directory, to, 0o700)
    } else {
        open_at(
            directory,
            to,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
        .map(drop)
    };
    match claimed {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error),
    }
    let moved = rename_between(source, from, directory, to);
    if moved.is_err() {
        let _ = remove_at(directory, to, folder);
    }
    moved.map(|()| true)
}

fn remove_at(directory: &OwnedFd, name: &OsStr, folder: bool) -> std::io::Result<()> {
    let name = c_name(name)?;
    let flags = if folder { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: `name` is a valid C string, and the descriptor is owned and open.
    let status = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), flags) };
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

pub(crate) fn make_directory_at(
    directory: &OwnedFd,
    name: impl AsRef<OsStr>,
    mode: u32,
) -> std::io::Result<()> {
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
    remove_at(directory, OsStr::new(name), false)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn root() -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let root = directory.path().canonicalize().expect("canonical");
        (directory, root)
    }

    #[test]
    fn a_directory_is_made_private_below_a_base_that_a_link_leads_to() {
        let (_directory, root) = root();
        std::fs::create_dir(root.join("real")).expect("a folder");
        symlink(root.join("real"), root.join("base")).expect("a link at the base");
        let path = root.join("base/a/b");
        create_real_directory(&path, &root.join("base")).expect("a link at the base is followed");
        for made in [root.join("real/a"), root.join("real/a/b")] {
            let metadata = std::fs::symlink_metadata(&made).expect("a folder");
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o777, 0o700);
        }
        create_real_directory(&path, &root.join("base")).expect("a folder that exists");
        create_real_directory(&root.join("new/base"), &root.join("new/base")).expect("a base");
        assert!(root.join("new/base").is_dir());
    }

    #[test]
    fn a_link_below_the_base_is_refused_and_nothing_is_made_through_it() {
        let (_directory, root) = root();
        std::fs::create_dir_all(root.join("base/a")).expect("a folder");
        std::fs::create_dir(root.join("outside")).expect("a folder");
        symlink(root.join("outside"), root.join("base/a/link")).expect("a link");
        for path in [root.join("base/a/link"), root.join("base/a/link/b/c")] {
            let error = create_real_directory(&path, &root.join("base")).expect_err("a refusal");
            assert!(
                matches!(&error, Error::Symlink { path } if *path == root.join("base/a/link")),
                "{error}"
            );
        }
        assert_eq!(
            std::fs::read_dir(root.join("outside"))
                .expect("list")
                .count(),
            0
        );
        std::fs::write(root.join("base/file"), "").expect("a file");
        let error = create_real_directory(&root.join("base/file/b"), &root.join("base"))
            .expect_err("a file");
        assert!(matches!(error, Error::Io { .. }), "{error}");
    }

    type Move = fn(&OwnedFd, &OsStr, &OwnedFd, &OsStr) -> std::io::Result<bool>;

    #[test]
    fn a_move_replaces_nothing() {
        let moves: [(&str, Move); 2] = [
            ("one call", move_new_at),
            ("claim, then rename", claim_then_rename),
        ];
        for (how, move_new) in moves {
            let (_directory, root) = root();
            for folder in ["from", "to", "outside"] {
                std::fs::create_dir(root.join(folder)).expect("a folder");
            }
            let from = open_directory(&root.join("from")).expect("open");
            let to = open_directory(&root.join("to")).expect("open");
            let name = OsStr::new("copy");
            let stage = |folder: bool| {
                if folder {
                    std::fs::create_dir(root.join("from/copy")).expect("a staged folder");
                    std::fs::write(root.join("from/copy/file"), "staged").expect("a file");
                } else {
                    std::fs::write(root.join("from/copy"), "staged").expect("a staged file");
                }
            };
            for folder in [false, true] {
                stage(folder);
                assert!(move_new(&from, name, &to, name).expect("a move"), "{how}");
                let moved = if folder { "to/copy/file" } else { "to/copy" };
                assert_eq!(
                    std::fs::read_to_string(root.join(moved)).expect("read"),
                    "staged",
                    "{how}"
                );
                assert!(std::fs::symlink_metadata(root.join("from/copy")).is_err());
                remove_if_present(&root.join("to/copy")).expect("remove");

                let target = root.join("to/copy");
                let present: [(&str, &dyn Fn()); 3] = [
                    ("a file", &|| {
                        std::fs::write(&target, "kept").expect("a file")
                    }),
                    ("an empty folder", &|| {
                        std::fs::create_dir(&target).expect("a folder");
                    }),
                    ("a link", &|| {
                        symlink(root.join("outside"), &target).expect("a link");
                    }),
                ];
                for (what, put) in present {
                    stage(folder);
                    put();
                    let before = std::fs::symlink_metadata(&target).expect("the target");
                    assert!(
                        !move_new(&from, name, &to, name).expect("a kept target"),
                        "{how}: {what}"
                    );
                    let after = std::fs::symlink_metadata(&target).expect("the target");
                    assert_eq!(before.ino(), after.ino(), "{how}: {what}");
                    assert!(
                        std::fs::symlink_metadata(root.join("from/copy")).is_ok(),
                        "{how}: {what}: the staged copy stays"
                    );
                    assert_eq!(
                        std::fs::read_dir(root.join("outside"))
                            .expect("list")
                            .count(),
                        0
                    );
                    remove_if_present(&target).expect("remove");
                    remove_if_present(&root.join("from/copy")).expect("remove");
                }
            }
        }
    }
}
