//! Bounded inspection of directory entries for configured command identities.

use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::ptr::NonNull;

const MAX_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 128;
const DIRECTORY_FLAGS: libc::c_int = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Inspect existing names without following symbolic links or accepting an incomplete directory walk.
pub(super) fn contains(path: &Path, identities: &[(u64, u64)]) -> io::Result<bool> {
    let before = std::fs::symlink_metadata(path)?;
    if before.is_file() {
        return Ok(identities.contains(&(before.dev(), before.ino())));
    }
    if !before.is_dir() {
        return Ok(false);
    }
    // Once the root exists, every later missing name means the inspection was incomplete.
    let inspect_existing = || {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(DIRECTORY_FLAGS)
            .open(path)?;
        let mut remaining = MAX_ENTRIES;
        let found = inspect(&directory, &before, identities, &mut remaining, 0)?;
        require_unchanged(&before, &std::fs::symlink_metadata(path)?)?;
        Ok(found)
    };
    inspect_existing().map_err(|error: io::Error| {
        io::Error::other(format!("directory inspection failed: {error}"))
    })
}

fn inspect(
    directory: &File,
    before: &Metadata,
    identities: &[(u64, u64)],
    remaining: &mut usize,
    depth: usize,
) -> io::Result<bool> {
    if depth >= MAX_DEPTH {
        return Err(io::Error::other("directory depth exceeds 128"));
    }
    require_unchanged(before, &directory.metadata()?)?;
    let stream = DirectoryStream::new(directory)?;
    while let Some(name) = stream.next()? {
        *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("directory inspection exceeds 100000 entries"))?;
        let metadata = entry_metadata(directory, &name)?;
        match metadata.st_mode & libc::S_IFMT {
            libc::S_IFREG => {
                if identities.contains(&entry_identity(&metadata)) {
                    return Ok(true);
                }
            }
            libc::S_IFDIR => {
                // SAFETY: the directory descriptor and terminated entry name stay live during openat.
                let descriptor = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | DIRECTORY_FLAGS,
                    )
                };
                if descriptor == -1 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: openat returned a new descriptor, now owned by child.
                let child = unsafe { File::from_raw_fd(descriptor) };
                let child_before = child.metadata()?;
                require_same_entry(&metadata, &child_before)?;
                if inspect(&child, &child_before, identities, remaining, depth + 1)? {
                    return Ok(true);
                }
                require_same_entry(&entry_metadata(directory, &name)?, &child_before)?;
            }
            _ => {}
        }
    }
    require_unchanged(before, &directory.metadata()?)?;
    Ok(false)
}

fn require_unchanged(before: &Metadata, after: &Metadata) -> io::Result<()> {
    if (
        before.dev(),
        before.ino(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(io::Error::other("directory changed during inspection"));
    }
    Ok(())
}

fn require_same_entry(entry: &libc::stat, opened: &Metadata) -> io::Result<()> {
    if (
        entry_identity(entry),
        entry.st_mtime,
        entry.st_mtime_nsec,
        entry.st_ctime,
        entry.st_ctime_nsec,
    ) != (
        (opened.dev(), opened.ino()),
        opened.mtime(),
        opened.mtime_nsec(),
        opened.ctime(),
        opened.ctime_nsec(),
    ) {
        return Err(io::Error::other(
            "directory entry changed during inspection",
        ));
    }
    Ok(())
}

fn entry_identity(entry: &libc::stat) -> (u64, u64) {
    #[cfg(target_os = "macos")]
    let device = entry.st_dev as u64;
    #[cfg(target_os = "linux")]
    let device = entry.st_dev;
    (device, entry.st_ino)
}

fn entry_metadata(directory: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::uninit();
    // SAFETY: the descriptor, terminated name, and output pointer are valid for this call.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat initialized metadata on success.
    Ok(unsafe { metadata.assume_init() })
}

struct DirectoryStream(NonNull<libc::DIR>);

impl DirectoryStream {
    fn new(directory: &File) -> io::Result<Self> {
        let descriptor = directory.try_clone()?.into_raw_fd();
        // SAFETY: fdopendir consumes the duplicated descriptor only on success.
        let stream = unsafe { libc::fdopendir(descriptor) };
        match NonNull::new(stream) {
            Some(stream) => Ok(Self(stream)),
            None => {
                let error = io::Error::last_os_error();
                // SAFETY: fdopendir failed, leaving ownership of the descriptor here.
                unsafe { libc::close(descriptor) };
                Err(error)
            }
        }
    }

    fn next(&self) -> io::Result<Option<CString>> {
        loop {
            // SAFETY: the platform accessor gives this thread's errno; the directory stream is live.
            let entry = unsafe {
                #[cfg(target_os = "macos")]
                {
                    *libc::__error() = 0;
                }
                #[cfg(target_os = "linux")]
                {
                    *libc::__errno_location() = 0;
                }
                libc::readdir(self.0.as_ptr())
            };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
            // SAFETY: readdir returned a live entry with a terminated name, copied before the next call.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name != c"." && name != c".." {
                return Ok(Some(name.to_owned()));
            }
        }
    }
}

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this stream came from fdopendir and is closed exactly once.
        unsafe { libc::closedir(self.0.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    fn identity(path: &Path) -> (u64, u64) {
        let metadata = std::fs::metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    }

    #[test]
    fn a_nested_hard_link_is_found_but_a_copy_is_not() {
        let root = tempfile::tempdir().unwrap();
        let command = root.path().join("command");
        let tree = root.path().join("tree");
        let nested = tree.join("nested");
        std::fs::write(&command, "command").unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        let identities = [identity(&command)];
        std::fs::copy(&command, nested.join("copy")).unwrap();
        assert!(!contains(&tree, &identities).unwrap());
        std::fs::hard_link(&command, nested.join("alias")).unwrap();
        assert!(contains(&tree, &identities).unwrap());
    }

    #[test]
    fn directory_symlinks_are_not_followed() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside");
        let tree = root.path().join("tree");
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(&tree).unwrap();
        let command = outside.join("command");
        std::fs::write(&command, "command").unwrap();
        symlink(&outside, tree.join("linked-directory")).unwrap();
        symlink(&tree, tree.join("loop")).unwrap();
        assert!(!contains(&tree, &[identity(&command)]).unwrap());
    }

    #[test]
    fn an_unreadable_subdirectory_does_not_count_as_empty() {
        let root = tempfile::tempdir().unwrap();
        let hidden = root.path().join("hidden");
        std::fs::create_dir(&hidden).unwrap();
        std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o0)).unwrap();
        let enumerable = std::fs::read_dir(&hidden).is_ok();
        let result = contains(root.path(), &[(0, 0)]);
        std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o700)).unwrap();
        if enumerable {
            eprintln!("skipping: this identity can enumerate a mode-000 directory");
            return;
        }
        assert!(
            result.is_err(),
            "an incomplete scan cannot admit: {result:?}"
        );
    }

    #[test]
    fn a_changed_directory_or_an_exhausted_budget_refuses() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        directory
            .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
            .unwrap();
        let before = directory.metadata().unwrap();
        std::fs::write(root.path().join("new-entry"), "ordinary").unwrap();
        assert!(
            inspect(&directory, &before, &[(0, 0)], &mut 10, 0).is_err(),
            "changes after opening must refuse"
        );
        let before = directory.metadata().unwrap();
        assert!(
            inspect(&directory, &before, &[(0, 0)], &mut 0, 0).is_err(),
            "a partial enumeration must refuse"
        );
        assert!(
            inspect(&directory, &before, &[(0, 0)], &mut 10, MAX_DEPTH).is_err(),
            "excessive depth must refuse"
        );
    }

    #[test]
    fn a_missing_root_is_distinct_from_a_failed_directory_inspection() {
        let root = tempfile::tempdir().unwrap();
        let missing = contains(&root.path().join("new-output"), &[(0, 0)]).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }
}
