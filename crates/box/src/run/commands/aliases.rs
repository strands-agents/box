//! Bounded inspection of directory entries for configured command identities.

use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::ptr::NonNull;
use std::time::{Duration, Instant};

const SCAN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DEPTH: usize = 128;
const DIRECTORY_FLAGS: libc::c_int = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Whether the folder of `path` holds all `links` names of the file `identity`.
///
/// Every name then shares the command's folder, which no write grant may reach, so no write
/// grant can hold one and the scan has nothing to find.
pub(super) fn every_name_beside(path: &Path, identity: (u64, u64), links: u64) -> bool {
    let Some(folder) = path.parent() else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(folder) else {
        return false;
    };
    let mut names = 0_u64;
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        if std::fs::symlink_metadata(entry.path())
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == identity)
        {
            names += 1;
        }
    }
    names == links
}

/// Inspect existing names without following symbolic links or accepting an incomplete directory walk.
pub(super) fn contains(path: &Path, identities: &[(u64, u64)]) -> io::Result<bool> {
    contains_before_deadline(
        path,
        identities,
        Instant::now() + SCAN_TIMEOUT,
        &check_deadline,
    )
}

fn contains_before_deadline(
    path: &Path,
    identities: &[(u64, u64)],
    deadline: Instant,
    check: &impl Fn(Instant) -> io::Result<()>,
) -> io::Result<bool> {
    let before = checked_io(deadline, check, || std::fs::symlink_metadata(path))?;
    if before.is_file() {
        return finish_before_deadline(
            deadline,
            check,
            Ok(identities.contains(&(before.dev(), before.ino()))),
        );
    }
    if !before.is_dir() {
        return finish_before_deadline(deadline, check, Ok(false));
    }
    // Once the root exists, every later missing name means the inspection was incomplete.
    let inspect_existing = || {
        let directory = checked_io(deadline, check, || {
            OpenOptions::new()
                .read(true)
                .custom_flags(DIRECTORY_FLAGS)
                .open(path)
        })?;
        let found = inspect(&directory, &before, identities, deadline, check, 0)?;
        let after = checked_io(deadline, check, || std::fs::symlink_metadata(path))?;
        require_unchanged(&before, &after)?;
        finish_before_deadline(deadline, check, Ok(found))
    };
    finish_before_deadline(deadline, check, inspect_existing()).map_err(|error: io::Error| {
        io::Error::other(format!("directory inspection failed: {error}"))
    })
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "directory inspection exceeded 30 seconds",
        ));
    }
    Ok(())
}

// Check the deadline around an operation; a blocked filesystem call must return first.
fn checked_io<T>(
    deadline: Instant,
    check: &impl Fn(Instant) -> io::Result<()>,
    operation: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    check(deadline)?;
    finish_before_deadline(deadline, check, operation())
}

fn finish_before_deadline<T>(
    deadline: Instant,
    check: &impl Fn(Instant) -> io::Result<()>,
    result: io::Result<T>,
) -> io::Result<T> {
    check(deadline)?;
    result
}

fn inspect(
    directory: &File,
    before: &Metadata,
    identities: &[(u64, u64)],
    deadline: Instant,
    check: &impl Fn(Instant) -> io::Result<()>,
    depth: usize,
) -> io::Result<bool> {
    if depth >= MAX_DEPTH {
        return Err(io::Error::other("directory depth exceeds 128"));
    }
    let opened = checked_io(deadline, check, || directory.metadata())?;
    require_unchanged(before, &opened)?;
    let stream = DirectoryStream::new(directory, deadline, check)?;
    while let Some(name) = stream.next(deadline, check)? {
        let metadata = checked_io(deadline, check, || entry_metadata(directory, &name))?;
        match metadata.st_mode & libc::S_IFMT {
            libc::S_IFREG => {
                if identities.contains(&entry_identity(&metadata)) {
                    return finish_before_deadline(deadline, check, Ok(true));
                }
            }
            libc::S_IFDIR => {
                let child = checked_io(deadline, check, || {
                    // SAFETY: the directory descriptor and terminated name stay live during openat.
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
                    Ok(unsafe { File::from_raw_fd(descriptor) })
                })?;
                let child_before = checked_io(deadline, check, || child.metadata())?;
                require_same_entry(&metadata, &child_before)?;
                if inspect(
                    &child,
                    &child_before,
                    identities,
                    deadline,
                    check,
                    depth + 1,
                )? {
                    return finish_before_deadline(deadline, check, Ok(true));
                }
                let after = checked_io(deadline, check, || entry_metadata(directory, &name))?;
                require_same_entry(&after, &child_before)?;
            }
            _ => {}
        }
    }
    let after = checked_io(deadline, check, || directory.metadata())?;
    require_unchanged(before, &after)?;
    finish_before_deadline(deadline, check, Ok(false))
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
    fn new(
        directory: &File,
        deadline: Instant,
        check: &impl Fn(Instant) -> io::Result<()>,
    ) -> io::Result<Self> {
        let duplicate = checked_io(deadline, check, || directory.try_clone())?;
        checked_io(deadline, check, || {
            let descriptor = duplicate.into_raw_fd();
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
        })
    }

    fn next(
        &self,
        deadline: Instant,
        check: &impl Fn(Instant) -> io::Result<()>,
    ) -> io::Result<Option<CString>> {
        loop {
            let name = checked_io(deadline, check, || {
                // SAFETY: the accessor gives this thread's errno; the directory stream is live.
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
                // SAFETY: readdir returned a terminated name, copied before the next call.
                Ok(Some(
                    unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_owned(),
                ))
            })?;
            let Some(name) = name else {
                return Ok(None);
            };
            if name.as_c_str() != c"." && name.as_c_str() != c".." {
                return Ok(Some(name));
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
    use std::cell::Cell;
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
    fn a_changed_directory_refuses() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        directory
            .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
            .unwrap();
        let before = directory.metadata().unwrap();
        std::fs::write(root.path().join("new-entry"), "ordinary").unwrap();
        assert!(
            inspect(
                &directory,
                &before,
                &[(0, 0)],
                Instant::now() + SCAN_TIMEOUT,
                &check_deadline,
                0,
            )
            .is_err(),
            "changes after opening must refuse"
        );
    }

    #[test]
    fn excessive_depth_refuses() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        let before = directory.metadata().unwrap();
        assert!(
            inspect(
                &directory,
                &before,
                &[(0, 0)],
                Instant::now() + SCAN_TIMEOUT,
                &check_deadline,
                MAX_DEPTH,
            )
            .is_err(),
            "excessive depth must refuse"
        );
    }

    #[test]
    fn an_expired_deadline_refuses_even_an_empty_tree() {
        let root = tempfile::tempdir().unwrap();
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let error =
            contains_before_deadline(root.path(), &[(0, 0)], expired, &check_deadline).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("30 seconds"));
    }

    #[test]
    fn recursive_inspection_keeps_the_original_deadline() {
        let root = tempfile::tempdir().unwrap();
        let command = root.path().join("command");
        let tree = root.path().join("tree");
        let nested = tree.join("child").join("grandchild");
        std::fs::write(&command, "command").unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::hard_link(&command, nested.join("alias")).unwrap();
        let deadline = Instant::now() + SCAN_TIMEOUT;
        let check = |seen| {
            assert_eq!(seen, deadline, "recursion must not restart the time budget");
            check_deadline(seen)
        };
        assert!(
            contains_before_deadline(&tree, &[identity(&command)], deadline, &check).unwrap(),
            "the alias in the grandchild must be inspected"
        );
    }

    #[test]
    fn a_successful_metadata_call_cannot_finish_after_the_deadline() {
        let root = tempfile::tempdir().unwrap();
        let deadline = Instant::now() + SCAN_TIMEOUT;
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let completed = Cell::new(false);
        let check = |seen| {
            assert_eq!(seen, deadline);
            check_deadline(if completed.get() { expired } else { seen })
        };
        let result = checked_io(deadline, &check, || {
            let metadata = std::fs::symlink_metadata(root.path());
            assert!(metadata.is_ok(), "the filesystem result must be successful");
            completed.set(true);
            metadata
        });
        assert!(completed.get(), "the filesystem operation must run");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn a_missing_root_after_the_deadline_does_not_count_as_absent() {
        let root = tempfile::tempdir().unwrap();
        let deadline = Instant::now() + SCAN_TIMEOUT;
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let completed = Cell::new(false);
        let check = |seen| {
            assert_eq!(seen, deadline);
            check_deadline(if completed.get() { expired } else { seen })
        };
        let result = checked_io(deadline, &check, || {
            let metadata = std::fs::symlink_metadata(root.path().join("new-output"));
            assert_eq!(
                metadata.as_ref().unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
            completed.set(true);
            metadata
        });
        assert!(completed.get(), "the filesystem operation must run");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn more_than_one_hundred_thousand_entries_are_fully_inspected() {
        let root = tempfile::tempdir().unwrap();
        let command = root.path().join("command");
        let tree = root.path().join("tree");
        std::fs::write(&command, "command").unwrap();
        std::fs::create_dir(&tree).unwrap();
        for entry in 0..100_001 {
            File::create(tree.join(format!("ordinary-{entry}"))).unwrap();
        }
        let identities = [identity(&command)];
        assert!(!contains(&tree, &identities).unwrap());
        std::fs::hard_link(&command, tree.join("alias")).unwrap();
        assert!(contains(&tree, &identities).unwrap());
    }

    #[test]
    fn a_missing_root_is_distinct_from_a_failed_directory_inspection() {
        let root = tempfile::tempdir().unwrap();
        let missing = contains(&root.path().join("new-output"), &[(0, 0)]).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }
}
