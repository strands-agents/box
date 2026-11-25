//! Directory relationships anchored to an open object rather than its selected pathname.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use crate::record::config::filesystem::FileIdentity;

#[derive(Debug)]
pub(super) struct DirectoryPin {
    file: File,
    identity: FileIdentity,
}

fn directory_flags() -> libc::c_int {
    #[cfg(target_os = "linux")]
    let access = libc::O_PATH;
    #[cfg(not(target_os = "linux"))]
    let access = libc::O_RDONLY;
    access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
}

impl DirectoryPin {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        Self::from_file(
            OpenOptions::new()
                .read(true)
                .custom_flags(directory_flags())
                .open(path)?,
        )
    }

    fn from_file(file: File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "expected a directory",
            ));
        }
        Ok(Self {
            identity: FileIdentity::of(&metadata),
            file,
        })
    }

    fn parent(&self) -> io::Result<Self> {
        // SAFETY: the borrowed descriptor remains open, and the path is a terminated literal.
        let fd = unsafe { libc::openat(self.file.as_raw_fd(), c"..".as_ptr(), directory_flags()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new descriptor whose ownership moves into File.
        Self::from_file(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn within(&self, ancestor: &Self) -> io::Result<bool> {
        let mut current = Self::from_file(self.file.try_clone()?)?;
        let namespace_root = Self::open(Path::new("/"))?;
        for _ in 0..4096 {
            if current.identity == ancestor.identity {
                return Ok(true);
            }
            if current.identity == namespace_root.identity {
                return Ok(false);
            }
            current = current.parent()?;
        }
        Err(io::Error::other(
            "directory ancestry exceeds the validation limit",
        ))
    }

    pub(super) fn overlaps(&self, other: &Self) -> io::Result<bool> {
        Ok(self.within(other)? || other.within(self)?)
    }

    pub(super) fn intersects(&self, path: &Path) -> io::Result<bool> {
        match Self::open(path) {
            Ok(other) => return self.overlaps(&other),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => return Err(error),
        }
        // A file or absent suffix is inside the source only when its existing parent is inside it.
        // Merely sharing a parent does not make an unrelated absent sibling a restriction on it.
        for ancestor in path.ancestors().skip(1) {
            match Self::open(ancestor) {
                Ok(parent) => return parent.within(self),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no existing parent for a permission boundary",
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn directory_relationships_use_pins_and_keep_siblings_separate() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("source/child")).unwrap();
        std::fs::create_dir(root.join("sibling")).unwrap();
        std::fs::write(root.join("source/file"), "data").unwrap();
        std::fs::write(root.join("sibling/file"), "data").unwrap();
        let source = DirectoryPin::open(&root.join("source")).unwrap();
        let parent = DirectoryPin::open(&root).unwrap();
        let child = DirectoryPin::open(&root.join("source/child")).unwrap();
        let sibling = DirectoryPin::open(&root.join("sibling")).unwrap();
        assert!(source.within(&source).unwrap());
        assert!(source.within(&parent).unwrap());
        assert!(child.within(&source).unwrap());
        assert!(!parent.within(&source).unwrap());
        assert!(
            source
                .within(&DirectoryPin::open(Path::new("/")).unwrap())
                .unwrap()
        );
        assert!(!sibling.overlaps(&source).unwrap());
        assert!(source.intersects(&root.join("source/file")).unwrap());
        assert!(
            source
                .intersects(&root.join("source/absent/child"))
                .unwrap()
        );
        assert!(!source.intersects(&root.join("sibling/file")).unwrap());
        assert!(
            !source
                .intersects(&root.join("sibling/absent/child"))
                .unwrap()
        );
        assert!(!source.intersects(&root.join("absent/child")).unwrap());
        assert!(DirectoryPin::open(&root.join("source/file")).is_err());
        assert!(DirectoryPin::open(&root.join("absent")).is_err());
    }

    #[test]
    fn aliases_resolve_to_the_same_object_before_it_is_pinned() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("source")).unwrap();
        std::os::unix::fs::symlink(root.join("source"), root.join("alias")).unwrap();
        let source = DirectoryPin::open(&root.join("source")).unwrap();
        let alias = DirectoryPin::open(&root.join("alias").canonicalize().unwrap()).unwrap();
        assert!(source.overlaps(&alias).unwrap());
        assert!(DirectoryPin::open(&root.join("alias")).is_err());
    }
}
