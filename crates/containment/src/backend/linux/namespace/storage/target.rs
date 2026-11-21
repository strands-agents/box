//! Destination objects retained before workload execution and checked before publication.

use super::{Identity, attach, failure, identity, io_failure, own, transport};
use crate::{ContainmentError, Scope};
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};

struct Anchor {
    path: PathBuf,
    descriptor: OwnedFd,
    identity: Identity,
}

/// A target and every lexical ancestor, captured after the initial view is sealed.
pub(super) struct PinnedTarget {
    scope: Scope,
    anchors: Vec<Anchor>,
}

impl PinnedTarget {
    pub(super) fn capture(path: &Path, scope: Scope) -> Result<Self, ContainmentError> {
        let paths = target_paths(path, scope)?;
        let descriptors = open_components(&paths, scope)?;
        Self::from_descriptors(paths, descriptors, scope)
    }

    pub(super) fn send(&self, control: &UnixStream) -> Result<(), ContainmentError> {
        for anchor in &self.anchors {
            transport::send_fd(control, &anchor.descriptor)?;
        }
        Ok(())
    }

    pub(super) fn receive(
        control: &UnixStream,
        path: &Path,
        scope: Scope,
    ) -> Result<Self, ContainmentError> {
        let paths = target_paths(path, scope)?;
        let descriptors = paths
            .iter()
            .map(|_| transport::receive_fd(control))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_descriptors(paths, descriptors, scope)
    }

    fn from_descriptors(
        paths: Vec<PathBuf>,
        descriptors: Vec<OwnedFd>,
        scope: Scope,
    ) -> Result<Self, ContainmentError> {
        let last = paths.len() - 1;
        let anchors = paths
            .into_iter()
            .zip(descriptors)
            .enumerate()
            .map(|(index, (path, descriptor))| {
                require_kind(&descriptor, if index == last { scope } else { Scope::Root })?;
                require_read_only(&descriptor, &path)?;
                let identity = identity(&descriptor)?;
                Ok(Anchor {
                    path,
                    descriptor,
                    identity,
                })
            })
            .collect::<Result<Vec<_>, ContainmentError>>()?;
        Ok(Self { scope, anchors })
    }

    pub(super) fn descriptors(&self) -> impl Iterator<Item = std::os::fd::RawFd> + '_ {
        self.anchors
            .iter()
            .map(|anchor| anchor.descriptor.as_raw_fd())
    }

    pub(super) fn adopt_root(&self) -> Result<(), ContainmentError> {
        let root = &self
            .anchors
            .first()
            .expect("registration includes root")
            .descriptor;
        // SAFETY: the immutable registered root is adopted only by the disposable publisher.
        if unsafe { libc::fchdir(root.as_raw_fd()) } != 0
            || unsafe { libc::chroot(c".".as_ptr()) } != 0
            || unsafe { libc::chdir(c"/".as_ptr()) } != 0
        {
            return Err(io_failure(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Consume the registration so a target can be published only once through this object.
    pub(super) fn publish(self, prepared: &OwnedFd) -> Result<(), ContainmentError> {
        require_kind(prepared, self.scope)?;
        let paths = self
            .anchors
            .iter()
            .map(|anchor| anchor.path.clone())
            .collect::<Vec<_>>();
        let current = open_components(&paths, self.scope)?;
        for (anchor, descriptor) in self.anchors.iter().zip(&current) {
            require_read_only(descriptor, &anchor.path)?;
            if identity(descriptor)? != anchor.identity {
                return Err(failure(format!(
                    "publication target or ancestor '{}' changed after registration",
                    anchor.path.display()
                )));
            }
        }
        // Every lexical ancestor is immutable to the capability-free workload. The attachment uses
        // the retained target object, after confirming its current logical name still reaches it.
        attach(
            prepared,
            &self
                .anchors
                .last()
                .expect("validated target has ancestors")
                .descriptor,
        )
    }
}

fn target_paths(path: &Path, scope: Scope) -> Result<Vec<PathBuf>, ContainmentError> {
    if !matches!(scope, Scope::File | Scope::Root)
        || !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || path
            .as_os_str()
            .as_bytes()
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b"..")
    {
        return Err(failure(
            "publication target must be an absolute non-root file or directory without dot components",
        ));
    }
    let mut paths = path.ancestors().map(Path::to_path_buf).collect::<Vec<_>>();
    paths.reverse();
    Ok(paths)
}

fn open_components(paths: &[PathBuf], scope: Scope) -> Result<Vec<OwnedFd>, ContainmentError> {
    let mut descriptors = Vec::<OwnedFd>::with_capacity(paths.len());
    for (index, path) in paths.iter().enumerate() {
        let (parent, name) = if index == 0 {
            (libc::AT_FDCWD, Path::new("/"))
        } else {
            (
                descriptors[index - 1].as_raw_fd(),
                Path::new(path.file_name().expect("normal target component")),
            )
        };
        let name = CString::new(name.as_os_str().as_bytes())
            .map_err(|_| failure("target path contains NUL"))?;
        let directory = index + 1 != paths.len() || scope == Scope::Root;
        // SAFETY: a retained parent and one normal component cannot follow an ancestor link.
        let descriptor = own(unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_PATH
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | if directory { libc::O_DIRECTORY } else { 0 },
            )
        } as libc::c_long)?;
        require_kind(
            &descriptor,
            if directory { Scope::Root } else { Scope::File },
        )?;
        descriptors.push(descriptor);
    }
    Ok(descriptors)
}

fn require_kind(descriptor: &OwnedFd, scope: Scope) -> Result<(), ContainmentError> {
    // SAFETY: fstat writes a correctly sized local for an owned descriptor.
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut status) } != 0 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    let expected = if scope == Scope::File {
        libc::S_IFREG
    } else {
        libc::S_IFDIR
    };
    if status.st_mode & libc::S_IFMT != expected {
        return Err(failure(
            "publication target has the wrong object kind or is a symlink",
        ));
    }
    Ok(())
}

fn require_read_only(descriptor: &OwnedFd, path: &Path) -> Result<(), ContainmentError> {
    // SAFETY: fstatvfs writes a correctly sized local for an owned descriptor.
    let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(descriptor.as_raw_fd(), &mut status) } != 0 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    if status.f_flag & libc::ST_RDONLY == 0 {
        return Err(failure(format!(
            "publication target ancestor '{}' is writable",
            path.display()
        )));
    }
    Ok(())
}
