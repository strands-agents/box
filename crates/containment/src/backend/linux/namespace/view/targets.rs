//! Mount targets opened without following symbolic links.

use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;

pub(super) struct MountTarget {
    root: File,
    relative: PathBuf,
    directory: bool,
    bind: bool,
    aliases: bool,
    location: PathBuf,
    target: File,
}

impl MountTarget {
    pub(super) fn prepare(
        view: &MountView,
        entry: &MountEntry,
        root: &Path,
        directory: bool,
    ) -> Result<Self, ContainmentError> {
        Self::prepare_target(view, entry, root, directory, false)
    }

    pub(super) fn prepare_bind(
        view: &MountView,
        entry: &MountEntry,
        root: &Path,
        directory: bool,
    ) -> Result<Self, ContainmentError> {
        Self::prepare_target(view, entry, root, directory, true)
    }

    fn prepare_target(
        view: &MountView,
        entry: &MountEntry,
        root: &Path,
        directory: bool,
        bind: bool,
    ) -> Result<Self, ContainmentError> {
        let staging_root = root.to_path_buf();
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)
            .map_err(|error| refusal(format!("opening the staging root: {error}")))?;
        let relative = entry
            .target
            .strip_prefix("/")
            .unwrap_or(&entry.target)
            .to_path_buf();
        let protected = matches!(
            entry.origin,
            MountOrigin::Protection { .. } | MountOrigin::TreeProtection { .. }
        );
        let create = (!protected).then_some((view, bind.then_some(entry.target.as_path())));
        let aliases = bind
            && entry
                .source
                .as_ref()
                .is_some_and(|source| source != &entry.target);
        let (target, resolved) = walk(
            &root,
            &relative,
            directory,
            !bind || protected,
            aliases,
            create,
        )?;
        let location = staging_root.join(resolved);
        if protected && aliases {
            let locations = view.mount_locations.borrow();
            let expected = view.entries.iter().any(|grant| {
                if grant.kind != MountKind::Bind || !grant.writable {
                    return false;
                }
                let (Some(source), Some(granted)) = (&entry.source, &grant.source) else {
                    return false;
                };
                let Ok(suffix) = source.strip_prefix(granted) else {
                    return false;
                };
                grant.target.join(suffix) == entry.target
                    && locations
                        .get(&grant.target)
                        .is_some_and(|granted| granted.join(suffix) == location)
            });
            if !expected {
                return Err(refusal(format!(
                    "write-protected mountpoint '{}' resolved to an unexpected location",
                    entry.target.display()
                )));
            }
        }
        Ok(Self {
            root,
            relative,
            directory,
            bind,
            aliases,
            location,
            target,
        })
    }

    pub(super) fn metadata(&self) -> Result<std::fs::Metadata, ContainmentError> {
        self.target
            .metadata()
            .map_err(|error| refusal(format!("inspecting mount target: {error}")))
    }

    pub(super) fn location(&self) -> &Path {
        &self.location
    }

    pub(super) fn path(&self) -> PathBuf {
        descriptor_path(&self.target)
    }

    pub(super) fn require_new_mount(
        &self,
        spelling: &Path,
        previous: &BTreeSet<u64>,
    ) -> Result<File, ContainmentError> {
        // A root overmount must be reopened through its staging name.
        let mounted = if self.relative.as_os_str().is_empty() {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(spelling)
                .map_err(|error| refusal(format!("opening the mounted root: {error}")))?
        } else {
            walk(
                &self.root,
                &self.relative,
                self.directory,
                !self.bind,
                self.aliases,
                None,
            )?
            .0
        };
        let id = mount_id(&mounted)?;
        let table = mount_table()?;
        let landed = table.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.next().and_then(|value| value.parse::<u64>().ok()) == Some(id)
                && fields
                    .nth(3)
                    .is_some_and(|raw| Path::new(&unescape_mount_field(raw)) == self.location)
        });
        if previous.contains(&id) || !landed {
            return Err(refusal(format!(
                "mount for '{}' did not land at its own mountpoint",
                spelling.display()
            )));
        }
        Ok(mounted)
    }

    pub(super) fn require_same_mount(
        &self,
        spelling: &Path,
        previous: &BTreeSet<u64>,
        expected: &File,
    ) -> Result<(), ContainmentError> {
        let mounted = self.require_new_mount(spelling, previous)?;
        if mount_id(&mounted)? != mount_id(expected)? {
            return Err(refusal(format!(
                "mount for '{}' changed after placement verification",
                spelling.display()
            )));
        }
        Ok(())
    }
}

fn mount_id(mounted: &File) -> Result<u64, ContainmentError> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", mounted.as_raw_fd()))
        .map_err(|error| refusal(format!("reading the mounted target identity: {error}")))?;
    info.lines()
        .find_map(|line| line.strip_prefix("mnt_id:")?.trim().parse::<u64>().ok())
        .ok_or_else(|| refusal("the mounted target has no mount identity".into()))
}

fn walk(
    root: &File,
    relative: &Path,
    directory: bool,
    regular_file: bool,
    aliases: bool,
    create: Option<(&MountView, Option<&Path>)>,
) -> Result<(File, PathBuf), ContainmentError> {
    let retain_root = || {
        root.try_clone()
            .map_err(|error| refusal(format!("retaining the staging root: {error}")))
    };
    let mut parent = retain_root()?;
    let mut parents = Vec::new();
    let mut remaining = std::collections::VecDeque::new();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(refusal(
                "a mount target contains a non-normal component".into(),
            ));
        };
        remaining.push_back(name.to_os_string());
    }
    let mut prefix = PathBuf::from("/");
    let mut followed = 0;
    while let Some(component) = remaining.pop_front() {
        if component == ".." {
            if let Some(previous) = parents.pop() {
                parent = previous;
                prefix.pop();
            }
            continue;
        }
        prefix.push(&component);
        let is_directory = directory || !remaining.is_empty();
        let name = path_to_c(Path::new(&component))?;
        let flags = libc::O_PATH
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if is_directory && !aliases {
                libc::O_DIRECTORY
            } else {
                0
            };
        let open = || {
            // SAFETY: parent owns the descriptor, and name is a live C string.
            let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
            if descriptor < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                // SAFETY: openat returned a new owned descriptor.
                Ok(unsafe { File::from_raw_fd(descriptor) })
            }
        };
        let child = match open() {
            Ok(child) => child,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) && create.is_some() => {
                let (view, pending_bind) = create.unwrap();
                if view.entries.iter().any(|entry| {
                    entry.kind == MountKind::Bind
                        && Some(entry.target.as_path()) != pending_bind
                        && prefix.starts_with(&entry.target)
                }) {
                    return Err(refusal(format!(
                        "'{}' is absent from the tree bound over it, and a mountpoint created there would be created on the host",
                        prefix.display()
                    )));
                }
                if is_directory {
                    // SAFETY: parent owns the descriptor, and name is a live C string.
                    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
                        return Err(refusal(format!(
                            "creating '{}': {}",
                            prefix.display(),
                            std::io::Error::last_os_error()
                        )));
                    }
                } else {
                    // SAFETY: parent owns the descriptor, and name is a live C string.
                    let descriptor = unsafe {
                        libc::openat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_CREAT
                                | libc::O_EXCL
                                | libc::O_WRONLY
                                | libc::O_NOFOLLOW
                                | libc::O_CLOEXEC,
                            0o600,
                        )
                    };
                    if descriptor < 0 {
                        return Err(refusal(format!(
                            "creating the mountpoint '{}': {}",
                            prefix.display(),
                            std::io::Error::last_os_error()
                        )));
                    }
                    // SAFETY: openat returned a new owned descriptor.
                    drop(unsafe { File::from_raw_fd(descriptor) });
                }
                open().map_err(|error| {
                    refusal(format!(
                        "opening mountpoint '{}': {error}",
                        prefix.display()
                    ))
                })?
            }
            Err(error) => {
                return Err(refusal(format!(
                    "opening mountpoint '{}' without following links: {error}",
                    prefix.display()
                )));
            }
        };
        let metadata = child.metadata().map_err(|error| {
            refusal(format!(
                "inspecting mountpoint '{}': {error}",
                prefix.display()
            ))
        })?;
        if metadata.is_symlink() && aliases {
            followed += 1;
            if followed > 40 {
                return Err(refusal(
                    "a mount target contains too many symbolic links".into(),
                ));
            }
            let link = link_contents(&child)?;
            prefix.pop();
            let mut redirected = std::collections::VecDeque::new();
            for component in link.components() {
                match component {
                    std::path::Component::RootDir => {
                        parent = retain_root()?;
                        parents.clear();
                        prefix = PathBuf::from("/");
                    }
                    std::path::Component::CurDir => {}
                    std::path::Component::ParentDir => {
                        redirected.push_back(std::ffi::OsString::from(".."))
                    }
                    std::path::Component::Normal(name) => redirected.push_back(name.to_os_string()),
                    _ => {
                        return Err(refusal(
                            "a mount target link contains an invalid component".into(),
                        ));
                    }
                }
            }
            redirected.append(&mut remaining);
            remaining = redirected;
            continue;
        }
        if is_directory && !metadata.is_dir() {
            return Err(refusal(format!(
                "mountpoint '{}' is not a directory",
                prefix.display()
            )));
        }
        if !is_directory && regular_file && !metadata.is_file() {
            return Err(refusal(format!(
                "refused file mountpoint '{}' is not a regular file",
                prefix.display()
            )));
        }
        parents.push(parent);
        parent = child;
    }
    Ok((
        parent,
        prefix.strip_prefix("/").unwrap_or(&prefix).to_path_buf(),
    ))
}

fn link_contents(link: &File) -> Result<PathBuf, ContainmentError> {
    use std::os::unix::ffi::OsStringExt as _;
    let mut bytes = vec![0u8; 256];
    loop {
        // SAFETY: link retains a symbolic link, and bytes supplies the writable buffer.
        let length = unsafe {
            libc::readlinkat(
                link.as_raw_fd(),
                c"".as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(refusal(format!(
                "reading a mount target link: {}",
                std::io::Error::last_os_error()
            )));
        }
        if (length as usize) < bytes.len() {
            bytes.truncate(length as usize);
            return Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)));
        }
        if bytes.len() >= 65536 {
            return Err(refusal("a mount target link is too long".into()));
        }
        bytes.resize(bytes.len() * 2, 0);
    }
}

pub(super) fn descriptor_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn mount_table() -> Result<String, ContainmentError> {
    std::fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        refusal(format!(
            "reading the mount table to verify target placement: {error}"
        ))
    })
}

pub(super) fn mount_ids() -> Result<BTreeSet<u64>, ContainmentError> {
    Ok(mount_table()?
        .lines()
        .filter_map(|line| line.split_whitespace().next()?.parse().ok())
        .collect())
}

#[cfg(test)]
thread_local! {
    pub(super) static AFTER_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_MOUNT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn after_open() {
    AFTER_OPEN.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
pub(super) fn after_mount() {
    AFTER_MOUNT.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
thread_local! {
    pub(super) static AFTER_BIND_TARGET_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_BIND_MOUNT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_BIND_SOURCE_PIN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_BIND_VERIFICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn after_bind_source_pin() {
    AFTER_BIND_SOURCE_PIN.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
pub(super) fn after_bind_target_open() {
    AFTER_BIND_TARGET_OPEN.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
pub(super) fn after_bind_mount() {
    AFTER_BIND_MOUNT.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
pub(super) fn after_bind_verification() {
    AFTER_BIND_VERIFICATION.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}
