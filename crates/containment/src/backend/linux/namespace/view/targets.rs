//! Mount targets opened without following symbolic links.

use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;

pub(super) struct MountTarget {
    root: File,
    relative: PathBuf,
    directory: bool,
    target: File,
}

impl MountTarget {
    pub(super) fn prepare(
        view: &MountView,
        entry: &MountEntry,
        root: &Path,
        directory: bool,
    ) -> Result<Self, ContainmentError> {
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
        let target = walk(&root, &relative, directory, Some(view))?;
        Ok(Self {
            root,
            relative,
            directory,
            target,
        })
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
            walk(&self.root, &self.relative, self.directory, None)?
        };
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", mounted.as_raw_fd()))
            .map_err(|error| refusal(format!("reading the mounted target identity: {error}")))?;
        let id = info
            .lines()
            .find_map(|line| line.strip_prefix("mnt_id:")?.trim().parse::<u64>().ok())
            .ok_or_else(|| refusal("the mounted target has no mount identity".into()))?;
        let table = mount_table()?;
        let landed = table.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.next().and_then(|value| value.parse::<u64>().ok()) == Some(id)
                && fields
                    .nth(3)
                    .is_some_and(|raw| Path::new(&unescape_mount_field(raw)) == spelling)
        });
        if previous.contains(&id) || !landed {
            return Err(refusal(format!(
                "mount for '{}' did not land at its own mountpoint",
                spelling.display()
            )));
        }
        Ok(mounted)
    }
}

fn walk(
    root: &File,
    relative: &Path,
    directory: bool,
    create: Option<&MountView>,
) -> Result<File, ContainmentError> {
    let mut parent = root
        .try_clone()
        .map_err(|error| refusal(format!("retaining the staging root: {error}")))?;
    let components: Vec<_> = relative.components().collect();
    let mut prefix = PathBuf::from("/");
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(refusal(
                "a mount target contains a non-normal component".into(),
            ));
        };
        prefix.push(name);
        let is_directory = directory || index + 1 != components.len();
        let name = path_to_c(Path::new(name))?;
        let flags = libc::O_PATH
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if is_directory { libc::O_DIRECTORY } else { 0 };
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
                let view = create.unwrap();
                if view
                    .entries
                    .iter()
                    .any(|entry| entry.kind == MountKind::Bind && prefix.starts_with(&entry.target))
                {
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
        if !is_directory
            && !child
                .metadata()
                .map_err(|error| {
                    refusal(format!(
                        "inspecting mountpoint '{}': {error}",
                        prefix.display()
                    ))
                })?
                .is_file()
        {
            return Err(refusal(format!(
                "refused file mountpoint '{}' is not a regular file",
                prefix.display()
            )));
        }
        parent = child;
    }
    Ok(parent)
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
