use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use containment::{Operation, Scope};

use crate::error::{BoxError, ConfigError, InstallationError};
use crate::record::config::filesystem::DirectReach;
use crate::record::layout::{disk_identity, lies_within};

#[cfg(target_os = "linux")]
#[path = "installation_mounts.rs"]
mod mounts;

#[cfg(not(target_os = "macos"))]
pub(super) fn executable() -> io::Result<PathBuf> {
    std::env::current_exe()
}

#[cfg(target_os = "macos")]
pub(super) fn executable() -> io::Result<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt as _;

    let mut buffer = [0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is writable for the supplied length, and getpid selects this process.
    let length = unsafe {
        libc::proc_pidpath(
            libc::getpid(),
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return Err(io::Error::last_os_error());
    }
    let path = CStr::from_bytes_until_nul(&buffer)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(PathBuf::from(OsStr::from_bytes(path.to_bytes())))
}

/// The installed executable identities that no workload may change.
#[derive(Debug)]
pub(crate) struct TrustedInstallation {
    binaries: Vec<InstalledBinary>,
    preparation: std::sync::Mutex<()>,
}

#[derive(Debug)]
struct InstalledBinary {
    path: PathBuf,
    names: Vec<PathBuf>,
    opened: File,
    identity: (u64, u64),
}

impl TrustedInstallation {
    pub(crate) fn load() -> Result<Self, BoxError> {
        let current = executable().map_err(|source| InstallationError::Locate { source })?;
        let helper = super::contain::trampoline::locate()?;
        Self::open(current, helper)
    }

    fn open(current: PathBuf, helper: PathBuf) -> Result<Self, BoxError> {
        let directory = helper.parent().ok_or_else(|| InstallationError::Invalid {
            path: helper.clone(),
            reason: "the installation has no parent directory".into(),
        })?;
        let mut binaries = vec![
            InstalledBinary::open_identity(current.clone(), directory)?,
            InstalledBinary::open(helper.clone(), directory)?,
            InstalledBinary::open(directory.join("strands-box-sock-alias"), directory)?,
        ];
        if current.ends_with("Box.app/Contents/MacOS/box") {
            let package = current
                .ancestors()
                .nth(4)
                .ok_or_else(|| InstallationError::Invalid {
                    path: current.clone(),
                    reason: "the application bundle has no package directory".into(),
                })?;
            let wrapper = package.join("box");
            match std::fs::symlink_metadata(&wrapper) {
                Ok(_) => binaries.push(InstalledBinary::open_identity(wrapper, package)?),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(InstallationError::Invalid {
                        path: wrapper,
                        reason: error.to_string(),
                    }
                    .into());
                }
            }
        }
        let installation = Self {
            binaries,
            preparation: std::sync::Mutex::new(()),
        };
        installation.verify()?;
        Ok(installation)
    }

    pub(crate) fn verify(&self) -> Result<(), BoxError> {
        for binary in &self.binaries {
            binary.verify()?;
        }
        Ok(())
    }

    pub(crate) fn launcher(&self) -> (&Path, &File) {
        let helper = &self.binaries[1];
        (&helper.path, &helper.opened)
    }

    pub(crate) fn alias_image(&self) -> (&Path, &File) {
        let alias = &self.binaries[2];
        (&alias.path, &alias.opened)
    }

    pub(crate) fn prepare(&self) -> std::sync::MutexGuard<'_, ()> {
        self.preparation
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn refuses_mutation(&self, path: &Path) -> bool {
        self.binaries.iter().any(|binary| binary.enclosed_by(path))
            || self.aliases().map_or(true, |aliases| {
                aliases.iter().any(|name| lies_within(name, path))
            })
    }

    fn aliases(&self) -> io::Result<Vec<PathBuf>> {
        #[cfg(target_os = "linux")]
        {
            mounts::aliases(&self.binaries)
        }
        #[cfg(target_os = "macos")]
        {
            let data = Path::new("/System/Volumes/Data");
            Ok(self
                .binaries
                .iter()
                .flat_map(|binary| {
                    binary.names.iter().filter_map(|name| {
                        let alias = if let Ok(relative) = name.strip_prefix(data) {
                            Path::new("/").join(relative)
                        } else {
                            data.join(name.strip_prefix("/").ok()?)
                        };
                        (disk_identity(&alias) == Some(binary.identity)).then_some(alias)
                    })
                })
                .collect())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Ok(Vec::new())
        }
    }

    pub(crate) fn validate_reach(&self, table: &str, reach: &DirectReach) -> Result<(), BoxError> {
        self.verify()?;
        let aliases = self.aliases().map_err(|error| InstallationError::Invalid {
            path: self.binaries[0].path.clone(),
            reason: format!("cannot inventory mounted executable aliases: {error}"),
        })?;
        for grant in &reach.grants {
            if grant.operation != Operation::Write {
                continue;
            }
            let protected = self
                .binaries
                .iter()
                .find(|binary| match grant.scope {
                    Scope::Root | Scope::Dir => binary.enclosed_by(&grant.resolved),
                    Scope::File => binary.names(&grant.resolved),
                })
                .map(|binary| &binary.path)
                .or_else(|| {
                    aliases.iter().find(|name| match grant.scope {
                        Scope::Root | Scope::Dir => lies_within(name, &grant.resolved),
                        Scope::File => **name == grant.resolved,
                    })
                });
            if let Some(path) = protected {
                return Err(ConfigError::Filesystem {
                    table: table.to_string(),
                    entry: grant.authored.clone(),
                    reason: format!(
                        "this write grant can change trusted Box executable {} or its path. \
                         Keep the Box installation outside every process's write grants",
                        path.display()
                    ),
                }
                .into());
            }
        }
        Ok(())
    }
}

impl InstalledBinary {
    fn open_identity(path: PathBuf, directory: &Path) -> Result<Self, BoxError> {
        #[cfg(target_os = "linux")]
        let flags = libc::O_PATH;
        #[cfg(target_os = "macos")]
        let flags = libc::O_EXEC;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let flags = 0;
        Self::open_with_flags(
            path,
            &[directory.to_path_buf(), directory.join("deps")],
            flags,
        )
    }

    fn open(path: PathBuf, directory: &Path) -> Result<Self, BoxError> {
        Self::open_with_inventory(path, &[directory.to_path_buf(), directory.join("deps")])
    }

    fn open_with_inventory(path: PathBuf, directories: &[PathBuf]) -> Result<Self, BoxError> {
        Self::open_with_flags(path, directories, 0)
    }

    fn open_with_flags(
        path: PathBuf,
        directories: &[PathBuf],
        flags: i32,
    ) -> Result<Self, BoxError> {
        let invalid = |reason: String| InstallationError::Invalid {
            path: path.clone(),
            reason,
        };
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|error| invalid(error.to_string()))?;
        let metadata = opened
            .metadata()
            .map_err(|error| invalid(error.to_string()))?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            return Err(invalid("must be an executable regular file".into()).into());
        }
        let identity = (metadata.dev(), metadata.ino());
        let mut names = vec![path.clone()];
        if metadata.nlink() > 1 {
            // Cargo places its second executable name in the installation's immediate deps directory.
            let entry_identity = |name: &Path| {
                let parent = name.parent()?;
                Some((disk_identity(parent)?, name.file_name()?.to_os_string()))
            };
            let mut entries = HashSet::new();
            entries.insert(entry_identity(&path).ok_or_else(|| {
                invalid("cannot identify the executable's directory entry".into())
            })?);
            let mut scanned = HashSet::new();
            for parent in directories {
                let parent_identity = match std::fs::symlink_metadata(parent) {
                    Ok(metadata) if metadata.is_dir() => (metadata.dev(), metadata.ino()),
                    Ok(_) => continue,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(invalid(error.to_string()).into()),
                };
                if !scanned.insert(parent_identity) {
                    continue;
                }
                for entry in
                    std::fs::read_dir(parent).map_err(|error| invalid(error.to_string()))?
                {
                    let entry = entry.map_err(|error| invalid(error.to_string()))?;
                    let candidate = entry.path();
                    if entry
                        .file_type()
                        .map_err(|error| invalid(error.to_string()))?
                        .is_file()
                        && disk_identity(&candidate) == Some(identity)
                        && entries.insert((parent_identity, entry.file_name()))
                    {
                        names.push(candidate);
                    }
                }
            }
        }
        if names.len() as u64 != metadata.nlink() {
            return Err(invalid(
                "has hard links outside the installation inventory. Install an independent copy"
                    .into(),
            )
            .into());
        }
        Ok(Self {
            path,
            names,
            opened,
            identity,
        })
    }

    fn verify(&self) -> Result<(), BoxError> {
        let unchanged = self
            .opened
            .metadata()
            .is_ok_and(|metadata| metadata.nlink() == self.names.len() as u64)
            && self.names.iter().all(|name| {
                std::fs::symlink_metadata(name).is_ok_and(|metadata| {
                    metadata.is_file() && (metadata.dev(), metadata.ino()) == self.identity
                })
            });
        if unchanged {
            Ok(())
        } else {
            Err(InstallationError::Changed {
                path: self.path.clone(),
            }
            .into())
        }
    }

    fn names(&self, path: &Path) -> bool {
        self.names.iter().any(|name| name == path) || disk_identity(path) == Some(self.identity)
    }

    fn enclosed_by(&self, path: &Path) -> bool {
        self.names(path) || self.names.iter().any(|name| lies_within(name, path))
    }
}

#[cfg(test)]
#[path = "installation_tests.rs"]
mod tests;
