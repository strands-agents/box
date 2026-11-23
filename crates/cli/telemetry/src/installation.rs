use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

use nix::fcntl::{OFlag, openat, renameat};
use nix::libc;
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde::{Deserialize, Serialize};
use uuid::{Builder, Uuid, Variant, Version};

use crate::source::open_at;

const FILE: &str = "installation.toml";

/// The persistent random identifier for one installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct InstallationId(Uuid);

impl InstallationId {
    /// Read or create the installation identity in the Box directory.
    pub fn load_or_create(box_dir: &Path) -> io::Result<Self> {
        let directory = open_directory(box_dir)?;
        if let (Some(id), _) = read(&directory)? {
            return Ok(id);
        }
        lock(&directory)?;
        let (existing, text) = read(&directory)?;
        if let Some(id) = existing {
            return Ok(id);
        }
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(io::Error::other)?;
        let id = Builder::from_random_bytes(bytes).into_uuid();
        let (bom, text) = split_bom(&text);
        publish(
            &directory,
            &format!("{bom}installation_id = \"{id}\"\n{text}"),
        )?;
        Ok(Self(id))
    }
}

/// The saved `telemetry` choice; `None` when the file or the key is absent.
pub(crate) fn saved_choice(box_dir: &Path) -> io::Result<Option<bool>> {
    let directory = match open_existing_directory(box_dir) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(text) = read_text(&directory)? else {
        return Ok(None);
    };
    #[derive(Deserialize)]
    struct Choice {
        telemetry: Option<bool>,
    }
    let (_, text) = split_bom(&text);
    let choice: Choice = toml::from_str(text).map_err(|_| invalid())?;
    Ok(choice.telemetry)
}

/// Save the `telemetry` choice and keep every other key, including the installation ID.
pub fn save_telemetry_choice(box_dir: &Path, enabled: bool) -> io::Result<()> {
    let directory = open_directory(box_dir)?;
    lock(&directory)?;
    let text = read_text(&directory)?.unwrap_or_default();
    let (bom, text) = split_bom(&text);
    let mut document: toml_edit::DocumentMut = text.parse().map_err(|_| invalid())?;
    document["telemetry"] = toml_edit::value(enabled);
    publish(&directory, &format!("{bom}{document}"))
}

fn open_directory(box_dir: &Path) -> io::Result<File> {
    directory(box_dir, true)
}

fn open_existing_directory(box_dir: &Path) -> io::Result<File> {
    directory(box_dir, false)
}

fn directory(box_dir: &Path, create: bool) -> io::Result<File> {
    let open = |path: &Path| {
        OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
            .open(path)
    };
    let Some(name) = box_dir.file_name() else {
        return open(box_dir);
    };
    let parent = box_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if create {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let parent = open(parent)?;
    if create {
        match mkdirat(Some(parent.as_raw_fd()), name, Mode::S_IRWXU) {
            Ok(()) | Err(nix::errno::Errno::EEXIST) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let fd = openat(
        Some(parent.as_raw_fd()),
        name,
        OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Hold the directory's exclusive lock until `directory` closes.
fn lock(directory: &File) -> io::Result<()> {
    // SAFETY: directory owns an open descriptor; closing it releases the lock.
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Replace the metadata file atomically with `contents`.
fn publish(directory: &File, contents: &str) -> io::Result<()> {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    let staged_name = format!(".installation-{}.tmp", u64::from_ne_bytes(bytes));
    let fd = openat(
        Some(directory.as_raw_fd()),
        staged_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )?;
    // SAFETY: openat returned a new descriptor that nothing else owns.
    let mut staged = unsafe { File::from_raw_fd(fd) };
    let published = (|| -> io::Result<()> {
        staged.write_all(contents.as_bytes())?;
        staged.sync_all()?;
        renameat(
            Some(directory.as_raw_fd()),
            staged_name.as_str(),
            Some(directory.as_raw_fd()),
            FILE,
        )?;
        Ok(())
    })();
    let _ = unlinkat(
        Some(directory.as_raw_fd()),
        staged_name.as_str(),
        UnlinkatFlags::NoRemoveDir,
    );
    published
}

fn split_bom(text: &str) -> (&'static str, &str) {
    text.strip_prefix('\u{feff}')
        .map_or(("", text), |text| ("\u{feff}", text))
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid installation metadata")
}

/// The metadata file's text; `None` when it does not exist.
fn read_text(directory: &File) -> io::Result<Option<String>> {
    let mut file = match open_at(directory, FILE, OFlag::O_NONBLOCK) {
        Ok(file) => file,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(Some(text))
}

fn read(directory: &File) -> io::Result<(Option<InstallationId>, String)> {
    let Some(text) = read_text(directory)? else {
        return Ok((None, String::new()));
    };
    #[derive(Deserialize)]
    struct Installation {
        installation_id: Option<String>,
    }
    let installation: Installation = toml::from_str(&text).map_err(|_| invalid())?;
    let Some(installation_id) = installation.installation_id else {
        return Ok((None, text));
    };
    let id = Uuid::parse_str(&installation_id).map_err(|_| invalid())?;
    if id.get_version() != Some(Version::Random)
        || id.get_variant() != Variant::RFC4122
        || id.to_string() != installation_id
    {
        return Err(invalid());
    }
    Ok((Some(InstallationId(id)), text))
}

#[cfg(test)]
mod tests;
