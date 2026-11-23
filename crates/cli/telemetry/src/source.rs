use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;

/// The source location established by the pack's file descriptor.
#[derive(Debug, Clone, Copy)]
pub enum PackLocation {
    Resources,
    Other,
    Unknown,
}

/// The loaded pack bytes and their source location.
pub fn read_pack(
    path: &Path,
    bundled: Option<(&Path, &str)>,
) -> io::Result<(String, PackLocation)> {
    let Some((root, id)) = bundled else {
        return std::fs::read_to_string(path).map(|text| (text, PackLocation::Other));
    };
    let open = || -> io::Result<File> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NONBLOCK).bits())
            .open(root)?;
        let pack = open_at(&directory, id, OFlag::O_DIRECTORY)?;
        Ok(open_at(&pack, "pack.toml", OFlag::O_NONBLOCK)?)
    };
    let Ok(mut file) = open() else {
        return std::fs::read_to_string(path).map(|text| (text, PackLocation::Unknown));
    };
    let location = match file.metadata() {
        Ok(metadata) if metadata.is_file() => PackLocation::Resources,
        Ok(_) => PackLocation::Other,
        Err(_) => PackLocation::Unknown,
    };
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok((text, location))
}

pub(crate) fn open_at(directory: &File, name: &str, flags: OFlag) -> Result<File, Errno> {
    let fd = openat(
        Some(directory.as_raw_fd()),
        name,
        flags | OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}
