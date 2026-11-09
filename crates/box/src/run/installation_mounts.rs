use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use super::InstalledBinary;

#[derive(Debug)]
struct Mount {
    id: Option<u64>,
    filesystem: Vec<u8>,
    device: Vec<u8>,
    root: PathBuf,
    point: PathBuf,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct MountIdentity {
    id: u64,
    device: u64,
}

/// Inspect command names only within one unchanged filesystem view with no alternate mounts.
pub(in crate::run) fn inspect_single_mount(
    command: &File,
    directory: &File,
    folder: &Path,
    target: &Path,
    check: impl Fn() -> io::Result<()>,
    inspect: impl FnOnce() -> io::Result<bool>,
) -> io::Result<bool> {
    inspect_with_mount_table(
        || std::fs::read("/proc/self/mountinfo"),
        &check,
        |mounts| {
            let target_file = checked(&check, || {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(target)
            })?;
            let folder_path = checked(&check, || std::fs::canonicalize(folder))?;
            let target_path = checked(&check, || std::fs::canonicalize(target))?;
            for (file, path) in [(directory, &folder_path), (&target_file, &target_path)] {
                let opened = checked(&check, || file.metadata())?;
                let resolved = checked(&check, || std::fs::metadata(path))?;
                if (opened.dev(), opened.ino()) != (resolved.dev(), resolved.ino()) {
                    return Ok(false);
                }
            }
            let identities = [
                mount_identity(command, &check)?,
                mount_identity(directory, &check)?,
                mount_identity(&target_file, &check)?,
            ];
            if !one_complete_mount(mounts, identities, &folder_path, &target_path, &check)? {
                return Ok(false);
            }
            checked(&check, inspect)
        },
    )
}

fn inspect_with_mount_table(
    mut read_table: impl FnMut() -> io::Result<Vec<u8>>,
    check: &impl Fn() -> io::Result<()>,
    inspect: impl FnOnce(&[Mount]) -> io::Result<bool>,
) -> io::Result<bool> {
    let before = checked(check, &mut read_table)?;
    let mounts = parse_with_check(&before, check)?;
    let accepted = checked(check, || inspect(&mounts))?;
    let after = checked(check, read_table)?;
    let accepted = accepted && before == after;
    check()?;
    Ok(accepted)
}

fn mount_identity(file: &File, check: &impl Fn() -> io::Result<()>) -> io::Result<MountIdentity> {
    let metadata = checked(check, || file.metadata())?;
    let info = checked(check, || {
        std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
    })?;
    let mut id = None;
    for line in info.lines() {
        check()?;
        if let Some(value) = line.strip_prefix("mnt_id:") {
            let parsed = value.trim().parse::<u64>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid descriptor mount identity",
                )
            })?;
            if id.replace(parsed).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate descriptor mount identity",
                ));
            }
        }
    }
    let id = id.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing descriptor mount identity",
        )
    })?;
    Ok(MountIdentity {
        id,
        device: metadata.dev(),
    })
}

fn one_complete_mount(
    mounts: &[Mount],
    identities: [MountIdentity; 3],
    folder: &Path,
    target: &Path,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<bool> {
    check()?;
    let identity = identities[0];
    if identities.iter().any(|candidate| *candidate != identity) {
        return Ok(false);
    }
    let mut matching = None;
    for mount in mounts {
        check()?;
        if mount.id.is_none() {
            return Ok(false);
        }
        if mount.id == Some(identity.id) && matching.replace(mount).is_some() {
            return Ok(false);
        }
    }
    let Some(selected) = matching else {
        return Ok(false);
    };
    let device = format!(
        "{}:{}",
        libc::major(identity.device),
        libc::minor(identity.device)
    );
    if selected.root != Path::new("/")
        || !matches!(selected.filesystem.as_slice(), b"ext4" | b"xfs" | b"tmpfs")
        || selected.device != device.as_bytes()
        || !folder.starts_with(&selected.point)
        || !target.starts_with(&selected.point)
    {
        return Ok(false);
    }
    for mount in mounts {
        check()?;
        if mount.id != selected.id
            && (mount.device == selected.device || mount.point == selected.point)
        {
            return Ok(false);
        }
        if mount.point.starts_with(folder) || mount.point.starts_with(target) {
            return Ok(false);
        }
    }
    check()?;
    Ok(true)
}

fn checked<T>(
    check: &impl Fn() -> io::Result<()>,
    operation: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    check()?;
    let result = operation();
    check()?;
    result
}

pub(super) fn aliases(binaries: &[InstalledBinary]) -> io::Result<Vec<PathBuf>> {
    aliases_with_reader(binaries, || std::fs::read("/proc/self/mountinfo"))
}

fn aliases_with_reader(
    binaries: &[InstalledBinary],
    mut read_table: impl FnMut() -> io::Result<Vec<u8>>,
) -> io::Result<Vec<PathBuf>> {
    for _ in 0..3 {
        let before = read_table()?;
        let mounts = parse(&before)?;
        let mut names = Vec::new();
        for binary in binaries {
            names.extend(names_at_mounts(&binary.names, binary.identity, &mounts)?);
        }
        if before == read_table()? {
            return Ok(names);
        }
    }
    Err(io::Error::other(
        "the mount table changed while checking trusted executable aliases",
    ))
}

fn names_at_mounts(
    names: &[PathBuf],
    identity: (u64, u64),
    mounts: &[Mount],
) -> io::Result<Vec<PathBuf>> {
    let mut seen = HashSet::new();
    let mut aliases = Vec::new();
    for name in names {
        for source in mounts {
            let Ok(relative) = name.strip_prefix(&source.point) else {
                continue;
            };
            let filesystem_path = if relative.as_os_str().is_empty() {
                source.root.clone()
            } else {
                source.root.join(relative)
            };
            for destination in mounts {
                if source.device != destination.device {
                    continue;
                }
                let Ok(relative) = filesystem_path.strip_prefix(&destination.root) else {
                    continue;
                };
                let candidate = if relative.as_os_str().is_empty() {
                    destination.point.clone()
                } else {
                    destination.point.join(relative)
                };
                if !seen.insert(candidate.clone()) {
                    continue;
                }
                match std::fs::metadata(&candidate) {
                    Ok(metadata)
                        if metadata.is_file() && (metadata.dev(), metadata.ino()) == identity =>
                    {
                        aliases.push(candidate)
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                        ) => {}
                    // A name this process cannot inspect may be the installation, so it is protected as one.
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        aliases.push(candidate)
                    }
                    Err(error) => {
                        return Err(io::Error::new(
                            error.kind(),
                            format!(
                                "checking mounted executable alias {}: {error}",
                                candidate.display()
                            ),
                        ));
                    }
                }
            }
        }
    }
    Ok(aliases)
}

fn parse(table: &[u8]) -> io::Result<Vec<Mount>> {
    parse_with_check(table, &|| Ok(()))
}

fn parse_with_check(table: &[u8], check: &impl Fn() -> io::Result<()>) -> io::Result<Vec<Mount>> {
    check()?;
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mount table for trusted executable aliases",
        )
    };
    let mut mounts = Vec::new();
    for line in table
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        check()?;
        let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or_else(invalid)?;
        if separator < 6 || fields.len() != separator + 4 {
            return Err(invalid());
        }
        let device: Vec<_> = fields[2].split(|byte| *byte == b':').collect();
        if device.len() != 2
            || device
                .iter()
                .any(|part| part.is_empty() || !part.iter().all(u8::is_ascii_digit))
        {
            return Err(invalid());
        }
        let root = decode_path(fields[3])?;
        let point = decode_path(fields[4])?;
        if !root.is_absolute() || !point.is_absolute() {
            return Err(invalid());
        }
        let id = std::str::from_utf8(fields[0])
            .ok()
            .and_then(|value| value.parse::<u64>().ok());
        mounts.push(Mount {
            id,
            filesystem: fields[separator + 1].to_vec(),
            device: fields[2].to_vec(),
            root,
            point,
        });
    }
    if mounts.is_empty() {
        return Err(invalid());
    }
    check()?;
    Ok(mounts)
}

fn decode_path(field: &[u8]) -> io::Result<PathBuf> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid path escape in trusted executable mount table",
        )
    };
    let mut decoded = Vec::with_capacity(field.len());
    let mut offset = 0;
    while offset < field.len() {
        let byte = field[offset];
        if byte == b'\\' {
            let digits = field.get(offset + 1..offset + 4).ok_or_else(invalid)?;
            if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                return Err(invalid());
            }
            let value = digits
                .iter()
                .fold(0_u16, |value, digit| value * 8 + u16::from(digit - b'0'));
            if value == 0 || value > u16::from(u8::MAX) {
                return Err(invalid());
            }
            decoded.push(value as u8);
            offset += 4;
        } else {
            if byte == 0 {
                return Err(invalid());
            }
            decoded.push(byte);
            offset += 1;
        }
    }
    Ok(Path::new(&OsString::from_vec(decoded)).to_path_buf())
}

#[cfg(test)]
#[path = "installation_mounts_tests.rs"]
mod tests;
