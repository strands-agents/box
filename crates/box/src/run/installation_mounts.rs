use std::collections::HashSet;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use super::InstalledBinary;

#[derive(Debug)]
struct Mount {
    device: Vec<u8>,
    root: PathBuf,
    point: PathBuf,
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
        mounts.push(Mount {
            device: fields[2].to_vec(),
            root,
            point,
        });
    }
    if mounts.is_empty() {
        return Err(invalid());
    }
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
