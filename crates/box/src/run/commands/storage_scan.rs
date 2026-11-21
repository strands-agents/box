//! Storage-specific command checks: provider trees are proved disjoint, never enumerated.
//!
//! The caller supplies the private compiler view with each admitted capture at its declared path.
//! This proof covers the current stable mount topology. It does not authorize later mount changes.

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use containment::{Operation, Scope};

use super::{ConfiguredCommands, aliases};
use crate::error::{BoxError, ConfigError};
use crate::record::config::filesystem::DirectReach;

const MAX_TABLE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MOUNTS: usize = 65_536;
const PROOF_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn validate(
    commands: &ConfiguredCommands,
    table: &str,
    reach: &DirectReach,
    roots: &[PathBuf],
    admitted: &[PathBuf],
) -> Result<(), BoxError> {
    declarations(roots, admitted).map_err(|error| refusal(table, "storage.mounts", error))?;
    // Keep the ordinary name, inode, route, and ancestor checks, including file-only grants.
    for grant in &reach.grants {
        if grant.operation != Operation::Write {
            continue;
        }
        for command in commands.protected() {
            let overlaps = match grant.scope {
                Scope::Root | Scope::Dir => command.enclosed_by(&grant.resolved),
                Scope::File => command.names(&grant.resolved),
            };
            if overlaps {
                return Err(ConfigError::Filesystem {
                    table: table.to_string(),
                    entry: grant.authored.clone(),
                    reason: format!(
                        "this write grant can change {} command {} or its path. \
                         Keep {} outside every process's write grants",
                        command.table,
                        command.path.display(),
                        if command.table.starts_with("[secret-source.") {
                            "the program of each secret source"
                        } else {
                            "configured tools"
                        }
                    ),
                }
                .into());
            }
        }
    }
    // Do not call mutable_aliases/every_name_beside here: their optimization itself reads directories.
    // Imported compiler replicas retain this original flag and these original descriptor identities.
    let identities: Vec<_> = commands
        .protected()
        .filter(|command| command.needs_alias_scan)
        .map(|command| command.identity)
        .collect();
    if identities.is_empty()
        || !reach
            .grants
            .iter()
            .any(|grant| grant.operation == Operation::Write && grant.scope != Scope::File)
    {
        return Ok(());
    }
    let devices: HashSet<_> = commands
        .protected()
        .map(|command| command.identity.0)
        .collect();
    let proof = Proof::capture(roots, admitted, &devices)
        .map_err(|error| refusal(table, "storage.mounts", error))?;
    for grant in &reach.grants {
        if grant.operation != Operation::Write || grant.scope == Scope::File {
            continue;
        }
        proof
            .check_deadline()
            .map_err(|error| refusal(table, &grant.authored, error))?;
        let result = aliases::contains_excluding(&grant.resolved, &identities, &proof.excluded);
        let reason = match result {
            Ok(false) => continue,
            Ok(true) => "contains a hard link to a configured tool command".to_string(),
            Err(error) => format!("cannot be inspected for configured command hard links: {error}"),
        };
        return Err(ConfigError::Filesystem {
            table: table.to_string(),
            entry: grant.authored.clone(),
            reason: format!(
                "this write grant {reason}. Keep configured tools and their hard links \
                 outside every process's write grants"
            ),
        }
        .into());
    }
    proof
        .verify()
        .map_err(|error| refusal(table, "storage.mounts", error))
}

fn refusal(table: &str, entry: &str, error: io::Error) -> BoxError {
    ConfigError::Filesystem {
        table: table.to_string(),
        entry: entry.to_string(),
        reason: format!(
            "storage cannot be proved separate from configured command aliases without \
             enumerating its files: {error}"
        ),
    }
    .into()
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn declarations(roots: &[PathBuf], admitted: &[PathBuf]) -> io::Result<()> {
    for (index, root) in roots.iter().enumerate() {
        if !normalized_absolute(root) || root == Path::new("/") {
            return Err(invalid(
                "storage roots must be normalized absolute non-root paths",
            ));
        }
        if roots[..index]
            .iter()
            .any(|other| root.starts_with(other) || other.starts_with(root))
        {
            return Err(invalid("storage roots must be unique and nonnested"));
        }
    }
    for (index, root) in admitted.iter().enumerate() {
        if !roots.contains(root) || admitted[..index].contains(root) {
            return Err(invalid("admitted roots must be unique declared roots"));
        }
    }
    Ok(())
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

struct Proof {
    before: Option<Vec<u8>>,
    anchors: Vec<Anchor>,
    excluded: Vec<PathBuf>,
    deadline: Instant,
}

impl Proof {
    fn capture(
        roots: &[PathBuf],
        admitted: &[PathBuf],
        protected: &HashSet<u64>,
    ) -> io::Result<Self> {
        let deadline = Instant::now() + PROOF_TIMEOUT;
        let mut proof = Self {
            before: None,
            anchors: Vec::new(),
            excluded: roots
                .iter()
                .filter(|root| !admitted.contains(root))
                .cloned()
                .collect(),
            deadline,
        };
        if admitted.is_empty() {
            return Ok(proof);
        }
        let before = read_table()?;
        let mounts = MountTable::parse(&before, deadline)?;
        let mut initial_devices = HashSet::new();
        for root in admitted {
            proof.check_deadline()?;
            let anchor = Anchor::open(root)?;
            let active = mounts.active(&anchor)?;
            if active.point != *root || !anchor.directory {
                return Err(invalid(
                    "an admitted root is not an active directory mount at its declared path",
                ));
            }
            initial_devices.insert(active.device);
            proof.anchors.push(anchor);
        }
        // Include each descendant mount and every other mount of those filesystems. In particular,
        // a bind alias outside the declared spelling must not send an ancestor scan into a provider.
        let devices = mounts.disjoint_closure(admitted, initial_devices, protected, deadline)?;
        let points: BTreeSet<_> = mounts
            .entries
            .iter()
            .filter(|mount| devices.contains(&mount.device))
            .map(|mount| mount.point.clone())
            .collect();
        for point in points {
            proof.check_deadline()?;
            if proof.anchors.iter().any(|anchor| anchor.path == point) {
                proof.excluded.push(point);
                continue;
            }
            let anchor = Anchor::open(&point)?;
            let active = mounts.active(&anchor)?;
            // A hidden record must not prune the different filesystem visible above it.
            if active.point == point && devices.contains(&active.device) {
                proof.excluded.push(point);
                proof.anchors.push(anchor);
            }
        }
        proof.before = Some(before);
        proof.verify()?;
        Ok(proof)
    }

    fn check_deadline(&self) -> io::Result<()> {
        check_deadline(self.deadline)
    }

    fn verify(&self) -> io::Result<()> {
        self.verify_with(read_table)
    }

    fn verify_with(&self, mut read: impl FnMut() -> io::Result<Vec<u8>>) -> io::Result<()> {
        self.check_deadline()?;
        for anchor in &self.anchors {
            self.check_deadline()?;
            anchor.verify()?;
        }
        if let Some(before) = &self.before
            && *before != read()?
        {
            return Err(invalid(
                "the mount table changed during storage command inspection",
            ));
        }
        self.check_deadline()
    }
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "storage command inspection exceeded 30 seconds",
        ));
    }
    Ok(())
}

fn read_table() -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open("/proc/self/mountinfo")?
        .take(MAX_TABLE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TABLE_BYTES {
        return Err(invalid(
            "the mount table exceeds the storage inspection limit",
        ));
    }
    Ok(bytes)
}

struct Anchor {
    path: PathBuf,
    opened: File,
    identity: (u64, u64),
    mount_id: u64,
    directory: bool,
}

impl Anchor {
    fn open(path: &Path) -> io::Result<Self> {
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = opened.metadata()?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("a storage mount anchor is a symbolic link"));
        }
        let mount_id = descriptor_mount_id(&opened)?;
        Ok(Self {
            path: path.to_path_buf(),
            opened,
            identity: (metadata.dev(), metadata.ino()),
            mount_id,
            directory: metadata.is_dir(),
        })
    }

    fn verify(&self) -> io::Result<()> {
        let metadata = self.opened.metadata()?;
        let current = Self::open(&self.path)?;
        if (metadata.dev(), metadata.ino()) != self.identity
            || current.identity != self.identity
            || current.mount_id != self.mount_id
        {
            return Err(invalid(
                "a storage mount anchor changed during command inspection",
            ));
        }
        Ok(())
    }
}

fn descriptor_mount_id(file: &File) -> io::Result<u64> {
    let mut info = String::new();
    File::open(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?
        .take(4097)
        .read_to_string(&mut info)?;
    if info.len() > 4096 {
        return Err(invalid("descriptor mount information exceeds its limit"));
    }
    let mut selected = None;
    for line in info.lines() {
        if let Some(value) = line.strip_prefix("mnt_id:") {
            let id = value
                .trim()
                .parse::<u64>()
                .map_err(|_| invalid("invalid descriptor mount identity"))?;
            if id == 0 || selected.replace(id).is_some() {
                return Err(invalid("duplicate or zero descriptor mount identity"));
            }
        }
    }
    selected.ok_or_else(|| invalid("descriptor mount identity is missing"))
}

#[derive(Debug)]
struct Mount {
    id: u64,
    device: u64,
    point: PathBuf,
}

#[derive(Debug)]
struct MountTable {
    entries: Vec<Mount>,
}

impl MountTable {
    fn parse(bytes: &[u8], deadline: Instant) -> io::Result<Self> {
        if bytes.len() as u64 > MAX_TABLE_BYTES {
            return Err(invalid(
                "the mount table exceeds the storage inspection limit",
            ));
        }
        let mut ids = HashSet::new();
        let mut entries = Vec::new();
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            check_deadline(deadline)?;
            let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
            let separator = fields
                .iter()
                .position(|field| *field == b"-")
                .ok_or_else(|| invalid("mount table separator is missing"))?;
            if separator < 6
                || fields.len() != separator + 4
                || fields.iter().any(|field| field.is_empty())
            {
                return Err(invalid("invalid mount table fields"));
            }
            let number = |field: &[u8]| -> io::Result<u64> {
                std::str::from_utf8(field)
                    .ok()
                    .and_then(|text| text.parse().ok())
                    .ok_or_else(|| invalid("invalid mount table number"))
            };
            let id = number(fields[0])?;
            let _parent = number(fields[1])?;
            if id == 0 || !ids.insert(id) || entries.len() >= MAX_MOUNTS {
                return Err(invalid("duplicate mount identity or too many mounts"));
            }
            let mut parts = fields[2].split(|byte| *byte == b':');
            let major = parts
                .next()
                .ok_or_else(|| invalid("missing device major"))?;
            let minor = parts
                .next()
                .ok_or_else(|| invalid("missing device minor"))?;
            if parts.next().is_some() {
                return Err(invalid("invalid mount device"));
            }
            let major =
                u32::try_from(number(major)?).map_err(|_| invalid("invalid device major"))?;
            let minor =
                u32::try_from(number(minor)?).map_err(|_| invalid("invalid device minor"))?;
            let device = libc::makedev(major, minor);
            if libc::major(device) != major || libc::minor(device) != minor {
                return Err(invalid("mount device cannot be represented"));
            }
            let point = decode_path(fields[4])?;
            if !normalized_absolute(&point) {
                return Err(invalid("mount point is not a normalized absolute path"));
            }
            entries.push(Mount { id, device, point });
        }
        if entries.is_empty() {
            return Err(invalid("the mount table is empty"));
        }
        Ok(Self { entries })
    }

    fn active(&self, anchor: &Anchor) -> io::Result<&Mount> {
        let mount = self
            .entries
            .iter()
            .find(|mount| mount.id == anchor.mount_id)
            .ok_or_else(|| invalid("an active storage anchor is absent from the mount table"))?;
        if mount.device != anchor.identity.0 || !anchor.path.starts_with(&mount.point) {
            return Err(invalid(
                "storage anchor does not match its mount-table identity",
            ));
        }
        Ok(mount)
    }

    fn disjoint_closure(
        &self,
        roots: &[PathBuf],
        mut devices: HashSet<u64>,
        protected: &HashSet<u64>,
        deadline: Instant,
    ) -> io::Result<HashSet<u64>> {
        for mount in &self.entries {
            check_deadline(deadline)?;
            if roots.iter().any(|root| mount.point.starts_with(root)) {
                devices.insert(mount.device);
            }
        }
        loop {
            if !devices.is_disjoint(protected) {
                return Err(invalid(
                    "an admitted storage tree or mount alias shares a protected command device",
                ));
            }
            let points: Vec<_> = self
                .entries
                .iter()
                .filter(|mount| devices.contains(&mount.device))
                .map(|mount| &mount.point)
                .collect();
            let mut added = Vec::new();
            for mount in &self.entries {
                check_deadline(deadline)?;
                if !devices.contains(&mount.device)
                    && points.iter().any(|point| mount.point.starts_with(point))
                {
                    added.push(mount.device);
                }
            }
            if added.is_empty() {
                return Ok(devices);
            }
            devices.extend(added);
        }
    }
}

fn decode_path(field: &[u8]) -> io::Result<PathBuf> {
    let mut result = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        if field[index] == b'\\' {
            let octal = field
                .get(index + 1..index + 4)
                .ok_or_else(|| invalid("truncated mount-path escape"))?;
            let byte = match octal {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid("invalid mount-path escape")),
            };
            result.push(byte);
            index += 4;
        } else {
            if field[index] == 0 {
                return Err(invalid("mount path contains a null byte"));
            }
            result.push(field[index]);
            index += 1;
        }
    }
    Ok(PathBuf::from(OsString::from_vec(result)))
}

#[cfg(test)]
mod tests;
