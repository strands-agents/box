//! Bounded mount-table observations for declared storage roots.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

pub(crate) const MAX_TABLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 16 * 1024;

/// One attachment in the observed mount namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MountRecord {
    pub(crate) mount_id: u64,
    pub(crate) parent_id: u64,
    pub(crate) device_major: u32,
    pub(crate) device_minor: u32,
    pub(crate) root: PathBuf,
    pub(crate) mount_point: PathBuf,
    pub(crate) mount_options: Vec<u8>,
    pub(crate) shared: Option<u64>,
    pub(crate) master: Option<u64>,
    pub(crate) filesystem: OsString,
    pub(crate) source: OsString,
    pub(crate) super_options: Vec<u8>,
}

/// A complete, bounded snapshot of mountinfo records.
#[derive(Debug)]
pub(crate) struct MountTable {
    records: BTreeMap<u64, MountRecord>,
}

/// A reason the observation cannot yet supply a storage candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingReason {
    NoMountAtRoot,
    NonStorageFilesystem,
    ObservationChanged,
}

/// An attachment candidate without a filesystem-responsiveness claim.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SourceObservation<'a> {
    Pending(PendingReason),
    Candidate(&'a MountRecord),
}

/// An unreadable, malformed, or oversized mount-table snapshot.
#[derive(Debug)]
pub(crate) enum MountInfoError {
    Read(io::Error),
    Limit(&'static str),
    Invalid { line: usize, reason: &'static str },
}

impl fmt::Display for MountInfoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "reading storage mount table: {error}"),
            Self::Limit(reason) => write!(formatter, "storage mount table exceeds {reason}"),
            Self::Invalid { line, reason } => {
                write!(
                    formatter,
                    "invalid storage mount table at line {line}: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for MountInfoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            _ => None,
        }
    }
}

impl MountTable {
    /// Read only a bounded prefix before parsing the snapshot.
    pub(crate) fn read(reader: impl Read) -> Result<Self, MountInfoError> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_TABLE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(MountInfoError::Read)?;
        Self::parse(&bytes)
    }

    /// Parse the fixed fields and propagation tags of a complete snapshot.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, MountInfoError> {
        if bytes.len() > MAX_TABLE_BYTES {
            return Err(MountInfoError::Limit("the byte limit"));
        }
        let mut records = BTreeMap::new();
        let content = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        for (offset, line) in content.split(|byte| *byte == b'\n').enumerate() {
            let number = offset + 1;
            if line.len() > MAX_RECORD_BYTES {
                return Err(MountInfoError::Limit("the record byte limit"));
            }
            if records.len() == MAX_RECORDS {
                return Err(MountInfoError::Limit("the record count limit"));
            }
            let record = parse_record(line).map_err(|reason| MountInfoError::Invalid {
                line: number,
                reason,
            })?;
            if records.insert(record.mount_id, record).is_some() {
                return Err(MountInfoError::Invalid {
                    line: number,
                    reason: "duplicate mount identity",
                });
            }
        }
        Ok(Self { records })
    }

    /// Match the exact root against a freshly observed attachment identity.
    pub(crate) fn classify(&self, root: &Path, active_mount_id: u64) -> SourceObservation<'_> {
        let Some(record) = self.records.get(&active_mount_id) else {
            return SourceObservation::Pending(PendingReason::ObservationChanged);
        };
        if !root.is_absolute() || record.mount_point != root {
            return SourceObservation::Pending(PendingReason::NoMountAtRoot);
        }
        let filesystem = record.filesystem.as_bytes();
        let candidate = matches!(filesystem, b"nfs" | b"nfs4" | b"efs" | b"fuse")
            || filesystem
                .strip_prefix(b"fuse.")
                .is_some_and(|suffix| !suffix.is_empty());
        if candidate {
            SourceObservation::Candidate(record)
        } else {
            SourceObservation::Pending(PendingReason::NonStorageFilesystem)
        }
    }
}

fn parse_record(line: &[u8]) -> Result<MountRecord, &'static str> {
    if line.contains(&0) {
        return Err("NUL byte");
    }
    let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
    let separator = fields
        .iter()
        .position(|field| *field == b"-")
        .ok_or("missing field separator")?;
    if separator < 6 || fields.len() != separator + 4 {
        return Err("wrong field count");
    }
    // The kernel can emit an empty mount source; every other field must be present.
    if fields
        .iter()
        .enumerate()
        .any(|(index, field)| field.is_empty() && index != separator + 2)
    {
        return Err("empty field");
    }
    let mount_id = number(fields[0])
        .filter(|value| *value != 0)
        .ok_or("invalid mount identity")?;
    let parent_id = number(fields[1]).ok_or("invalid parent identity")?;
    let colon = fields[2]
        .iter()
        .position(|byte| *byte == b':')
        .ok_or("invalid device identity")?;
    let (major, rest) = fields[2].split_at(colon);
    let minor = &rest[1..];
    let device_major = number(major)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or("invalid device major")?;
    let device_minor = number(minor)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or("invalid device minor")?;
    let root = decoded_path(fields[3])?;
    let mount_point = decoded_path(fields[4])?;
    let mut shared = None;
    let mut master = None;
    for field in &fields[6..separator] {
        let parsed = if let Some(value) = field.strip_prefix(b"shared:") {
            Some((&mut shared, value))
        } else {
            field
                .strip_prefix(b"master:")
                .map(|value| (&mut master, value))
        };
        if let Some((target, value)) = parsed {
            let value = number(value)
                .filter(|value| *value != 0)
                .ok_or("invalid propagation identity")?;
            if target.replace(value).is_some() {
                return Err("duplicate propagation tag");
            }
        }
    }
    Ok(MountRecord {
        mount_id,
        parent_id,
        device_major,
        device_minor,
        root,
        mount_point,
        mount_options: fields[5].to_vec(),
        shared,
        master,
        filesystem: OsString::from_vec(decode(fields[separator + 1])?),
        source: OsString::from_vec(decode(fields[separator + 2])?),
        super_options: fields[separator + 3].to_vec(),
    })
}

fn number(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
    })
}

fn decoded_path(bytes: &[u8]) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(OsString::from_vec(decode(bytes)?));
    if !path.is_absolute() {
        return Err("non-absolute mount path");
    }
    Ok(path)
}

fn decode(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'\\' {
            decoded.push(bytes[cursor]);
            cursor += 1;
            continue;
        }
        let escaped = bytes
            .get(cursor + 1..cursor + 4)
            .ok_or("incomplete path escape")?;
        decoded.push(match escaped {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err("unknown path escape"),
        });
        cursor += 4;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(table: &[u8], root: &str, active: u64) -> PendingReason {
        let table = MountTable::parse(table).expect("valid fixture");
        match table.classify(Path::new(root), active) {
            SourceObservation::Pending(reason) => reason,
            SourceObservation::Candidate(_) => panic!("unexpected candidate"),
        }
    }

    #[test]
    fn initial_and_repeated_self_binds_remain_pending() {
        for identity in [21, 31, 109] {
            let table =
                format!("{identity} 1 8:1 /mnt/data /mnt/data rw shared:19 - ext4 /dev/root rw\n");
            assert_eq!(
                observation(table.as_bytes(), "/mnt/data", identity),
                PendingReason::NonStorageFilesystem
            );
        }
    }

    #[test]
    fn mounted_storage_needs_no_previous_snapshot() {
        let table = MountTable::parse(
            b"22 1 0:47 / /mnt/data rw,nosuid,nodev - fuse mountpoint-s3 rw,user_id=0\n",
        )
        .unwrap();
        let SourceObservation::Candidate(mount) = table.classify(Path::new("/mnt/data"), 22) else {
            panic!("actual FUSE attachment")
        };
        assert_eq!(mount.filesystem, "fuse");
        assert_eq!((mount.device_major, mount.device_minor), (0, 47));
    }

    #[test]
    fn an_empty_mount_source_does_not_hide_another_storage_mount() {
        let tmpfs = "114 28 0:54 / /tmp/emptysrc rw,relatime shared:129 - tmpfs  rw,inode64\n";
        for source in ["mountpoint-s3", ""] {
            let fuse =
                format!("22 1 0:47 / /mnt/data rw,nosuid,nodev - fuse {source} rw,user_id=0\n");
            for rows in [format!("{tmpfs}{fuse}"), format!("{fuse}{tmpfs}")] {
                let table = MountTable::parse(rows.as_bytes()).expect("valid empty source field");
                assert!(table.records[&114].source.is_empty());
                assert_eq!(
                    table.classify(Path::new("/tmp/emptysrc"), 114),
                    SourceObservation::Pending(PendingReason::NonStorageFilesystem)
                );
                let SourceObservation::Candidate(record) =
                    table.classify(Path::new("/mnt/data"), 22)
                else {
                    panic!("the FUSE attachment must remain observable")
                };
                assert_eq!(record.filesystem, "fuse");
                assert_eq!(record.source, source);
                assert_eq!(record.super_options, b"rw,user_id=0");
            }
        }
    }

    #[test]
    fn empty_fields_other_than_the_mount_source_still_refuse_the_snapshot() {
        let fields = [
            "10",
            "1",
            "0:1",
            "/",
            "/mnt/data",
            "rw",
            "shared:7",
            "-",
            "fuse",
            "source",
            "rw",
        ];
        for index in [0, 1, 2, 3, 4, 5, 6, 7, 8, 10] {
            let mut malformed = fields;
            malformed[index] = "";
            let row = malformed.join(" ");
            assert!(
                MountTable::parse(row.as_bytes()).is_err(),
                "empty field {index} was accepted: {row:?}"
            );
        }
    }

    #[test]
    fn source_arrival_changes_classification_not_just_identity() {
        let before = b"21 1 8:1 /mnt/data /mnt/data rw shared:19 - ext4 /dev/root rw\n";
        assert_eq!(
            observation(before, "/mnt/data", 21),
            PendingReason::NonStorageFilesystem
        );
        let after = MountTable::parse(b"21 1 8:1 /mnt/data /mnt/data rw shared:19 - ext4 /dev/root rw\n22 21 0:47 / /mnt/data rw - fuse mountpoint-s3 rw\n").unwrap();
        assert!(matches!(
            after.classify(Path::new("/mnt/data"), 22),
            SourceObservation::Candidate(_)
        ));
    }

    #[test]
    fn stacked_mount_selection_uses_the_observed_identity_in_either_row_order() {
        let fuse = "22 21 0:47 / /mnt/data rw - fuse mountpoint-s3 rw\n";
        let cover = "23 22 0:58 / /mnt/data rw - tmpfs tmpfs rw\n";
        for rows in [format!("{fuse}{cover}"), format!("{cover}{fuse}")] {
            let table = MountTable::parse(rows.as_bytes()).unwrap();
            assert_eq!(
                table.classify(Path::new("/mnt/data"), 23),
                SourceObservation::Pending(PendingReason::NonStorageFilesystem)
            );
            assert!(matches!(
                table.classify(Path::new("/mnt/data"), 22),
                SourceObservation::Candidate(_)
            ));
        }
    }

    #[test]
    fn prefixes_and_ancestor_mounts_do_not_supply_a_candidate() {
        let table = b"10 1 0:1 / /mnt rw - nfs4 server:/export rw,vers=4.1\n11 10 0:2 / /mnt/database rw - fuse source rw\n";
        for identity in [10, 11] {
            assert_eq!(
                observation(table, "/mnt/data", identity),
                PendingReason::NoMountAtRoot
            );
        }
    }

    #[test]
    fn unmatched_observed_identity_requests_another_observation() {
        assert_eq!(
            observation(
                b"10 1 0:1 / /mnt/data rw - fuse source rw\n",
                "/mnt/data",
                11
            ),
            PendingReason::ObservationChanged
        );
    }

    #[test]
    fn filesystem_family_is_not_inferred_from_other_fields() {
        let table = b"10 1 0:1 /fuse /mnt/fuse rw master:20 - ext4 fuse.s3files rw,nfs4\n";
        assert_eq!(
            observation(table, "/mnt/fuse", 10),
            PendingReason::NonStorageFilesystem
        );
    }

    #[test]
    fn network_and_userspace_storage_conventions_remain_candidates() {
        for (filesystem, options) in [
            ("nfs", "rw,vers=4.0"),
            ("nfs4", "rw,vers=4.1"),
            ("nfs4", "rw,vers=4.2"),
            ("efs", "rw"),
            ("fuse.s3files", "rw"),
            ("fuse.boxread", "rw"),
        ] {
            let row = format!("10 1 0:1 / /mnt/data rw - {filesystem} source {options}\n");
            let table = MountTable::parse(row.as_bytes()).unwrap();
            let SourceObservation::Candidate(record) = table.classify(Path::new("/mnt/data"), 10)
            else {
                panic!("supported filesystem form")
            };
            assert_eq!(record.super_options, options.as_bytes());
        }
        assert_eq!(
            observation(
                b"10 1 0:1 / /mnt/data rw - fuse. source rw\n",
                "/mnt/data",
                10
            ),
            PendingReason::NonStorageFilesystem
        );
    }

    #[test]
    fn paths_decode_all_mountinfo_escapes_without_a_second_decode() {
        let table = MountTable::parse(br"10 1 0:1 /root\040a /mnt/a\040b\011c\012d\134040 rw shared:6 master:8 - fuse source\040name rw").unwrap();
        let root = Path::new("/mnt/a b\tc\nd\\040");
        let SourceObservation::Candidate(record) = table.classify(root, 10) else {
            panic!("decoded exact path")
        };
        assert_eq!(record.root, Path::new("/root a"));
        assert_eq!(record.source, "source name");
        assert_eq!((record.shared, record.master), (Some(6), Some(8)));
    }

    #[test]
    fn non_utf8_paths_and_sources_are_retained() {
        let table = MountTable::parse(b"10 1 0:1 / /mnt/\xff rw - fuse source\xfe rw\n").unwrap();
        let path = PathBuf::from(OsString::from_vec(b"/mnt/\xff".to_vec()));
        let SourceObservation::Candidate(record) = table.classify(&path, 10) else {
            panic!("byte-preserving path")
        };
        assert_eq!(record.source.as_bytes(), b"source\xfe");
    }

    #[test]
    fn propagation_words_inside_a_path_are_not_optional_fields() {
        let table = MountTable::parse(b"10 1 0:1 / /mnt/master:7 rw - fuse shared:9 rw\n").unwrap();
        let SourceObservation::Candidate(record) = table.classify(Path::new("/mnt/master:7"), 10)
        else {
            panic!("candidate")
        };
        assert_eq!((record.shared, record.master), (None, None));
    }

    #[test]
    fn unknown_optional_tags_are_ignored_in_the_optional_field_region() {
        let table = MountTable::parse(b"10 1 0:1 / /mnt/data rw future:3 idmapped master:8 propagate_from:9 - fuse source rw\n").unwrap();
        let SourceObservation::Candidate(record) = table.classify(Path::new("/mnt/data"), 10)
        else {
            panic!("candidate")
        };
        assert_eq!(record.master, Some(8));
    }

    #[test]
    fn malformed_snapshots_fail_instead_of_partially_classifying() {
        let valid = "10 1 0:1 / /mnt/data rw - fuse source rw\n";
        for invalid in [
            "",
            "\n",
            "bad\n",
            "10 1 0:1 / /mnt/data rw fuse source rw\n",
            "10 1 0:1 / /mnt/data rw - fuse source\n",
            "10 1 0:1 / /mnt/data rw - fuse source rw extra\n",
            "10 1 0:1 / /mnt/data rw shared:no - fuse source rw\n",
            "10 1 0:1 / /mnt/data rw master:2 master:3 - fuse source rw\n",
            "10 1 0:1 / /mnt/data\\777 rw - fuse source rw\n",
            "10 1 0:1 / /mnt/data\\04 rw - fuse source rw\n",
            "18446744073709551616 1 0:1 / /mnt/data rw - fuse source rw\n",
            "10 1 0:4294967296 / /mnt/data rw - fuse source rw\n",
        ] {
            assert!(
                MountTable::parse(invalid.as_bytes()).is_err(),
                "{invalid:?}"
            );
        }
        assert!(MountTable::parse(format!("{valid}{valid}").as_bytes()).is_err());
        assert!(MountTable::parse(format!("{valid}bad\n").as_bytes()).is_err());
        assert!(MountTable::parse(format!("{valid}\n").as_bytes()).is_err());
    }

    #[test]
    fn table_record_and_count_limits_refuse_oversized_input() {
        assert!(matches!(
            MountTable::parse(&vec![b'x'; MAX_TABLE_BYTES + 1]),
            Err(MountInfoError::Limit(_))
        ));
        assert!(matches!(
            MountTable::parse(&vec![b'x'; MAX_RECORD_BYTES + 1]),
            Err(MountInfoError::Limit(_))
        ));
        let mut rows = String::new();
        for identity in 1..=MAX_RECORDS + 1 {
            rows.push_str(&format!(
                "{identity} 0 0:1 / /mnt/data rw - fuse source rw\n"
            ));
        }
        assert!(matches!(
            MountTable::parse(rows.as_bytes()),
            Err(MountInfoError::Limit(_))
        ));
    }

    #[test]
    fn bounded_reader_does_not_consume_an_unbounded_stream() {
        struct Counting {
            remaining: usize,
            consumed: std::rc::Rc<std::cell::Cell<usize>>,
        }
        impl Read for Counting {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                let length = bytes.len().min(self.remaining);
                bytes[..length].fill(b'x');
                self.remaining -= length;
                self.consumed.set(self.consumed.get() + length);
                Ok(length)
            }
        }
        let consumed = std::rc::Rc::new(std::cell::Cell::new(0));
        let result = MountTable::read(Counting {
            remaining: usize::MAX,
            consumed: consumed.clone(),
        });
        assert!(matches!(result, Err(MountInfoError::Limit(_))));
        assert_eq!(consumed.get(), MAX_TABLE_BYTES + 1);
    }

    #[test]
    fn reader_errors_remain_errors() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("probe failure"))
            }
        }
        assert!(matches!(
            MountTable::read(Broken),
            Err(MountInfoError::Read(_))
        ));
    }
}
