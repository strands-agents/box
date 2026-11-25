//! One parser and descriptor identity reader for Linux mount checks.

use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Propagation {
    pub(super) shared: Option<u64>,
    pub(super) master: Option<u64>,
    pub(super) unbindable: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct MountRecord<'a> {
    pub(super) identity: u64,
    pub(super) parent: u64,
    pub(super) point: PathBuf,
    pub(super) idmapped: bool,
    pub(super) filesystem: &'a str,
    pub(super) propagation: Propagation,
}

pub(super) fn read() -> io::Result<String> {
    std::fs::read_to_string("/proc/self/mountinfo")
}

/// Read the identity of the pinned mount, not a new lookup of its pathname.
pub(super) fn mount_id(file: &File) -> io::Result<u64> {
    let mut metadata = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: the descriptor is live, and statx receives a valid output buffer.
    let result = unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            metadata.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statx initialized the output buffer after a successful call.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "statx returned no mount identity",
        ));
    }
    Ok(metadata.stx_mnt_id)
}

/// Ordinary target checks previously needed only fdinfo, which predates STATX_MNT_ID.
/// Keep that fallback without changing dependency policy's statx-only behavior.
pub(super) fn compatible_mount_id(file: &File) -> io::Result<u64> {
    with_fdinfo_fallback(mount_id(file), file)
}

fn with_fdinfo_fallback(primary: io::Result<u64>, file: &File) -> io::Result<u64> {
    primary.or_else(|_| {
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        info.lines()
            .find_map(|line| line.strip_prefix("mnt_id:")?.trim().parse().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "descriptor record has no mount identity",
                )
            })
    })
}

/// Reject the whole snapshot when a row is malformed or an identity repeats.
/// A parent may be outside the visible namespace; no complete ancestry is required.
pub(super) fn parse(table: &str) -> Option<Vec<MountRecord<'_>>> {
    let rows = table.lines().map(record).collect::<Option<Vec<_>>>()?;
    let mut identities = BTreeSet::new();
    rows.iter()
        .all(|row| identities.insert(row.identity))
        .then_some(rows)
}

fn record(line: &str) -> Option<MountRecord<'_>> {
    // Linux escapes ASCII separators; non-ASCII whitespace belongs to the path.
    let (mount, filesystem) = line.split_once(" - ")?;
    let fields: Vec<_> = mount.split_ascii_whitespace().collect();
    // The kernel preserves an explicitly empty source between two spaces.
    // Splitting this suffix on whitespace would erase that legitimate column.
    let filesystem: Vec<_> = filesystem.split(' ').collect();
    if fields.len() < 6
        || filesystem.len() != 3
        || filesystem[0].is_empty()
        || filesystem[2].is_empty()
        || filesystem
            .iter()
            .any(|field| field.bytes().any(|byte| byte.is_ascii_whitespace()))
    {
        return None;
    }
    let identity = fields[0].parse().ok()?;
    let parent = fields[1].parse().ok()?;
    let (major, minor) = fields[2].split_once(':')?;
    major.parse::<u32>().ok()?;
    minor.parse::<u32>().ok()?;
    let raw = fields[4];
    let mut remaining = raw;
    while let Some(index) = remaining.find('\\') {
        remaining = &remaining[index..];
        if ![r"\040", r"\011", r"\012", r"\134"]
            .iter()
            .any(|escape| remaining.starts_with(*escape))
        {
            return None;
        }
        remaining = &remaining[4..];
    }
    let point = PathBuf::from(super::unescape_mount_field(raw));
    if !point.is_absolute() {
        return None;
    }
    let mut propagation = Propagation::default();
    for field in &fields[6..] {
        if let Some(value) = field.strip_prefix("shared:") {
            if propagation.shared.replace(value.parse().ok()?).is_some() {
                return None;
            }
        } else if let Some(value) = field.strip_prefix("master:") {
            if propagation.master.replace(value.parse().ok()?).is_some() {
                return None;
            }
        } else if *field == "unbindable" {
            if propagation.unbindable {
                return None;
            }
            propagation.unbindable = true;
        } else if matches!(*field, "shared" | "master") || field.starts_with("unbindable:") {
            return None;
        }
        // Unknown optional fields are valid extensions, not propagation decisions.
    }
    if propagation.unbindable && (propagation.shared.is_some() || propagation.master.is_some()) {
        return None;
    }
    Some(MountRecord {
        identity,
        parent,
        point,
        idmapped: fields[5].split(',').any(|option| option == "idmapped"),
        filesystem: filesystem[0],
        propagation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_rows_keep_parent_and_propagation_without_requiring_visible_parents() {
        let table = "21 999 8:1 / /data rw,idmapped shared:7 master:4 propagate_from:3 future:yes - ext4 /dev/root rw\n22 21 0:42 / /data/child rw unbindable - tmpfs none rw\n";
        let rows = parse(table).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].identity, 21);
        assert_eq!(rows[0].parent, 999);
        assert_eq!(rows[0].point, PathBuf::from("/data"));
        assert!(rows[0].idmapped);
        assert_eq!(rows[0].filesystem, "ext4");
        assert_eq!(
            rows[0].propagation,
            Propagation {
                shared: Some(7),
                master: Some(4),
                unbindable: false
            }
        );
        assert_eq!(
            rows[1].propagation,
            Propagation {
                shared: None,
                master: None,
                unbindable: true
            }
        );
    }

    #[test]
    fn unicode_whitespace_and_kernel_escapes_remain_inside_mount_paths() {
        let row = record(r"21 20 8:1 / /work/café data/two\040words\011tab\012line\134end rw - ext4 /dev/root rw").unwrap();
        assert_eq!(
            row.point,
            PathBuf::from("/work/café\u{a0}data/two words\ttab\nline\\end")
        );
    }

    #[test]
    fn stacked_mounts_keep_distinct_identities_at_the_same_path() {
        let rows =
            parse("21 999 0:42 / /data rw - tmpfs  rw\n22 21 0:42 / /data rw - tmpfs none rw\n")
                .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].point, rows[1].point);
        assert_ne!(rows[0].identity, rows[1].identity);
        assert_eq!(rows[1].parent, rows[0].identity);
    }

    #[test]
    fn malformed_rows_and_duplicate_identities_refuse_the_whole_snapshot() {
        let valid = "20 999 8:1 / / rw - ext4 /dev/root rw\n";
        for bad in [
            "21 20 8:1 / /data rw",
            "21 bad 8:1 / /data rw - ext4 /dev/root rw",
            "21 20 bad / /data rw - ext4 /dev/root rw",
            "21 20 8:bad / /data rw - ext4 /dev/root rw",
            "21 20 bad:1 / /data rw - ext4 /dev/root rw",
            "21 20 8:1 / relative rw - ext4 /dev/root rw",
            r"21 20 8:1 / /bad\777path rw - ext4 /dev/root rw",
            r"21 20 8:1 / /bad\path rw - ext4 /dev/root rw",
            "21 20 8:1 / /data rw - ext4 /dev/root",
            "21 20 8:1 / /data rw - ext4 /dev/root rw extra",
            "21 20 8:1 / /data rw -  /dev/root rw",
            "21 20 8:1 / /data rw - ext4 /dev/root ",
            "21 20 8:1 / /data rw - ext4  ",
            "20 999 8:1 / / rw - ext4 /dev/root rw",
        ] {
            assert!(
                parse(&format!("{valid}{bad}\n")).is_none(),
                "accepted {bad}"
            );
        }
        for fields in [
            "shared:",
            "shared:bad",
            "master:",
            "master:bad",
            "shared",
            "master",
            "shared:1 shared:2",
            "master:1 master:2",
            "unbindable unbindable",
            "unbindable:1",
            "shared:1 unbindable",
            "master:1 unbindable",
        ] {
            let table = format!("{valid}21 20 8:1 / /data rw {fields} - ext4 /dev/root rw\n");
            assert!(parse(&table).is_none(), "accepted {fields}");
        }
    }

    #[test]
    fn ordinary_target_identity_survives_missing_or_blocked_statx_support() {
        let root = File::open("/").unwrap();
        let expected = mount_id(&root).unwrap();
        for error in [
            io::Error::new(io::ErrorKind::Unsupported, "missing STATX_MNT_ID"),
            io::Error::from_raw_os_error(libc::ENOSYS),
            io::Error::from_raw_os_error(libc::EPERM),
        ] {
            assert_eq!(with_fdinfo_fallback(Err(error), &root).unwrap(), expected);
        }
        assert_eq!(compatible_mount_id(&root).unwrap(), expected);
    }

    #[test]
    fn pinned_descriptor_identity_matches_the_kernel_descriptor_record() {
        let root = File::open("/").unwrap();
        let actual = mount_id(&root).unwrap();
        let fdinfo =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", root.as_raw_fd())).unwrap();
        let expected = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("mnt_id:")?.trim().parse::<u64>().ok())
            .unwrap();
        assert_eq!(actual, expected);
        assert!(
            parse(&read().unwrap())
                .unwrap()
                .iter()
                .any(|row| row.identity == actual)
        );
    }
}
