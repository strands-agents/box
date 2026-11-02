//! Inode permissions for uncertain hard-link aliases of native dependencies.

use crate::model::{ObjectIdentity, PathGrant};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

pub(super) fn hard_link_alias_may_be_writable(file: &File, write_root: &PathGrant) -> bool {
    let Ok(metadata) = file.metadata() else {
        return true;
    };
    // SAFETY: these calls read the process credentials without changing them.
    let users = unsafe { [libc::getuid(), libc::geteuid()] };
    if inode_may_be_writable(metadata.uid(), metadata.mode(), users, || {
        // SAFETY: the descriptor is live, and the empty path is a terminated string.
        let result = unsafe {
            libc::syscall(
                libc::SYS_faccessat2,
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::W_OK,
                libc::AT_EACCESS | libc::AT_EMPTY_PATH,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }) {
        return true;
    }
    let Ok(root) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&write_root.resolved)
    else {
        return true;
    };
    let Ok(root_metadata) = root.metadata() else {
        return true;
    };
    if write_root.identity != Some(ObjectIdentity::from_metadata(&root_metadata)) {
        return true;
    }
    let (Some(source_mount), Some(root_mount)) = (mount_id(file), mount_id(&root)) else {
        return true;
    };
    let Ok(table) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return true;
    };
    !root_uses_compatible_mounts(
        &table,
        [&write_root.original, &write_root.resolved],
        (source_mount, metadata.dev()),
        (root_mount, root_metadata.dev()),
    )
}

fn inode_may_be_writable(
    owner: u32,
    mode: u32,
    users: [u32; 2],
    access: impl FnOnce() -> std::io::Result<()>,
) -> bool {
    users.contains(&owner)
        || mode & 0o022 != 0
        || !matches!(access(), Err(error) if error.raw_os_error() == Some(libc::EACCES))
}

fn mount_id(file: &File) -> Option<u64> {
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
        return None;
    }
    // SAFETY: statx initialized the output buffer after a successful call.
    let metadata = unsafe { metadata.assume_init() };
    (metadata.stx_mask & libc::STATX_MNT_ID != 0).then_some(metadata.stx_mnt_id)
}

#[derive(Debug, PartialEq, Eq)]
struct MountRecord<'a> {
    identity: u64,
    device: u64,
    point: PathBuf,
    idmapped: bool,
    filesystem: &'a str,
}

fn root_uses_compatible_mounts(
    table: &str,
    roots: [&Path; 2],
    source_identity: (u64, u64),
    root_identity: (u64, u64),
) -> bool {
    let Some(mounts) = table.lines().map(mount_record).collect::<Option<Vec<_>>>() else {
        return false;
    };
    let identities: std::collections::BTreeSet<_> =
        mounts.iter().map(|mount| mount.identity).collect();
    if identities.len() != mounts.len() {
        return false;
    }
    let Some(source) = mounts
        .iter()
        .find(|mount| (mount.identity, mount.device) == source_identity)
    else {
        return false;
    };
    let Some(root) = mounts.iter().find(|mount| {
        (mount.identity, mount.device) == root_identity && roots[1].starts_with(&mount.point)
    }) else {
        return false;
    };
    if source.identity != root.identity
        && (source.idmapped
            || root.idmapped
            || !ordinary_local_filesystem(source.filesystem)
            || !ordinary_local_filesystem(root.filesystem))
    {
        return false;
    }
    !mounts.iter().any(|mount| {
        mount.identity != root.identity && roots.iter().any(|root| mount.point.starts_with(root))
    })
}

fn ordinary_local_filesystem(filesystem: &str) -> bool {
    matches!(
        filesystem,
        "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "tmpfs" | "ramfs"
    )
}

fn mount_record(line: &str) -> Option<MountRecord<'_>> {
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    let separator = fields.iter().position(|field| *field == "-")?;
    if separator < 6 || fields.len() != separator + 4 {
        return None;
    }
    let identity = fields[0].parse().ok()?;
    fields[1].parse::<u64>().ok()?;
    let (major, minor) = fields[2].split_once(':')?;
    let device = libc::makedev(major.parse().ok()?, minor.parse().ok()?);
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
    point.is_absolute().then_some(MountRecord {
        identity,
        device,
        point,
        idmapped: fields[5].split(',').any(|option| option == "idmapped"),
        filesystem: fields[separator + 1],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_owned_readonly_inode_permissions_exclude_writes() {
        for mode in [0o444, 0o644, 0o755] {
            assert!(!inode_may_be_writable(0, mode, [1000, 1000], || {
                Err(std::io::Error::from_raw_os_error(libc::EACCES))
            }));
        }
    }

    #[test]
    fn ownership_and_write_bits_keep_hard_link_aliases_restricted() {
        for (owner, mode, users) in [
            (1000, 0o444, [1000, 2000]),
            (2000, 0o444, [1000, 2000]),
            (0, 0o664, [1000, 1000]),
            (0, 0o646, [1000, 1000]),
        ] {
            assert!(inode_may_be_writable(owner, mode, users, || {
                panic!("ownership or writable mode bits already require restriction")
            }));
        }
    }

    #[test]
    fn only_a_permission_denial_can_exclude_an_unknown_writable_alias() {
        assert!(inode_may_be_writable(0, 0o644, [1000, 1000], || Ok(())));
        for error in [
            libc::EROFS,
            libc::ETXTBSY,
            libc::ENOSYS,
            libc::EPERM,
            libc::EBADF,
        ] {
            assert!(inode_may_be_writable(0, 0o644, [1000, 1000], || {
                Err(std::io::Error::from_raw_os_error(error))
            }));
        }
    }

    fn check_mounts(table: &str, source: u64, root: u64, root_device: u64) -> bool {
        root_uses_compatible_mounts(
            table,
            [Path::new("/work/project"), Path::new("/work/project")],
            (source, libc::makedev(8, 1)),
            (root, root_device),
        )
    }

    #[test]
    fn plain_bind_mounts_and_separate_local_filesystems_preserve_inode_permissions() {
        let base = "20 1 8:1 / / rw - ext4 /dev/root rw\n";
        let device = libc::makedev(8, 1);
        assert!(check_mounts(base, 20, 20, device));
        for (filesystem, numbers, device) in [
            ("ext4", "8:1", device),
            ("tmpfs", "0:42", libc::makedev(0, 42)),
        ] {
            let table =
                format!("{base}21 20 {numbers} / /work/project rw - {filesystem} none rw\n");
            assert!(check_mounts(&table, 20, 21, device));
        }
    }

    #[test]
    fn different_idmapped_mounts_keep_aliases_restricted() {
        let device = libc::makedev(8, 1);
        for (source_options, root_options) in [
            ("rw,idmapped", "rw"),
            ("rw", "rw,idmapped"),
            ("rw,idmapped", "rw,idmapped"),
        ] {
            let table = format!(
                "20 1 8:1 / / {source_options} - ext4 /dev/root rw\n\
                 21 20 8:1 / /work/project {root_options} - ext4 /dev/root rw\n"
            );
            assert!(!check_mounts(&table, 20, 21, device));
        }
        let same = "20 1 8:1 / / rw,idmapped - ext4 /dev/root rw\n";
        assert!(check_mounts(same, 20, 20, device));
        let ordinary = "20 1 8:1 / / rw - ext4 /dev/root rw\n\
                        21 20 8:1 / /work/project rw,not-idmapped - ext4 /dev/root rw\n";
        assert!(check_mounts(ordinary, 20, 21, device));
    }

    #[test]
    fn layered_and_unknown_filesystems_keep_cross_mount_aliases_restricted() {
        let device = libc::makedev(8, 1);
        for filesystem in ["overlay", "fuse", "fuse.sshfs", "vfat", "nfs", "unknown"] {
            for (source, root) in [(filesystem, "ext4"), ("ext4", filesystem)] {
                let table = format!(
                    "20 1 8:1 / / rw - {source} none rw\n\
                     21 20 8:1 / /work/project rw - {root} none rw\n"
                );
                assert!(!check_mounts(&table, 20, 21, device));
            }
            let same = format!("20 1 8:1 / / rw - {filesystem} none rw\n");
            assert!(check_mounts(&same, 20, 20, device));
        }
    }

    #[test]
    fn an_unknown_or_nested_mount_keeps_aliases_restricted() {
        let base = "20 1 8:1 / / rw - ext4 /dev/root rw\n";
        let device = libc::makedev(8, 1);
        assert!(!check_mounts(base, 21, 20, device));
        assert!(!check_mounts(base, 20, 21, device));
        assert!(!check_mounts(base, 20, 20, libc::makedev(8, 2)));
        let source_mismatch = "20 1 8:2 / / rw - ext4 /dev/root rw\n";
        assert!(!check_mounts(source_mismatch, 20, 20, libc::makedev(8, 2)));
        for point in ["/work/project", "/work/project/nested"] {
            let table = format!("{base}21 20 8:1 / {point} rw - ext4 /dev/root rw\n");
            assert!(!check_mounts(&table, 20, 20, device));
        }
        let cross_mount = format!(
            "{base}21 20 0:42 / /work/project rw - tmpfs none rw\n\
             22 21 8:1 / /work/project/nested rw,idmapped - ext4 /dev/root rw\n"
        );
        assert!(!check_mounts(&cross_mount, 20, 21, libc::makedev(0, 42)));
        let sibling = format!("{base}21 20 8:1 / /work/project-other rw - ext4 /dev/root rw\n");
        assert!(check_mounts(&sibling, 20, 20, device));
    }

    #[test]
    fn mount_paths_preserve_unicode_and_decode_kernel_escapes() {
        let point = "/work/café\u{a0}data/two words\ttab\nline\\end";
        let line = r"21 20 8:1 / /work/café data/two\040words\011tab\012line\134end rw - ext4 /dev/root rw";
        assert_eq!(
            mount_record(line),
            Some(MountRecord {
                identity: 21,
                device: libc::makedev(8, 1),
                point: PathBuf::from(point),
                idmapped: false,
                filesystem: "ext4",
            })
        );
        let table = format!("20 1 8:1 / / rw - ext4 /dev/root rw\n{line}\n");
        let identity = (20, libc::makedev(8, 1));
        let roots = [Path::new("/work/link"), Path::new("/work/café\u{a0}data")];
        assert!(!root_uses_compatible_mounts(
            &table, roots, identity, identity
        ));
        let roots = [Path::new("/work/café\u{a0}data"), Path::new("/work/target")];
        assert!(!root_uses_compatible_mounts(
            &table, roots, identity, identity
        ));
    }

    #[test]
    fn malformed_mount_tables_cannot_exempt_a_dependency() {
        for table in [
            "",
            "20 1 8:1 / / rw",
            "20 bad 8:1 / / rw - ext4 /dev/root rw",
            "20 1 bad / / rw - ext4 /dev/root rw",
            "20 1 8:1 / relative rw - ext4 /dev/root rw",
            r"20 1 8:1 / /bad\777path rw - ext4 /dev/root rw",
            r"20 1 8:1 / /bad\path rw - ext4 /dev/root rw",
            "20 1 8:1 / / rw - ext4 /dev/root rw\nmalformed\n",
            "20 1 8:1 / / rw - ext4 /dev/root rw\n20 1 8:1 / / rw - ext4 /dev/root rw\n",
        ] {
            assert!(!check_mounts(table, 20, 20, libc::makedev(8, 1)));
        }
    }
}
