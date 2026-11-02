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
    if source_mount != root_mount {
        return true;
    }
    let Ok(table) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return true;
    };
    !root_uses_only_mount(
        &table,
        [&write_root.original, &write_root.resolved],
        source_mount,
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

fn root_uses_only_mount(table: &str, roots: [&Path; 2], mount: u64) -> bool {
    let mut found = false;
    for line in table.lines() {
        let Some((identity, point)) = mount_point(line) else {
            return false;
        };
        if identity == mount && roots[1].starts_with(&point) {
            found = true;
        }
        if identity != mount && roots.iter().any(|root| point.starts_with(root)) {
            return false;
        }
    }
    found
}

fn mount_point(line: &str) -> Option<(u64, PathBuf)> {
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    let separator = fields.iter().position(|field| *field == "-")?;
    if separator < 6 || fields.len() != separator + 4 {
        return None;
    }
    let identity = fields[0].parse().ok()?;
    fields[1].parse::<u64>().ok()?;
    let (major, minor) = fields[2].split_once(':')?;
    major.parse::<u64>().ok()?;
    minor.parse::<u64>().ok()?;
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
    point.is_absolute().then_some((identity, point))
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

    #[test]
    fn an_unknown_or_nested_mount_keeps_aliases_restricted() {
        let base = "20 1 8:1 / / rw - ext4 /dev/root rw\n";
        let roots = [Path::new("/work/project"), Path::new("/work/project")];
        assert!(root_uses_only_mount(base, roots, 20));
        assert!(!root_uses_only_mount(base, roots, 21));
        for point in ["/work/project", "/work/project/nested"] {
            let table = format!("{base}21 20 8:1 / {point} rw - ext4 /dev/root rw\n");
            assert!(!root_uses_only_mount(&table, roots, 20));
        }
        let sibling = format!("{base}21 20 8:1 / /work/project-other rw - ext4 /dev/root rw\n");
        assert!(root_uses_only_mount(&sibling, roots, 20));
    }

    #[test]
    fn mount_paths_preserve_unicode_and_decode_kernel_escapes() {
        let point = "/work/café\u{a0}data/two words\ttab\nline\\end";
        let line = r"21 20 8:1 / /work/café data/two\040words\011tab\012line\134end rw - ext4 /dev/root rw";
        assert_eq!(mount_point(line), Some((21, PathBuf::from(point))));
        let table = format!("20 1 8:1 / / rw - ext4 /dev/root rw\n{line}\n");
        let roots = [Path::new("/work/link"), Path::new("/work/café\u{a0}data")];
        assert!(!root_uses_only_mount(&table, roots, 20));
        let roots = [Path::new("/work/café\u{a0}data"), Path::new("/work/target")];
        assert!(!root_uses_only_mount(&table, roots, 20));
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
        ] {
            assert!(!root_uses_only_mount(
                table,
                [Path::new("/work"), Path::new("/work")],
                20
            ));
        }
    }
}
