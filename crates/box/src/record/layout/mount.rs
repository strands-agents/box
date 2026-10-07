//! Read the mount identity of an open descriptor.

use std::fs::File;
use std::io::{self, Read as _, Seek as _};
use std::os::fd::{AsRawFd as _, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, Ordering};

static INSPECTOR: AtomicPtr<MountInspector> = AtomicPtr::new(std::ptr::null_mut());

struct MountInspector {
    pid: u32,
    reader: Mutex<MountReader>,
}

struct MountReader {
    slot: File,
    information: File,
}

pub(super) fn prepare() -> io::Result<()> {
    if statx_identity(libc::AT_FDCWD).is_none() {
        inspector()?;
    }
    Ok(())
}

pub(super) fn identity(file: &File) -> io::Result<u64> {
    if let Some(identity) = statx_identity(file.as_raw_fd()) {
        return Ok(identity);
    }
    inspector()?
        .reader
        .lock()
        .map_err(|_| io::Error::other("mount inspector lock is poisoned"))?
        .identity(file)
}

fn statx_identity(descriptor: RawFd) -> Option<u64> {
    let mut metadata = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: statx writes the initialized buffer and inspects the supplied descriptor.
    let result = unsafe {
        libc::syscall(
            libc::SYS_statx,
            descriptor,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC,
            libc::STATX_MNT_ID,
            metadata.as_mut_ptr(),
        )
    };
    if result != 0 {
        return None;
    }
    // SAFETY: the buffer is initialized, including fields absent from the returned mask.
    let metadata = unsafe { metadata.assume_init() };
    (metadata.stx_mask & libc::STATX_MNT_ID != 0).then_some(metadata.stx_mnt_id)
}

fn inspector() -> io::Result<&'static MountInspector> {
    let pid = std::process::id();
    let mut published = INSPECTOR.load(Ordering::Acquire);
    loop {
        if !published.is_null() {
            // SAFETY: the PID is immutable and published allocations live for the process lifetime.
            let inspector = unsafe { &*published };
            if inspector.pid == pid {
                return Ok(inspector);
            }
        }
        let replacement = Box::into_raw(Box::new(MountInspector {
            pid,
            reader: Mutex::new(MountReader::open()?),
        }));
        match INSPECTOR.compare_exchange(
            published,
            replacement,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // SAFETY: the published allocation is never freed.
                return Ok(unsafe { &*replacement });
            }
            Err(current) => {
                // SAFETY: the failed publication leaves this allocation exclusively owned here.
                drop(unsafe { Box::from_raw(replacement) });
                published = current;
            }
        }
    }
}

impl MountReader {
    fn open() -> io::Result<Self> {
        let slot = File::open("/proc/self")?;
        let information = File::open(format!("/proc/self/fdinfo/{}", slot.as_raw_fd()))?;
        let mut reader = Self { slot, information };
        reader.read_identity()?;
        Ok(reader)
    }

    fn identity(&mut self, file: &File) -> io::Result<u64> {
        // SAFETY: both descriptors stay open and the mutex exclusively owns the destination slot.
        if unsafe { libc::dup3(file.as_raw_fd(), self.slot.as_raw_fd(), libc::O_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
        self.read_identity()
    }

    fn read_identity(&mut self) -> io::Result<u64> {
        self.information.rewind()?;
        let mut information = String::new();
        self.information.read_to_string(&mut information)?;
        parse_identity(&information)
    }
}

fn parse_identity(information: &str) -> io::Result<u64> {
    let mut identities = information
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:"));
    if let (Some(identity), None) = (identities.next(), identities.next())
        && let Ok(identity) = identity.trim().parse::<u64>()
    {
        return Ok(identity);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "its mount identity is unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use super::super::tests::mount_identity_under_syscall_refusals;
    use super::*;

    const NO_PATH_PROBES: &[(libc::c_long, libc::c_int)] = &[
        (libc::SYS_statx, libc::ENOSYS),
        (libc::SYS_openat, libc::EACCES),
        (libc::SYS_openat2, libc::EACCES),
        (libc::SYS_name_to_handle_at, libc::EOPNOTSUPP),
    ];

    fn expected_identity(file: &File) -> u64 {
        let information =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
                .expect("independent descriptor information");
        parse_identity(&information).expect("independent mount identity")
    }

    #[test]
    fn mount_inspector_reads_each_target_after_hardening() {
        let directory = tempfile::tempdir().expect("directory");
        let files = [
            File::open(directory.path()).expect("directory descriptor"),
            File::open("/proc").expect("proc descriptor"),
            File::open("/").expect("root descriptor"),
        ];
        let identities = files.each_ref().map(expected_identity);
        assert_ne!(identities[0], identities[1]);
        assert_ne!(identities[1], identities[2]);
        mount_identity_under_syscall_refusals(NO_PATH_PROBES, true, || {
            for _ in 0..10 {
                for (file, expected) in files.iter().zip(identities) {
                    if identity(file).ok() != Some(expected) {
                        return false;
                    }
                }
            }
            true
        });
    }

    #[test]
    fn mount_inspector_serializes_concurrent_targets() {
        let directory = tempfile::tempdir().expect("directory");
        let files = [
            File::open(directory.path()).expect("directory descriptor"),
            File::open("/proc").expect("proc descriptor"),
        ];
        let identities = files.each_ref().map(expected_identity);
        assert_ne!(identities[0], identities[1]);
        mount_identity_under_syscall_refusals(NO_PATH_PROBES, true, || {
            std::thread::scope(|scope| {
                let workers: Vec<_> = files
                    .iter()
                    .zip(identities)
                    .map(|(file, expected)| {
                        scope.spawn(move || (0..100).all(|_| identity(file).ok() == Some(expected)))
                    })
                    .collect();
                workers
                    .into_iter()
                    .all(|worker| worker.join().unwrap_or(false))
            })
        });
    }

    #[test]
    fn mount_inspector_replaces_a_forked_locked_parent_reader() {
        let directory = tempfile::tempdir().expect("directory");
        let parent_target = File::open(directory.path()).expect("parent descriptor");
        let child_target = File::open("/proc").expect("child descriptor");
        let child_identity = expected_identity(&child_target);
        let parent = inspector().expect("parent inspector");
        let mut locked = parent.reader.lock().expect("parent lock");
        assert_ne!(
            locked.identity(&parent_target).expect("parent identity"),
            child_identity
        );
        mount_identity_under_syscall_refusals(NO_PATH_PROBES, true, || {
            identity(&child_target).ok() == Some(child_identity)
                && inspector().is_ok_and(|child| child.pid != parent.pid)
        });
        drop(locked);
    }

    #[test]
    fn mount_inspector_does_not_return_a_previous_identity_after_an_io_error() {
        let file = File::open("/proc").expect("proc descriptor");
        for (syscall, error) in [
            (libc::SYS_dup3, libc::EBADF),
            (libc::SYS_lseek, libc::EIO),
            (libc::SYS_read, libc::EIO),
        ] {
            let mut refusals = NO_PATH_PROBES.to_vec();
            refusals.push((syscall, error));
            mount_identity_under_syscall_refusals(&refusals, true, || identity(&file).is_err());
        }
    }

    #[test]
    fn mount_inspector_descriptors_are_closed_on_exec() {
        let file = File::open("/proc").expect("proc descriptor");
        let mut reader = MountReader::open().expect("reader");
        for _ in 0..2 {
            reader.identity(&file).expect("identity");
            for descriptor in [&reader.slot, &reader.information] {
                // SAFETY: fcntl reads flags on the retained descriptor.
                let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
                assert_ne!(flags, -1);
                assert_ne!(flags & libc::FD_CLOEXEC, 0);
            }
        }
    }

    #[test]
    fn mount_inspector_refuses_missing_ambiguous_or_malformed_identity() {
        for information in [
            "",
            "ino:\t42\n",
            "mnt_id:\t\n",
            "mnt_id:\t-1\n",
            "mnt_id:\tword\n",
            "mnt_id:\t18446744073709551616\n",
            "mnt_id:\t27\nmnt_id:\t29\n",
        ] {
            assert!(parse_identity(information).is_err(), "{information:?}");
        }
        assert_eq!(parse_identity("pos:\t0\nmnt_id:\t27\n").unwrap(), 27);
    }
}
