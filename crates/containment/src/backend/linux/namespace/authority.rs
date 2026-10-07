//! Dropping the authority the launcher needed, before the workload runs.

use crate::error::ContainmentError;

use super::MECHANISM;

/// Close every descriptor except the ones the workload is meant to keep.
pub(crate) fn close_inherited_descriptors(keep: &[libc::c_int]) -> Result<(), ContainmentError> {
    let entries = std::fs::read_dir("/proc/self/fd").map_err(|source| {
        // Failing closed matters here: if the descriptor table cannot be read, the
        // launcher cannot prove it closed the inherited ones.
        ContainmentError::ApplyFailed {
            backend: MECHANISM.to_string(),
            reason: format!(
                "enumerating /proc/self/fd to close inherited descriptors: {source}; \
                 refusing rather than exec with an unknown descriptor table"
            ),
        }
    })?;

    // Collect every candidate, THEN drop the enumeration handle, THEN close.
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        if let Some(number) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
            && !keep.contains(&number)
        {
            candidates.push(number);
        }
    }
    // `flatten()` consumed the iterator, so the directory handle is already closed here — which is
    // what lets the post-condition expect every attempted descriptor to be gone, with no special
    // case for the handle itself.

    for descriptor in &candidates {
        // A failed close is not fatal on its own; the post-condition below decides.
        // SAFETY: closing a descriptor number this process owns.
        unsafe { libc::close(*descriptor) };
    }

    // Verify, rather than trusting the `close` results just discarded.
    verify_closed(&candidates)
}

/// Refuse if any descriptor this pass tried to close is still open.
fn verify_closed(attempted: &[libc::c_int]) -> Result<(), ContainmentError> {
    for descriptor in attempted {
        // SAFETY: `F_GETFD` only reads a descriptor's flags; a closed descriptor
        // returns -1 with EBADF, which is the expected outcome.
        if unsafe { libc::fcntl(*descriptor, libc::F_GETFD) } != -1 {
            return Err(ContainmentError::ApplyFailed {
                backend: MECHANISM.to_string(),
                reason: format!(
                    "descriptor {descriptor} survived the inherited-descriptor close, \
                     so the mount view is not a boundary; refusing rather than exec \
                     the workload with a descriptor from outside its view"
                ),
            });
        }
    }

    Ok(())
}

/// Clear every capability set, including bounding and ambient.
pub(crate) fn drop_all_capabilities() -> Result<(), ContainmentError> {
    // Drop the bounding set first, one capability at a time: `PR_CAPBSET_DROP` takes a single
    // capability, and it requires CAP_SETPCAP -- which is in the effective set we are about to
    // clear.
    for capability in 0..=63 {
        // SAFETY: a prctl with scalar arguments and no pointers.
        let dropped = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if dropped != 0 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                // Past the last capability this kernel knows: done, not failed.
                Some(libc::EINVAL) => break,
                _ => {
                    return Err(ContainmentError::ApplyFailed {
                        backend: MECHANISM.to_string(),
                        reason: format!(
                            "dropping capability {capability} from the bounding set: \
                             {error}; a populated bounding set would let a later \
                             execve regain privilege"
                        ),
                    });
                }
            }
        }
    }

    // Now clear the three sets a `capset` call carries. Version 3 of the capability
    // ABI is what every supported kernel uses.
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    let header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        // 0 means "this thread", which is the only thread: apply runs
        // single-threaded.
        pid: 0,
    };
    // All-zero data clears effective, permitted, and inheritable in both 32-bit
    // halves.
    let data = [CapabilityData::default(); 2];

    // SAFETY: `capset` reads one header and two data words, both of which are
    // valid, correctly sized locals for the duration of the call.
    let result = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    if result != 0 {
        return Err(ContainmentError::ApplyFailed {
            backend: MECHANISM.to_string(),
            reason: format!(
                "clearing the capability sets: {}",
                std::io::Error::last_os_error()
            ),
        });
    }

    Ok(())
}

/// Set `no_new_privs`, so no `execve` can gain privilege.
pub(crate) fn set_no_new_privileges() -> Result<(), ContainmentError> {
    // SAFETY: a prctl with scalar arguments and no pointers.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(ContainmentError::ApplyFailed {
            backend: MECHANISM.to_string(),
            reason: format!("setting no_new_privs: {}", std::io::Error::last_os_error()),
        });
    }
    Ok(())
}

/// `struct __user_cap_header_struct`.
#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: libc::c_int,
}

/// `struct __user_cap_data_struct`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptors named in `keep` survive, and an unnamed one does not.
    #[test]
    fn only_the_kept_descriptors_survive() {
        let temporary = tempfile::NamedTempFile::new().expect("temp file");
        let victim = std::fs::File::open(temporary.path()).expect("open a victim descriptor");
        let victim_number = {
            use std::os::fd::AsRawFd as _;
            victim.as_raw_fd()
        };

        // SAFETY: the child only calls async-signal-safe operations plus a
        // directory read, and exits with `_exit`.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            let keep = [0, 1, 2];
            let closed_cleanly = close_inherited_descriptors(&keep).is_ok();
            // SAFETY: probing whether the descriptor is still open.
            let still_open = unsafe { libc::fcntl(victim_number, libc::F_GETFD) } != -1;
            // SAFETY: terminating the child with a status the parent reads.
            unsafe {
                libc::_exit(match (closed_cleanly, still_open) {
                    (true, false) => 0, // closed cleanly, victim gone
                    (true, true) => 1,  // victim survived: the close did nothing
                    (false, _) => 2,    // enumeration failed
                })
            };
        }

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "an inherited descriptor survived the close, so the mount view would \
             not be a boundary"
        );
    }

    /// The post-condition refuses when a descriptor survives the close.
    #[test]
    fn a_surviving_descriptor_is_refused_rather_than_ignored() {
        let temporary = tempfile::NamedTempFile::new().expect("temp file");
        let victim = std::fs::File::open(temporary.path()).expect("open a victim descriptor");
        let victim_number = {
            use std::os::fd::AsRawFd as _;
            victim.as_raw_fd()
        };

        // SAFETY: the child performs the close and exits; it never returns into
        // test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            // The post-condition is checked directly, because going through the close pass cannot
            // exercise it: that pass would simply close the victim, and a descriptor that closes is
            // not the case under test.
            let leaked = verify_closed(&[victim_number]).is_err();

            // And a descriptor that genuinely closed must pass, or every launch would refuse
            // itself.
            unsafe { libc::close(victim_number) };
            let closed_is_fine = verify_closed(&[victim_number]).is_ok();

            // SAFETY: terminating the child with the verdict.
            unsafe {
                libc::_exit(match (leaked, closed_is_fine) {
                    (true, true) => 0,
                    (false, _) => 1, // a surviving descriptor was NOT refused
                    (_, false) => 2, // a closed descriptor was wrongly refused
                })
            };
        }

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "a surviving descriptor must be refused: the mount view is not a boundary \
             while a descriptor from outside it is open"
        );
    }

    /// Dropping capabilities and setting `no_new_privs` both succeed, and the
    /// process afterwards holds an empty bounding set.
    #[test]
    fn dropping_authority_empties_every_capability_set() {
        if !super::super::probe::user_namespace_is_permitted() {
            println!(
                "skipping: this host forbids user namespaces, so the capability \
                 drop cannot be exercised in the context apply runs in"
            );
            return;
        }

        // SAFETY: the child performs the drops and exits; it does not return into
        // test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            // Read the ids BEFORE the unshare: inside a fresh user namespace with no map yet,
            // `getuid()` returns the overflow uid (65534) and mapping that is refused with EPERM.
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            // SAFETY: a single syscall with a constant argument; irreversible for
            // this child only.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
                // SAFETY: terminating the child.
                unsafe { libc::_exit(6) };
            }
            // The one-ID map, so the child holds the namespaced capability set the launcher's own
            // sequence holds.
            let _ = std::fs::write("/proc/self/setgroups", "deny");
            let _ = std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"));
            let _ = std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"));

            let dropped = drop_all_capabilities().is_ok();
            let locked = set_no_new_privileges().is_ok();
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();

            let empty = |field: &str| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix(field))
                    .map(|value| value.trim().chars().all(|c| c == '0'))
                    .unwrap_or(false)
            };

            let all_clear = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
                .iter()
                .all(|field| empty(field));
            let no_new_privs = status
                .lines()
                .find_map(|line| line.strip_prefix("NoNewPrivs:"))
                .map(|value| value.trim() == "1")
                .unwrap_or(false);

            // SAFETY: terminating the child with a status the parent reads.
            unsafe {
                libc::_exit(match (dropped, locked, all_clear, no_new_privs) {
                    (true, true, true, true) => 0,
                    (false, ..) => 2,
                    (_, false, ..) => 3,
                    (_, _, false, _) => 4,
                    (_, _, _, false) => 5,
                })
            };
        }

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "authority survived the drop (2=capset failed, 3=no_new_privs failed, \
             4=a capability set was non-empty, 5=no_new_privs was not set, \
             6=the child could not enter a user namespace)"
        );
    }
}
