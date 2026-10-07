//! Refuse another process the trusted process's memory
//! (docs/design/decisions.md#the-trusted-processs-memory-is-a-defended-asset).
//!
//! What each mechanism buys, the four gaps it does *not* close, and why `mlockall` is
//! absent are measured in the crate's `AGENTS.md`. Read it before changing what is applied.
//!
//! **There is no opt-out.** Every mechanism here applies unconditionally, and no environment
//! variable declines one.

use std::fmt;

/// Applying the hardening failed in a way the platform does not explain.
#[derive(Debug)]
pub(crate) enum HardeningError {
    /// The descriptor mount inspector could not be prepared.
    #[cfg(target_os = "linux")]
    MountInspection(std::io::Error),
    /// `setrlimit(RLIMIT_CORE, {0, 0})` failed. Lowering a limit cannot legitimately fail.
    CoreLimit(std::io::Error),
    /// `prctl(PR_SET_DUMPABLE, 0)` returned an error. Linux documents none for a valid argument.
    #[cfg(target_os = "linux")]
    Dumpable(std::io::Error),
    /// The syscall reported success and the read-back did not agree.
    NotInEffect {
        /// What was checked, for the operator's message.
        what: &'static str,
        /// The value read back.
        observed: i32,
    },
}

impl fmt::Display for HardeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(target_os = "linux")]
            Self::MountInspection(error) => {
                write!(f, "could not prepare descriptor mount inspection: {error}")
            }
            Self::CoreLimit(error) => {
                write!(f, "could not disable core dumps (RLIMIT_CORE): {error}")
            }
            #[cfg(target_os = "linux")]
            Self::Dumpable(error) => {
                write!(f, "could not mark this process non-dumpable: {error}")
            }
            Self::NotInEffect { what, observed } => write!(
                f,
                "{what} reported success but is not in effect (read back {observed}); \
                 refusing to serve secrets from readable memory"
            ),
        }
    }
}

/// Make this process's memory unreadable to another process at the same UID.
pub(crate) struct Hardening;

impl Hardening {
    /// Apply every protection this platform offers, or refuse.
    pub(crate) fn apply() -> Result<(), HardeningError> {
        deny_core_dumps()?;
        #[cfg(target_os = "linux")]
        crate::record::layout::prepare_mount_inspection()
            .map_err(HardeningError::MountInspection)?;
        deny_memory_reads()?;
        deny_debugger_attach();
        Ok(())
    }
}

/// `setrlimit(RLIMIT_CORE, {0, 0})` — no core file, and the limit cannot be raised again.
#[cfg(unix)]
fn deny_core_dumps() -> Result<(), HardeningError> {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` with a valid resource and an initialized `rlimit` we own.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
        return Err(HardeningError::CoreLimit(std::io::Error::last_os_error()));
    }

    let mut observed = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: `getrlimit` writing into an `rlimit` we own.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut observed) } != 0 {
        return Err(HardeningError::CoreLimit(std::io::Error::last_os_error()));
    }
    if observed.rlim_cur != 0 || observed.rlim_max != 0 {
        return Err(HardeningError::NotInEffect {
            what: "RLIMIT_CORE=0",
            // Reported as the soft limit; a nonzero hard limit with a zero soft one is the
            // re-raisable state this exists to prevent, and prints as 0 only if truly zero.
            observed: i32::try_from(observed.rlim_cur.max(observed.rlim_max)).unwrap_or(i32::MAX),
        });
    }
    Ok(())
}

/// Non-Unix has no `RLIMIT_CORE`; there is nothing to refuse.
#[cfg(not(unix))]
fn deny_core_dumps() -> Result<(), HardeningError> {
    Ok(())
}

/// `prctl(PR_SET_DUMPABLE, 0)` — refuse `ptrace`, `process_vm_readv`, and the memory `/proc` nodes.
#[cfg(target_os = "linux")]
fn deny_memory_reads() -> Result<(), HardeningError> {
    // SAFETY: a prctl with scalar arguments and no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(HardeningError::Dumpable(std::io::Error::last_os_error()));
    }
    // SAFETY: `PR_GET_DUMPABLE` returns the flag as the return value; no pointers.
    let observed = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    if observed != 0 {
        return Err(HardeningError::NotInEffect {
            what: "PR_SET_DUMPABLE=0",
            observed,
        });
    }
    Ok(())
}

/// `PR_SET_DUMPABLE` is Linux-only. On every other platform the address space is protected by
/// [`deny_debugger_attach`] and `RLIMIT_CORE` alone.
#[cfg(not(target_os = "linux"))]
fn deny_memory_reads() -> Result<(), HardeningError> {
    Ok(())
}

/// `ptrace(PT_DENY_ATTACH)` — refuse a debugger on macOS.
#[cfg(target_os = "macos")]
fn deny_debugger_attach() {
    unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

/// `PT_DENY_ATTACH` is macOS-only.
#[cfg(not(target_os = "macos"))]
fn deny_debugger_attach() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// No environment variable declines a mechanism in this module.
    #[test]
    fn no_environment_variable_declines_the_hardening() {
        let needles = [
            format!("env{}var", "::"),
            format!("var{}os", "_"),
            format!("{}_env", "std"),
        ];
        let offenders: Vec<&str> = include_str!("hardening.rs")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| needles.iter().any(|needle| line.contains(needle.as_str())))
            .collect();

        assert!(
            offenders.is_empty(),
            "hardening.rs reads the environment: {offenders:?}. An operator-settable switch \
             that turns off PR_SET_DUMPABLE or PT_DENY_ATTACH exposes the CA private key and \
             every resolved secret to any process at this UID, and Box has no such switch \
             (docs/design/decisions.md#the-trusted-processs-memory-is-a-defended-asset). \
             Fix the code, not this test."
        );
    }

    /// `RLIMIT_CORE` reaches `{0, 0}`, and the resulting limit really cannot be raised again.
    #[test]
    #[cfg(unix)]
    fn the_core_limit_is_zero_and_cannot_be_raised_again() {
        // SAFETY: the child applies the irreversible change and `_exit`s; it never returns into
        // test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            let applied = deny_core_dumps().is_ok();

            let mut observed = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            // SAFETY: `getrlimit` into an `rlimit` we own.
            let read_back = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut observed) } == 0;
            let is_zero = observed.rlim_cur == 0 && observed.rlim_max == 0;

            // Try to undo it. With `rlim_max` zeroed this must fail.
            let raised = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };
            // SAFETY: `setrlimit` with a valid resource and an `rlimit` we own.
            let re_raised = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raised) } == 0;

            // SAFETY: `_exit` in a forked child, no unwinding, no allocator work.
            unsafe {
                libc::_exit(match (applied, read_back, is_zero, re_raised) {
                    (true, true, true, false) => 0,
                    (false, ..) => 2,
                    (_, false, ..) => 3,
                    (_, _, false, _) => 4,
                    (_, _, _, true) => 5,
                })
            };
        }

        let mut status = 0;
        // SAFETY: `waitpid` on our own child, writing into an `int` we own.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "core dumps are not durably disabled (2=setrlimit failed, 3=getrlimit failed, \
             4=the limit was not {{0,0}}, 5=the limit was raised again, so rlim_max was not zeroed)"
        );
    }

    /// `PR_SET_DUMPABLE=0` takes effect, and the read-back is what proves it.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_process_becomes_non_dumpable() {
        // SAFETY: the child applies the irreversible change and `_exit`s.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            let applied = deny_memory_reads().is_ok();
            // SAFETY: `PR_GET_DUMPABLE` returns the flag; no pointers.
            let observed = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
            // SAFETY: `_exit` in a forked child.
            unsafe {
                libc::_exit(match (applied, observed) {
                    (true, 0) => 0,
                    (false, _) => 2,
                    (_, _) => 3,
                })
            };
        }

        let mut status = 0;
        // SAFETY: `waitpid` on our own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "the process stayed dumpable (2=prctl reported failure, \
             3=prctl succeeded but PR_GET_DUMPABLE did not read back 0)"
        );
    }

    /// A non-dumpable process refuses `process_vm_readv` from a sibling at the same UID.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_sibling_cannot_read_a_non_dumpable_process() {
        assert!(
            reads_own_child(false),
            "the control arm must succeed: a dumpable child's memory is readable at the same UID, \
             and if this fails the probe is measuring something other than dumpability"
        );
        assert!(
            !reads_own_child(true),
            "a non-dumpable child's memory must not be readable"
        );
    }

    /// Fork a child holding a known value, optionally harden it, and try to read that value back
    /// with `process_vm_readv`. Returns whether the read succeeded.
    #[cfg(target_os = "linux")]
    fn reads_own_child(harden: bool) -> bool {
        use std::io::Read as _;
        use std::os::unix::io::FromRawFd as _;

        const CANARY: &[u8; 16] = b"CANARY-0xDEADBEE";

        let mut fds = [0; 2];
        // SAFETY: `pipe` writing two descriptors into an array we own.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
        let (read_fd, write_fd) = (fds[0], fds[1]);

        // SAFETY: the child hardens itself and `_exit`s; it never returns into harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            // SAFETY: closing a descriptor this process owns.
            unsafe { libc::close(read_fd) };
            let canary = *CANARY;
            if harden {
                let _ = deny_memory_reads();
            }
            // Tell the parent where the canary lives, then idle until killed.
            let address = canary.as_ptr() as usize;
            // SAFETY: writing a `usize` we own to a descriptor we own.
            unsafe {
                libc::write(
                    write_fd,
                    (&raw const address).cast::<libc::c_void>(),
                    std::mem::size_of::<usize>(),
                );
                libc::close(write_fd);
            }
            loop {
                // SAFETY: `pause` takes no arguments and returns on a signal.
                unsafe { libc::pause() };
            }
        }

        // SAFETY: closing a descriptor this process owns.
        unsafe { libc::close(write_fd) };
        let mut pipe = unsafe { std::fs::File::from_raw_fd(read_fd) };
        let mut address_bytes = [0u8; std::mem::size_of::<usize>()];
        let got_address = pipe.read_exact(&mut address_bytes).is_ok();
        let address = usize::from_ne_bytes(address_bytes);

        let mut out = [0u8; CANARY.len()];
        let local = libc::iovec {
            iov_base: out.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: out.len(),
        };
        let remote = libc::iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: out.len(),
        };
        // SAFETY: `process_vm_readv` against our own child, with iovecs we own. A failure is the
        // outcome under test, not an error.
        let read = unsafe { libc::process_vm_readv(child, &local, 1, &remote, 1, 0) };

        // SAFETY: killing and reaping our own child.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(child, &mut status, 0);
        }

        got_address && read == out.len() as isize && &out == CANARY
    }
}
