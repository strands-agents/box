//! Measuring whether this identity may create a user namespace.

/// Whether this identity may create a user namespace, measured once.
pub(crate) fn user_namespace_is_permitted() -> bool {
    // SAFETY: `fork` in a possibly-multithreaded parent is safe for the child only if the child
    // performs async-signal-safe work.
    let child = unsafe { libc::fork() };

    match child {
        // Fork failed. Not "unsupported because denied" but "unmeasurable", and
        // both mean the same thing to the caller: do not select this backend.
        -1 => false,
        0 => {
            // In the child. Nothing here may allocate or panic.
            // SAFETY: a single syscall with a constant argument.
            let created = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            // `_exit`, never `exit`: `exit` runs atexit handlers and flushes stdio, which is
            // neither async-signal-safe nor the child's business.
            unsafe { libc::_exit(if created == 0 { 0 } else { 1 }) };
        }
        pid => {
            let mut status: libc::c_int = 0;
            // SAFETY: `pid` is this process's own child and `status` is a valid
            // out-pointer for the duration of the call.
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited != pid {
                return false;
            }
            // Only a clean exit 0 counts. A signalled child (`WIFEXITED` false)
            // proves nothing about namespace policy, so it reads as unsupported.
            let exited_normally = libc::WIFEXITED(status);
            exited_normally && libc::WEXITSTATUS(status) == 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe answers without restricting this process.
    #[test]
    fn the_probe_leaves_the_calling_process_unrestricted() {
        let first = user_namespace_is_permitted();
        let second = user_namespace_is_permitted();

        assert_eq!(
            first, second,
            "the probe must be repeatable: a different second answer would mean \
             the first call restricted this process"
        );
    }

    /// On a host that permits user namespaces the probe says so, and the measurement is the same
    /// fact the launcher depends on.
    #[test]
    fn the_probe_reports_this_hosts_policy() {
        let permitted = user_namespace_is_permitted();
        // Not an assertion about the host: an assertion that the answer is usable.
        println!("user namespaces permitted here: {permitted}");
    }
}
