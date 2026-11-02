//! The namespace's PID 1: descendant lifetime and signal forwarding.

/// The exit status a caller should use when the workload was signalled.
const SIGNAL_EXIT_BASE: i32 = 128;

/// Arm termination with the launcher before acknowledging readiness.
pub(super) fn arm_parent_death(control: &std::os::unix::net::UnixStream) -> bool {
    // SAFETY: prctl takes scalar arguments for the parent-death signal.
    let armed = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == 0 };
    armed && transfer_byte(control, true) && transfer_byte(control, false)
}

/// Confirm that the reaper armed termination while this launcher is alive.
pub(super) fn confirm_parent_death(control: &std::os::unix::net::UnixStream) -> bool {
    transfer_byte(control, false) && transfer_byte(control, true)
}

fn transfer_byte(control: &std::os::unix::net::UnixStream, sending: bool) -> bool {
    use std::os::fd::AsRawFd;
    let mut byte = 1_u8;
    loop {
        // SAFETY: the socket and one-byte buffer remain valid for each syscall.
        let result = unsafe {
            if sending {
                libc::send(
                    control.as_raw_fd(),
                    (&byte as *const u8).cast(),
                    1,
                    libc::MSG_NOSIGNAL,
                )
            } else {
                libc::read(control.as_raw_fd(), (&mut byte as *mut u8).cast(), 1)
            }
        };
        if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return result == 1 && byte == 1;
    }
}

/// Run as the namespace's PID 1: forward signals, reap orphans, and return the
/// workload's exit status.
pub(crate) fn supervise(workload: libc::pid_t) -> i32 {
    // Store the pid BEFORE installing the handlers.
    WORKLOAD_PID.store(workload, std::sync::atomic::Ordering::Relaxed);
    install_forwarding_handlers();

    loop {
        let mut status: libc::c_int = 0;
        // Wait for *any* child, not just the workload: orphaned grandchildren reparent here and
        // must be reaped rather than accumulated.
        let reaped = unsafe { libc::waitpid(-1, &mut status, 0) };

        if reaped == -1 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                // A signal interrupted the wait. The handler has already forwarded
                // it; resume waiting rather than treating this as an exit.
                Some(libc::EINTR) => continue,
                // No children at all.
                Some(libc::ECHILD) => return 0,
                _ => return 125,
            }
        }

        if reaped != workload {
            // An orphan. Reaped, and deliberately not reported: its status is not
            // the run's result.
            continue;
        }

        // The workload itself exited.
        if libc::WIFEXITED(status) {
            return libc::WEXITSTATUS(status);
        }
        if libc::WIFSIGNALED(status) {
            return SIGNAL_EXIT_BASE + libc::WTERMSIG(status);
        }
        return 125;
    }
}

/// The workload's PID, for the signal handlers.
static WORKLOAD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Forward `SIGTERM` and `SIGINT` to the workload.
extern "C" fn forward(signal: libc::c_int) {
    let target = WORKLOAD_PID.load(std::sync::atomic::Ordering::Relaxed);
    if target > 0 {
        // SAFETY: a single syscall with scalar arguments; async-signal-safe.
        unsafe { libc::kill(target, signal) };
    }
}

/// Install the forwarding handlers.
fn install_forwarding_handlers() {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: `sigaction` with a handler that only calls `kill`. The struct is
        // zeroed first so every unnamed field has a defined value.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = forward as *const () as libc::sighandler_t;
            // `SA_RESTART` is deliberately absent: `waitpid` should return `EINTR`
            // so the loop notices the signal, rather than silently restarting.
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termination_signals_reach_the_workload_and_determine_its_status() {
        super::super::failure_tests::in_fresh_process(|| {
            for signal in [libc::SIGTERM, libc::SIGINT] {
                let mut child = std::process::Command::new("/bin/sleep")
                    .arg("3")
                    .spawn()
                    .unwrap();
                let pid = child.id() as libc::pid_t;
                WORKLOAD_PID.store(pid, std::sync::atomic::Ordering::Relaxed);
                install_forwarding_handlers();
                // SAFETY: raise invokes the installed handler in this isolated test process.
                assert_eq!(unsafe { libc::raise(signal) }, 0);
                assert_eq!(supervise(pid), SIGNAL_EXIT_BASE + signal);
                assert_eq!(child.wait().unwrap_err().raw_os_error(), Some(libc::ECHILD));
            }
            WORKLOAD_PID.store(0, std::sync::atomic::Ordering::Relaxed);
            // With no workload, forwarding must not signal the process group.
            forward(libc::SIGTERM);
        });
    }

    #[test]
    fn an_invalid_lifetime_acknowledgment_is_refused() {
        use std::io::Write as _;
        let (parent, mut child) = std::os::unix::net::UnixStream::pair().unwrap();
        child.write_all(&[0]).unwrap();
        assert!(!confirm_parent_death(&parent));
    }

    #[test]
    fn a_closed_lifetime_channel_refuses_confirmation() {
        let (parent, child) = std::os::unix::net::UnixStream::pair().expect("lifetime channel");
        drop(child);
        assert!(!confirm_parent_death(&parent));
    }

    #[test]
    fn a_reaper_cannot_start_after_its_lifetime_channel_closes() {
        let (parent, child) = std::os::unix::net::UnixStream::pair().expect("lifetime channel");
        drop(parent);
        // SAFETY: the child uses syscalls and exits without returning into the test harness.
        let pid = unsafe { libc::fork() };
        assert_ne!(pid, -1, "fork");
        if pid == 0 {
            let accepted = arm_parent_death(&child);
            // SAFETY: exit without running the parent's destructors.
            unsafe { libc::_exit(i32::from(accepted)) };
        }
        let mut status = 0;
        // SAFETY: wait for this test's child and store its status.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "the closed channel must refuse"
        );
    }

    /// Runs `supervise` in a real PID namespace and returns its exit status.
    fn in_pid_namespace(body: impl FnOnce() -> i32) -> Option<i32> {
        if !super::super::probe::user_namespace_is_permitted() {
            return None;
        }

        // SAFETY: the child enters new namespaces and exits; it never returns into
        // test-harness code.
        let outer = unsafe { libc::fork() };
        assert_ne!(outer, -1, "fork failed");

        if outer == 0 {
            // Read the ids BEFORE the unshare: inside a fresh user namespace with no map yet,
            // `getuid()` returns the overflow uid (65534) and mapping that is refused with EPERM.
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            // SAFETY: irreversible for this child only.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
                // SAFETY: terminating the child.
                unsafe { libc::_exit(10) };
            }
            let _ = std::fs::write("/proc/self/setgroups", "deny");
            let _ = std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"));
            let _ = std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"));
            // CLONE_NEWPID affects *children*, so a fork is required before anything is PID 1.
            if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
                // SAFETY: terminating the child.
                unsafe { libc::_exit(11) };
            }

            // SAFETY: this grandchild is PID 1 of the new namespace.
            let init = unsafe { libc::fork() };
            if init == -1 {
                // SAFETY: terminating the child.
                unsafe { libc::_exit(12) };
            }
            if init == 0 {
                let code = body();
                // SAFETY: terminating namespace PID 1, which kills the namespace.
                unsafe { libc::_exit(code) };
            }

            let mut status = 0;
            // SAFETY: waiting on this process's own child.
            unsafe { libc::waitpid(init, &mut status, 0) };
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                125
            };
            // SAFETY: propagating the namespace init's status outward.
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(outer, &mut status, 0) };
        assert!(
            libc::WIFEXITED(status),
            "the outer child must exit normally"
        );
        Some(libc::WEXITSTATUS(status))
    }

    /// The workload's exit status is the run's exit status.
    #[test]
    fn the_workloads_exit_status_is_propagated() {
        let Some(observed) = in_pid_namespace(|| {
            // SAFETY: forking inside the namespace; the child exits immediately.
            let workload = unsafe { libc::fork() };
            if workload == 0 {
                // SAFETY: a distinctive status to propagate.
                unsafe { libc::_exit(42) };
            }
            supervise(workload)
        }) else {
            println!("skipping: this host forbids user namespaces");
            return;
        };

        assert_eq!(
            observed, 42,
            "the reaper must propagate the workload's status, or the box would \
             report the wrong exit code for every run"
        );
    }

    /// An orphaned grandchild is reaped rather than left a zombie, and its status
    /// is not mistaken for the workload's.
    #[test]
    fn an_orphaned_grandchild_is_reaped_and_does_not_change_the_result() {
        let Some(observed) = in_pid_namespace(|| {
            // SAFETY: forking inside the namespace.
            let workload = unsafe { libc::fork() };
            if workload == 0 {
                // SAFETY: the workload double-forks, orphaning the grandchild.
                let orphan = unsafe { libc::fork() };
                if orphan == 0 {
                    // Outlive the workload briefly, then exit with a status that would be wrong to
                    // report as the run's.
                    unsafe {
                        libc::usleep(50_000);
                        libc::_exit(99);
                    }
                }
                // SAFETY: the workload exits first, orphaning its child.
                unsafe { libc::_exit(7) };
            }
            supervise(workload)
        }) else {
            println!("skipping: this host forbids user namespaces");
            return;
        };

        assert_eq!(
            observed, 7,
            "the orphan's status (99) must not become the run's result; the reaper \
             reports the workload's status and reaps everything else"
        );
    }

    #[test]
    fn an_adopted_child_is_reaped_before_the_workload_exits() {
        let Some(observed) = in_pid_namespace(|| {
            // The workload cannot exit successfully until PID 1 reaps the adopted child.
            // Everything after these forks uses scalar syscalls and _exit.
            let workload = unsafe { libc::fork() };
            if workload < 0 {
                return 90;
            }
            if workload == 0 {
                unsafe {
                    let mut channel = [0; 2];
                    if libc::pipe(channel.as_mut_ptr()) != 0 {
                        libc::_exit(91);
                    }
                    let intermediate = libc::fork();
                    if intermediate < 0 {
                        libc::_exit(92);
                    }
                    if intermediate == 0 {
                        let adopted = libc::fork();
                        if adopted < 0 {
                            libc::_exit(93);
                        }
                        if adopted == 0 {
                            libc::_exit(99);
                        }
                        let sent = libc::write(
                            channel[1],
                            (&adopted as *const libc::pid_t).cast(),
                            std::mem::size_of::<libc::pid_t>(),
                        );
                        libc::_exit(if sent == std::mem::size_of::<libc::pid_t>() as isize {
                            0
                        } else {
                            94
                        });
                    }
                    libc::close(channel[1]);
                    let mut adopted: libc::pid_t = 0;
                    let received = libc::read(
                        channel[0],
                        (&mut adopted as *mut libc::pid_t).cast(),
                        std::mem::size_of::<libc::pid_t>(),
                    );
                    libc::close(channel[0]);
                    if received != std::mem::size_of::<libc::pid_t>() as isize || adopted <= 0 {
                        libc::_exit(95);
                    }
                    let mut status = 0;
                    if libc::waitpid(intermediate, &mut status, 0) != intermediate {
                        libc::_exit(96);
                    }
                    for _ in 0..300 {
                        if libc::kill(adopted, 0) == -1 && *libc::__errno_location() == libc::ESRCH
                        {
                            libc::_exit(7);
                        }
                        libc::usleep(10_000);
                    }
                    libc::_exit(97);
                }
            }
            supervise(workload)
        }) else {
            println!("skipping: this host forbids user namespaces");
            return;
        };
        assert_eq!(
            observed, 7,
            "PID 1 must reap the adopted child while the workload remains alive"
        );
    }

    /// A descendant that outlives the workload does not outlive the namespace.
    #[test]
    fn a_lingering_descendant_does_not_hold_the_run_open() {
        let started = std::time::Instant::now();

        let Some(observed) = in_pid_namespace(|| {
            // SAFETY: forking inside the namespace.
            let workload = unsafe { libc::fork() };
            if workload == 0 {
                // SAFETY: double-fork a long-lived sleeper.
                let sleeper = unsafe { libc::fork() };
                if sleeper == 0 {
                    // SAFETY: sleeping far longer than the test tolerates.
                    unsafe {
                        libc::sleep(30);
                        libc::_exit(0);
                    }
                }
                // SAFETY: exit immediately, orphaning the sleeper.
                unsafe { libc::_exit(0) };
            }
            supervise(workload)
        }) else {
            println!("skipping: this host forbids user namespaces");
            return;
        };

        let elapsed = started.elapsed();
        assert_eq!(observed, 0, "the workload exited cleanly");
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "the run took {elapsed:?}: teardown waited for a lingering descendant \
             instead of terminating it with the namespace"
        );
    }
}
