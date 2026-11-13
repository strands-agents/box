/// Whether this host can run the Linux namespace launcher. Always `true` off Linux.
#[cfg(not(target_os = "linux"))]
pub(crate) fn namespace_launcher_is_usable() -> bool {
    true
}

/// Whether this host can run the Linux namespace launcher.
///
/// A build host can permit user namespaces and still refuse a nested procfs, which failed every
/// box-spawning test on such a host. A test that cannot construct a box measures nothing, so it
/// **skips loudly** rather than failing. It probes the exact operation that fails, in a forked
/// reaper the way the real launcher does.
#[cfg(target_os = "linux")]
pub(crate) fn namespace_launcher_is_usable() -> bool {
    // The box selects the namespace backend only on ARM64 and x86-64.
    if !cfg!(any(target_arch = "aarch64", target_arch = "x86_64")) {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    if std::env::var_os("EXPERIMENTAL_X86_SUPPORT").as_deref() != Some(std::ffi::OsStr::new("TRUE"))
    {
        eprintln!("skipping: Linux x86-64 Box tests require EXPERIMENTAL_X86_SUPPORT=TRUE");
        return false;
    }
    use std::sync::OnceLock;
    static USABLE: OnceLock<bool> = OnceLock::new();
    *USABLE.get_or_init(|| {
        // SAFETY: the child only makes syscalls and `_exit`s.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return true; // cannot probe; let the test run and report its own failure
        }
        if child == 0 {
            // SAFETY: syscall-only child.
            unsafe {
                let namespaces = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
                if libc::unshare(namespaces) != 0 {
                    libc::_exit(10);
                }
                let inner = libc::fork();
                if inner < 0 {
                    libc::_exit(12);
                }
                if inner == 0 {
                    let fstype = c"proc".as_ptr();
                    let target = c"/proc".as_ptr();
                    if libc::mount(fstype, target, fstype, 0, std::ptr::null()) != 0 {
                        libc::_exit(11);
                    }
                    libc::_exit(0);
                }
                let mut inner_status = 0;
                libc::waitpid(inner, &mut inner_status, 0);
                let ok = libc::WIFEXITED(inner_status) && libc::WEXITSTATUS(inner_status) == 0;
                libc::_exit(if ok { 0 } else { 11 });
            }
        }
        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        let usable = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        if !usable {
            println!(
                "skipping: this host cannot run the namespace launcher (unshare or a nested \
                 procfs mount is refused); a box cannot be constructed here"
            );
        }
        usable
    })
}
