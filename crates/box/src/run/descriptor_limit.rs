//! The box's own open-file limit, raised for the ingress relay and put back in every child it spawns.

use std::sync::atomic::{AtomicU64, Ordering};

/// The soft limit before [`raise`], or `0` when the limit was not raised.
static INHERITED_SOFT_LIMIT: AtomicU64 = AtomicU64::new(0);

/// Raise this process's soft `RLIMIT_NOFILE` as far as the hard limit allows, and return the soft
/// limit now in force.
pub(crate) fn raise() -> Option<u64> {
    // SAFETY: `getrlimit` and `setrlimit` read and write one local `rlimit`.
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return None;
        }
        // macOS refuses a soft limit above `OPEN_MAX`, even when the hard limit is unlimited.
        #[cfg(target_os = "macos")]
        let ceiling = limit.rlim_max.min(10_240);
        #[cfg(not(target_os = "macos"))]
        let ceiling = limit.rlim_max;
        if limit.rlim_cur < ceiling {
            let raised = libc::rlimit {
                rlim_cur: ceiling,
                rlim_max: limit.rlim_max,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &raised) == 0 {
                let _ = INHERITED_SOFT_LIMIT.compare_exchange(
                    0,
                    limit.rlim_cur as u64,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                limit.rlim_cur = ceiling;
            }
        }
        Some(limit.rlim_cur as u64)
    }
}

/// Start `command` with the soft limit this process had before [`raise`].
pub(crate) fn restore_in_child(command: &mut tokio::process::Command) {
    let inherited = INHERITED_SOFT_LIMIT.load(Ordering::SeqCst);
    if inherited == 0 {
        return;
    }
    // SAFETY: the hook calls only `getrlimit` and `setrlimit` on a local before `exec`.
    unsafe {
        command.pre_exec(move || {
            let mut limit: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            limit.rlim_cur = inherited as libc::rlim_t;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soft_limit() -> u64 {
        // SAFETY: `getrlimit` writes one local `rlimit`.
        unsafe {
            let mut limit: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            limit.rlim_cur as u64
        }
    }

    /// Run in a child process, so raising the limit leaves the test binary's own limit alone.
    #[tokio::test]
    #[ignore = "run by a_child_starts_with_the_limit_the_box_had_before_it_raised_it"]
    async fn raised_limit_child() {
        // SAFETY: `setrlimit` reads one local `rlimit`; this process is the test's child.
        unsafe {
            let mut limit: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            limit.rlim_cur = 256.min(limit.rlim_max);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
        }
        let before = soft_limit();
        let raised = raise().expect("the limit is read");
        if raised == before {
            println!("skipping: the hard limit is {before}, so nothing was raised");
            return;
        }
        assert_eq!(soft_limit(), raised, "the box holds the raised limit");

        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "ulimit -n"]);
        restore_in_child(&mut command);
        let output = command.output().await.expect("the child runs");
        let child = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(
            child,
            before.to_string(),
            "the child starts with the limit the box had before it raised it"
        );
    }

    #[test]
    fn a_child_starts_with_the_limit_the_box_had_before_it_raised_it() {
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "run::descriptor_limit::tests::raised_limit_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("the child runs");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
