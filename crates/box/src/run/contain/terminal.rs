//! The controlling terminal, handed to the workload and handed back.
//!
//! **Split out of `supervise` because it shares nothing with spawning but a pid.** `supervise`
//! starts a child and reaps it; this is `tcsetpgrp` with the `SIGTTOU` dance around it, and it was
//! the least-tested code in that file.
//!
//! It takes the leader pid rather than a `ProcessGroup`, so this module knows nothing about how the
//! caller groups its children — which is also what keeps the two modules from depending on each
//! other.
//!
//! Restoring is a `Drop`, so a panic between claim and exit still hands the terminal back.

use crate::error::{BoxError, SuperviseError};

pub(crate) struct ForegroundTerminal {
    #[cfg(unix)]
    descriptor: Option<libc::c_int>,
    #[cfg(unix)]
    original_process_group: libc::pid_t,
}

impl ForegroundTerminal {
    pub(crate) fn claim(leader: libc::pid_t) -> Result<Self, BoxError> {
        #[cfg(unix)]
        {
            let descriptor = libc::STDIN_FILENO;
            // SAFETY: isatty only inspects the open standard-input descriptor.
            if unsafe { libc::isatty(descriptor) } != 1 {
                return Ok(Self {
                    descriptor: None,
                    original_process_group: 0,
                });
            }

            // SAFETY: these calls only inspect process and terminal state.
            let caller_process_group = unsafe { libc::getpgrp() };
            let foreground_process_group = unsafe { libc::tcgetpgrp(descriptor) };
            if foreground_process_group == -1 {
                return Err(SuperviseError::Control {
                    reason: std::io::Error::last_os_error().to_string(),
                }
                .into());
            }
            if foreground_process_group != caller_process_group {
                return Ok(Self {
                    descriptor: None,
                    original_process_group: 0,
                });
            }

            let mut terminal = Self {
                descriptor: Some(descriptor),
                original_process_group: foreground_process_group,
            };
            if let Err(error) = set_foreground_process_group(descriptor, leader) {
                terminal.descriptor = None;
                return Err(SuperviseError::Control {
                    reason: error.to_string(),
                }
                .into());
            }
            // SIGCONT to the child-led group, because handing the terminal over can stop a child
            // that was already reading it. A negative pid addresses the group.
            let continued = if unsafe { libc::kill(-leader, libc::SIGCONT) } == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            };
            if let Err(error) = continued
                && error.raw_os_error() != Some(libc::ESRCH)
            {
                let _ = terminal.restore();
                return Err(SuperviseError::Control {
                    reason: error.to_string(),
                }
                .into());
            }
            Ok(terminal)
        }

        #[cfg(not(unix))]
        {
            let _ = process_group;
            Ok(Self {})
        }
    }

    pub(crate) fn restore(&mut self) -> Result<(), BoxError> {
        #[cfg(unix)]
        {
            let Some(descriptor) = self.descriptor else {
                return Ok(());
            };
            set_foreground_process_group(descriptor, self.original_process_group).map_err(
                |error| SuperviseError::Control {
                    reason: error.to_string(),
                },
            )?;
            self.descriptor = None;
        }
        Ok(())
    }
}

impl Drop for ForegroundTerminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(unix)]
fn set_foreground_process_group(
    descriptor: libc::c_int,
    process_group: libc::pid_t,
) -> std::io::Result<()> {
    let mut blocked = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: both signal sets are initialized before use. SIGTTOU is
    // temporarily blocked while a background parent reclaims the terminal.
    unsafe {
        if libc::sigemptyset(blocked.as_mut_ptr()) == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let mut blocked = blocked.assume_init();
        if libc::sigaddset(&mut blocked, libc::SIGTTOU) == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let mask_result = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, previous.as_mut_ptr());
        if mask_result != 0 {
            return Err(std::io::Error::from_raw_os_error(mask_result));
        }
        let previous = previous.assume_init();
        let terminal_result = libc::tcsetpgrp(descriptor, process_group);
        let terminal_error = (terminal_result == -1).then(std::io::Error::last_os_error);
        let restore_result =
            libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        if let Some(error) = terminal_error {
            return Err(error);
        }
        if restore_result != 0 {
            return Err(std::io::Error::from_raw_os_error(restore_result));
        }
    }
    Ok(())
}
