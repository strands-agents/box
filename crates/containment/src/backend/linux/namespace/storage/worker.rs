//! Independent provider acquisition and private captured-source caches.

use super::protocol::SourceIdentity;
use super::*;
use serde::{Deserialize, Serialize};
#[cfg(not(test))]
use std::io::{Read as _, Write as _};

pub(super) struct Child {
    pid: libc::pid_t,
}

impl Child {
    pub(super) fn new(pid: libc::pid_t) -> Self {
        Self { pid }
    }
    pub(super) fn wait(&mut self) -> Result<(), ContainmentError> {
        if self.pid <= 0 {
            return Ok(());
        }
        let mut status = 0;
        loop {
            // SAFETY: this owner waits only for its unreaped child.
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            self.pid = 0;
            if result < 0 {
                return Err(io_failure(std::io::Error::last_os_error()));
            }
            return if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                Ok(())
            } else {
                Err(failure(format!(
                    "storage worker exited with status {status}"
                )))
            };
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.pid > 0 {
            // SAFETY: this is the same unreaped owned child, so PID reuse is impossible.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
            let _ = self.wait();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum CaptureEvent {
    Captured {
        identity: SourceIdentity,
        filesystem: String,
    },
    Failed {
        message: String,
    },
}

pub(super) struct Worker {
    _child: Child,
    pub(super) control: UnixStream,
    pub(super) source: Option<(SourceIdentity, String)>,
}

impl Worker {
    pub(super) fn spawn(root: &Path) -> Result<Self, ContainmentError> {
        let (control, worker_control) = UnixStream::pair().map_err(io_failure)?;
        // SAFETY: the persistent receiver is single-threaded and has not run workload code.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io_failure(std::io::Error::last_os_error()));
        }
        if pid == 0 {
            drop(control);
            let result: Result<(), ContainmentError> = (|| {
                authority::close_inherited_descriptors(&[0, 1, 2, worker_control.as_raw_fd()])?;
                if !reaper::arm_parent_death(&worker_control) {
                    return Err(failure("capture worker parent-death handshake failed"));
                }
                let parent = open_path(
                    root.parent()
                        .ok_or_else(|| failure("storage root has no parent"))?,
                )?;
                let observed = observe::wait(root, &parent, &worker_control, false)?;
                let source_identity = identity(&observed.source)?;
                let captured = clone_private_tree(&observed.source)?;
                production::install_sources(&[(root, captured.as_raw_fd())])?;
                let cached = open_path(root)?;
                if identity(&cached)?.object() != source_identity.object() {
                    return Err(failure("source cache does not retain its captured object"));
                }
                let event = CaptureEvent::Captured {
                    identity: SourceIdentity {
                        device: source_identity.device,
                        inode: source_identity.inode,
                        mount_id: source_identity.mount,
                    },
                    filesystem: observed.filesystem,
                };
                transport::send_text(
                    &worker_control,
                    &serde_json::to_string(&event).map_err(|error| failure(error.to_string()))?,
                )?;
                loop {
                    let mut command = [0];
                    (&worker_control)
                        .read_exact(&mut command)
                        .map_err(io_failure)?;
                    if command != *b"C" {
                        return Err(failure("invalid captured-source cache command"));
                    }
                    let cloned = clone_private_tree(&cached)?;
                    transport::send_fd(&worker_control, &cloned)?;
                }
            })();
            if let Err(error) = result {
                let event = CaptureEvent::Failed {
                    message: error.to_string(),
                };
                if let Ok(json) = serde_json::to_string(&event) {
                    let _ = transport::send_text(&worker_control, &json);
                }
            }
            // SAFETY: the capture worker never returns into receiver or workload code.
            unsafe { libc::_exit(125) };
        }
        drop(worker_control);
        let worker = Self {
            _child: Child::new(pid),
            control,
            source: None,
        };
        if !reaper::confirm_parent_death(&worker.control) {
            return Err(failure(
                "capture worker did not acknowledge parent-death protection",
            ));
        }
        Ok(worker)
    }

    pub(super) fn capture(&mut self) -> Result<(), ContainmentError> {
        let event: CaptureEvent =
            serde_json::from_str(&transport::receive_text(&self.control, CONTROL_LIMIT)?)
                .map_err(|error| failure(format!("invalid capture event: {error}")))?;
        match event {
            CaptureEvent::Captured {
                identity,
                filesystem,
            } => {
                if self.source.is_some() {
                    return Err(failure("source root was captured twice"));
                }
                self.source = Some((identity, filesystem));
                Ok(())
            }
            CaptureEvent::Failed { message } => Err(failure(message)),
        }
    }

    pub(super) fn request_clone(&self) -> Result<(), ContainmentError> {
        (&self.control).write_all(b"C").map_err(io_failure)
    }
}
