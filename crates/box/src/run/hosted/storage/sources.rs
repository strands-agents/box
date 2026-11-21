//! The Box-lifetime source helper process and its private recipient channel.

use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use super::Cancellation;
use crate::error::{BoxError, SuperviseError};
use crate::run::installation::TrustedInstallation;

pub(super) struct SourceHelper {
    control: UnixStream,
    child: Option<Child>,
    cancel: Arc<Cancellation>,
}

impl SourceHelper {
    pub(super) fn start(
        roots: &[PathBuf],
        trusted: &TrustedInstallation,
    ) -> Result<Self, BoxError> {
        let (path, image) = trusted
            .storage_compiler()
            .ok_or_else(|| failure("source helper executable was not pinned at setup"))?;
        let (control, child_control) = UnixStream::pair().map_err(io_error)?;
        control
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(io_error)?;
        control
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(io_error)?;
        let mut command = Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()));
        command
            .arg0(path)
            .args([
                "--source-control-fd",
                &child_control.as_raw_fd().to_string(),
            ])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let inherited = child_control.as_raw_fd();
        // SAFETY: the post-fork closure only adjusts its private inherited socket.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(inherited, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        trusted.verify()?;
        let child = command.spawn().map_err(io_error)?;
        drop(child_control);
        let cancel = Arc::new(Cancellation::default());
        let mut helper = Self {
            control,
            child: Some(child),
            cancel,
        };
        helper.cancel.track(&helper.control).map_err(io_error)?;
        if let Err(error) = containment::storage::sources::initialize(&helper.control, roots) {
            helper.close();
            return Err(failure(error.to_string()));
        }
        helper.control.set_read_timeout(None).map_err(io_error)?;
        Ok(helper)
    }

    pub(super) fn subscription(&self, roots: &[PathBuf]) -> Result<UnixStream, BoxError> {
        containment::storage::sources::subscribe(&self.control, roots)
            .map_err(|error| failure(error.to_string()))
    }

    pub(super) fn monitor(&self) -> Result<(UnixStream, Arc<Cancellation>), BoxError> {
        Ok((
            self.control.try_clone().map_err(io_error)?,
            Arc::clone(&self.cancel),
        ))
    }

    pub(super) fn close(&mut self) {
        self.cancel.cancel();
    }

    pub(super) fn finish(&mut self) -> Result<(), BoxError> {
        self.close();
        if let Some(mut child) = self.child.take() {
            // The helper's control EOF closes its source workers before normal exit.
            let status = child.wait().map_err(io_error)?;
            if !status.success() {
                return Err(failure(format!("source helper exited with {status}")));
            }
        }
        Ok(())
    }
}

impl Drop for SourceHelper {
    fn drop(&mut self) {
        self.close();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn io_error(source: std::io::Error) -> BoxError {
    SuperviseError::Spawn { source }.into()
}
fn failure(reason: impl Into<String>) -> BoxError {
    SuperviseError::Control {
        reason: reason.into(),
    }
    .into()
}
