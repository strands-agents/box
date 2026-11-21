//! Protected storage admission in a trusted receiver outside the workload mount namespace.

use std::ffi::CString;
#[cfg(test)]
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
#[cfg(any(test, feature = "test-support"))]
use std::time::Duration;

use super::{apply_failure, authority, reaper, view::MountView};
use crate::{ContainmentConfig, ContainmentError, Scope};

pub(super) mod mountinfo;
mod observe;
pub(crate) mod production;
#[cfg(test)]
mod production_tests;
pub(crate) mod protocol;
mod receiver;
mod target;
#[cfg(test)]
mod tests;
mod transport;
mod worker;

const CONTROL_LIMIT: usize = 1024 * 1024;

/// Explicit private test handoff. No public configuration or environment variable selects it.
#[cfg(any(test, feature = "test-support"))]
pub(super) struct Request {
    pub(super) root: PathBuf,
    pub(super) control: UnixStream,
    pub(super) capture: CaptureMode,
}

/// Select the explicit control fixture or automatic provider observation.
#[cfg(any(test, feature = "test-support"))]
pub(super) enum CaptureMode {
    #[cfg(test)]
    Manual,
    Automatic {
        observe_pending: bool,
        owner_handoff: bool,
    },
}

/// Launcher-owned lifetime and target registration. Only its original process owns the child.
pub(super) struct Setup {
    targets: Vec<(PathBuf, Scope)>,
    registration: Option<UnixStream>,
    lifetime: Option<UnixStream>,
    child: libc::pid_t,
    export_view: bool,
}

impl Setup {
    pub(super) fn close_registration(&mut self) {
        self.registration.take();
    }

    /// The PID-namespace child must not terminate or wait for its parent's other child.
    pub(super) fn disown_child(&mut self) {
        self.child = 0;
        self.lifetime.take();
    }

    /// Send the completed, sealed view to the helper before workload execution.
    pub(super) fn register_target(&mut self) -> Result<(), ContainmentError> {
        let namespace = open_namespace()?;
        let control = self
            .registration
            .as_ref()
            .ok_or_else(|| failure("target already registered"))?;
        transport::send_fd(control, &namespace)?;
        if self.export_view {
            // SAFETY: this launcher opens its already sealed mount-view root.
            let root = own(unsafe {
                libc::open(
                    c"/".as_ptr(),
                    libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
                .into()
            })?;
            transport::send_fd(control, &root)?;
        }
        for (path, scope) in &self.targets {
            target::PinnedTarget::capture(path, *scope)?.send(control)?;
        }
        self.close_registration();
        Ok(())
    }

    pub(super) fn lifetime_fd(&self) -> Option<std::os::fd::RawFd> {
        self.lifetime.as_ref().map(|socket| socket.as_raw_fd())
    }

    pub(super) fn complete(&mut self) {
        if let Some(lifetime) = self.lifetime.take() {
            use std::io::Write as _;
            if (&lifetime).write_all(b"D").is_ok() {
                while self.child > 0 {
                    // SAFETY: this original launcher owns the receiver child.
                    let waited = unsafe { libc::waitpid(self.child, std::ptr::null_mut(), 0) };
                    if waited >= 0
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                    {
                        self.child = 0;
                    }
                }
            }
        }
        self.finish();
    }

    pub(super) fn finish(&mut self) {
        self.close_registration();
        if self.child > 0 {
            // SAFETY: this process owns this child; no PID reuse is possible before waitpid.
            unsafe { libc::kill(self.child, libc::SIGKILL) };
            loop {
                // SAFETY: wait for this helper only; no shared status pointer is used.
                let waited = unsafe { libc::waitpid(self.child, std::ptr::null_mut(), 0) };
                if waited >= 0
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
            self.child = 0;
        }
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Fork before the launcher makes its view private, then give the launcher a distinct mount table.
#[cfg(any(test, feature = "test-support"))]
pub(super) fn prepare(request: Request) -> Result<Setup, ContainmentError> {
    if request.root == Path::new("/")
        || !request.root.is_absolute()
        || request
            .root
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(failure(
            "storage root must be an absolute non-root directory without traversal",
        ));
    }
    let parent = request
        .root
        .parent()
        .ok_or_else(|| failure("storage root has no parent"))?;
    let source_parent = open_path(parent)?;
    request
        .control
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(io_failure)?;
    request
        .control
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(io_failure)?;
    let (registration, helper_registration) = UnixStream::pair().map_err(io_failure)?;
    helper_registration
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(io_failure)?;
    let (parent_lifetime, helper_lifetime) = UnixStream::pair().map_err(io_failure)?;
    parent_lifetime
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(io_failure)?;
    helper_lifetime
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(io_failure)?;
    // The receiver may accept outside mounts, but it must never propagate its own mounts outward.
    propagation(libc::MS_SLAVE)?;
    // SAFETY: apply is called in the single-threaded trampoline before executing workload code.
    let child = unsafe { libc::fork() };
    if child == -1 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    if child == 0 {
        drop(registration);
        drop(parent_lifetime);
        let result = (|| {
            authority::close_inherited_descriptors(&[
                0,
                1,
                2,
                request.control.as_raw_fd(),
                helper_registration.as_raw_fd(),
                helper_lifetime.as_raw_fd(),
                source_parent.as_raw_fd(),
            ])?;
            authority::refuse_process_memory_access()?;
            authority::retain_storage_mount_access()?;
            authority::set_no_new_privileges()?;
            if !reaper::arm_parent_death(&helper_lifetime) {
                return Err(failure("storage helper parent-death handshake failed"));
            }
            drop(helper_lifetime);
            serve(&request, &source_parent, &helper_registration)
        })();
        let code = match result {
            Ok(()) => 0,
            Err(error) => {
                let _ = transport::send_json(
                    &request.control,
                    &serde_json::json!({"status":"failed", "error":error.to_string()}),
                );
                eprintln!("strands-box: storage helper failed: {error}");
                125
            }
        };
        // SAFETY: the helper must not return into launcher or workload code.
        unsafe { libc::_exit(code) };
    }
    drop(helper_registration);
    drop(helper_lifetime);
    drop(source_parent);
    let mut setup = Setup {
        targets: vec![(request.root.clone(), Scope::Root)],
        registration: Some(registration),
        lifetime: None,
        child,
        export_view: false,
    };
    if !reaper::confirm_parent_death(&parent_lifetime) {
        setup.finish();
        return Err(failure(
            "storage helper did not acknowledge parent-death protection",
        ));
    }
    drop(parent_lifetime);
    drop(request);
    // SAFETY: only this launcher leaves the receiving mount namespace. Its children inherit this copy.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    Ok(setup)
}

#[cfg(any(test, feature = "test-support"))]
fn serve(
    request: &Request,
    source_parent: &OwnedFd,
    registration: &UnixStream,
) -> Result<(), ContainmentError> {
    if matches!(
        request.capture,
        CaptureMode::Automatic {
            owner_handoff: true,
            ..
        }
    ) {
        protocol::send_owner(&request.control)?;
    }
    let destination_namespace = transport::receive_fd(registration)?;
    let destination = target::PinnedTarget::receive(registration, &request.root, Scope::Root)?;
    let (source, filesystem, capture_mode, pending_observations, notification_wakeups) =
        match request.capture {
            #[cfg(test)]
            CaptureMode::Manual => {
                let mut command = [0];
                (&request.control)
                    .read_exact(&mut command)
                    .map_err(io_failure)?;
                if command != *b"C" {
                    return Err(failure("invalid storage capture command"));
                }
                let name = request
                    .root
                    .file_name()
                    .ok_or_else(|| failure("storage root has no final component"))?;
                (
                    open_child(source_parent, Path::new(name))?,
                    None,
                    "manual",
                    0,
                    0,
                )
            }
            CaptureMode::Automatic {
                observe_pending, ..
            } => {
                let observed = observe::wait(
                    &request.root,
                    source_parent,
                    &request.control,
                    observe_pending,
                )?;
                (
                    observed.source,
                    Some(observed.filesystem),
                    "automatic",
                    observed.pending_observations,
                    observed.notification_wakeups,
                )
            }
        };
    let source_identity = identity(&source)?;
    let captured = clone_private_tree(&source)?;
    let inspection = clone_private_tree(&source)?;
    transport::send_fd(&request.control, &inspection)?;
    drop(inspection);
    let config_json = transport::receive_text(&request.control, CONTROL_LIMIT)?;

    // No raw source can propagate into the protected workload view. The selected clone is already
    // disconnected, and ordinary compiler/plan lookups now see it at its original logical name.
    // SAFETY: the helper is single-threaded and remains in the same owning user namespace.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    propagation(libc::MS_PRIVATE)?;
    let staging_target = open_path(&request.root)?;
    attach(&captured, &staging_target)?;
    let staged_source = open_path(&request.root)?;
    if identity(&staged_source)?.object() != source_identity.object() {
        return Err(failure(
            "captured source identity changed before policy compilation",
        ));
    }
    let config = ContainmentConfig::from_json(&config_json)?;
    let view = MountView::plan(&config)?;
    let protected = view.stage_subtree(&request.root)?;
    // The destination procfs describes the workload PID namespace, where this external helper
    // has no PID. Capture its authority in the staging namespace before entering that mount view.
    let capabilities = std::fs::read_to_string("/proc/self/status").map_err(io_failure)?;
    // SAFETY: destination namespace belongs to the same user namespace as this narrow helper.
    if unsafe { libc::setns(destination_namespace.as_raw_fd(), libc::CLONE_NEWNS) } != 0 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    destination.publish(&protected)?;
    transport::send_json(
        &request.control,
        &serde_json::json!({
            "status":"published", "source_device":source_identity.device,
            "source_inode":source_identity.inode,
            "source_mount_id":source_identity.mount,
            "source_filesystem":filesystem,
            "capture_mode":capture_mode,
            "pending_observations":pending_observations,
            "notification_wakeups":notification_wakeups,
            "helper_status": capabilities.lines().filter(|line| line.starts_with("Cap") || line.starts_with("NoNewPrivs:")).collect::<Vec<_>>()
        }),
    )?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    mount: u64,
}
impl Identity {
    fn object(&self) -> (u64, u64) {
        (self.device, self.inode)
    }
}

fn identity(fd: &OwnedFd) -> Result<Identity, ContainmentError> {
    // SAFETY: statx writes a fully sized output structure, using an owned descriptor.
    let mut result: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_INO | libc::STATX_MNT_ID,
            &mut result,
        )
    } != 0
    {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    if result.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(failure("kernel did not report mount identity"));
    }
    Ok(Identity {
        device: (u64::from(result.stx_dev_major) << 32) | u64::from(result.stx_dev_minor),
        inode: result.stx_ino,
        mount: result.stx_mnt_id,
    })
}

/// Clone every submount and disconnect propagation before any observation or policy work.
pub(super) fn clone_private_tree(source: &OwnedFd) -> Result<OwnedFd, ContainmentError> {
    const OPEN_TREE_CLONE: u32 = 1;
    // SAFETY: open_tree consumes a live descriptor and an empty, terminated pathname.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            source.as_raw_fd(),
            c"".as_ptr(),
            OPEN_TREE_CLONE
                | libc::O_CLOEXEC as u32
                | libc::AT_EMPTY_PATH as u32
                | libc::AT_RECURSIVE as u32,
        )
    };
    let cloned = own(raw)?;
    #[repr(C)]
    struct MountAttr {
        set: u64,
        clear: u64,
        propagation: u64,
        userns_fd: u64,
    }
    let attr = MountAttr {
        set: 0,
        clear: 0,
        propagation: libc::MS_PRIVATE,
        userns_fd: 0,
    };
    // SAFETY: the sized attribute structure and empty path remain valid for the syscall.
    if unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            cloned.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_RECURSIVE,
            &attr,
            std::mem::size_of_val(&attr),
        )
    } != 0
    {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    Ok(cloned)
}

fn attach(source: &OwnedFd, target: &OwnedFd) -> Result<(), ContainmentError> {
    const EMPTY_PATHS: u32 = 0x00000004 | 0x00000040;
    // SAFETY: both descriptors pin live mount-tree objects; empty-path mode performs no path reopen.
    if unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            source.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            EMPTY_PATHS,
        )
    } != 0
    {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn propagation(flags: libc::c_ulong) -> Result<(), ContainmentError> {
    // SAFETY: a scalar propagation change for this process's current private mount namespace.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | flags,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn open_namespace() -> Result<OwnedFd, ContainmentError> {
    // SAFETY: the literal path is terminated; following this procfs magic link is intentional.
    own(unsafe {
        libc::open(
            c"/proc/self/ns/mnt".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    } as libc::c_long)
}

fn open_path(path: &Path) -> Result<OwnedFd, ContainmentError> {
    let path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| failure("path contains NUL"))?;
    // SAFETY: the terminated path is live for this syscall; no final symlink is followed.
    own(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    } as libc::c_long)
}

fn open_child(parent: &OwnedFd, name: &Path) -> Result<OwnedFd, ContainmentError> {
    let path = CString::new(name.as_os_str().as_bytes())
        .map_err(|_| failure("source name contains NUL"))?;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: 0x08 | 0x04 | 0x02,
    };
    // SAFETY: the source parent pins the receiving namespace; openat2 refuses symlink/traversal escapes.
    own(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of_val(&how),
        )
    })
}

fn own(raw: libc::c_long) -> Result<OwnedFd, ContainmentError> {
    if raw < 0 {
        Err(io_failure(std::io::Error::last_os_error()))
    }
    // SAFETY: a successful descriptor-creating syscall returns a new owned descriptor.
    else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) })
    }
}

fn io_failure(error: std::io::Error) -> ContainmentError {
    failure(error.to_string())
}
fn failure(reason: impl Into<String>) -> ContainmentError {
    apply_failure(format!("storage admission: {}", reason.into()))
}

/// Fixture-only access to the real launcher and its private controller protocol.
#[cfg(any(test, feature = "test-support"))]
pub mod fixture {
    pub use super::protocol::{GenerationRequest, HelperEvent, SourceIdentity};
    use super::{CONTROL_LIMIT, CaptureMode, Request, protocol, transport};
    use crate::backend::ContainmentBackend as _;
    use crate::{ContainmentConfig, ContainmentError};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    /// Apply containment with automatic admission of one declared pending storage root.
    pub fn apply(
        config: &ContainmentConfig,
        root: PathBuf,
        control: UnixStream,
    ) -> Result<(), ContainmentError> {
        apply_mode(config, root, control, false, false)
    }

    /// Apply the automatic fixture and report its first pending source observation privately.
    pub fn apply_observing_pending(
        config: &ContainmentConfig,
        root: PathBuf,
        control: UnixStream,
    ) -> Result<(), ContainmentError> {
        apply_mode(config, root, control, true, false)
    }

    /// Apply the one-root fixture with an initial owner-user-namespace handoff.
    ///
    /// Receive that handle first, then use the existing observation/configuration functions.
    pub fn apply_with_owner_observation(
        config: &ContainmentConfig,
        root: PathBuf,
        control: UnixStream,
    ) -> Result<(), ContainmentError> {
        apply_mode(config, root, control, false, true)
    }

    /// Receive and validate the helper owner namespace without joining it in the caller.
    pub fn receive_owner_namespace(control: &UnixStream) -> Result<OwnedFd, ContainmentError> {
        protocol::receive_owner(control)
    }

    /// Encode a generation command for private protocol fixtures; the one-root launcher does not consume it.
    pub fn send_generation(
        control: &UnixStream,
        request: &GenerationRequest,
    ) -> Result<(), ContainmentError> {
        protocol::send_generation(control, request)
    }

    /// Decode a typed generation event in private protocol fixtures.
    pub fn receive_event(control: &UnixStream) -> Result<HelperEvent, ContainmentError> {
        protocol::receive_event(control)
    }

    fn apply_mode(
        config: &ContainmentConfig,
        root: PathBuf,
        control: UnixStream,
        observe_pending: bool,
        owner_handoff: bool,
    ) -> Result<(), ContainmentError> {
        crate::floors::require_all(config)?;
        let backend = super::super::NamespaceBackend::new();
        backend.validate_config(config)?;
        backend.apply_with_storage(
            config,
            None,
            None,
            None,
            Some(Request {
                root,
                control,
                capture: CaptureMode::Automatic {
                    observe_pending,
                    owner_handoff,
                },
            }),
            None,
        )
    }

    /// Receive an independent detached source tree for private inspection at its original path.
    pub fn receive_observation(control: &UnixStream) -> Result<OwnedFd, ContainmentError> {
        transport::receive_fd(control)
    }

    /// Return a profile produced by the original Box filesystem compiler.
    pub fn send_config(control: &UnixStream, config: &str) -> Result<(), ContainmentError> {
        transport::send_text(control, config)
    }

    /// Receive bounded publication or failure evidence from the storage helper.
    pub fn receive_receipt(control: &UnixStream) -> Result<String, ContainmentError> {
        transport::receive_text(control, CONTROL_LIMIT)
    }
}

/// Read one private descriptor for the cross-crate controller bridge.
pub(crate) fn receive_descriptor(control: &UnixStream) -> Result<OwnedFd, ContainmentError> {
    transport::receive_fd(control)
}
