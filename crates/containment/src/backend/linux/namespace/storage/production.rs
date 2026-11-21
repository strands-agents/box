//! Production storage handoff and creation of the persistent per-workload receiver.

use super::protocol::{ControllerCommand, HelperEvent, StorageLayout, VERSION};
use super::*;
use std::os::fd::{BorrowedFd, RawFd};

pub(crate) struct ProductionRequest {
    pub(crate) layout: StorageLayout,
    control: UnixStream,
    sources: UnixStream,
}

impl StorageLayout {
    /// Validate immutable logical paths without resolving provider contents.
    pub fn validate(&self) -> Result<(), ContainmentError> {
        if self.version != VERSION || self.roots.is_empty() {
            return Err(failure("unsupported or empty storage initialization"));
        }
        fn logical(path: &Path) -> bool {
            path.is_absolute()
                && path != Path::new("/")
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
                && !path
                    .as_os_str()
                    .as_bytes()
                    .split(|byte| *byte == b'/')
                    .any(|part| part == b"." || part == b"..")
        }
        for (index, root) in self.roots.iter().enumerate() {
            if !logical(root)
                || self.roots[..index]
                    .iter()
                    .any(|other| root.starts_with(other) || other.starts_with(root))
            {
                return Err(failure(
                    "storage roots must be distinct nonoverlapping absolute directories",
                ));
            }
            if !self
                .masks
                .iter()
                .any(|mask| mask.path == *root && mask.scope == Scope::Root)
            {
                return Err(failure(
                    "every storage root needs an initial directory mask",
                ));
            }
        }
        for entries in [&self.masks, &self.targets] {
            for (index, target) in entries.iter().enumerate() {
                if !logical(&target.path)
                    || !matches!(target.scope, Scope::Root | Scope::File)
                    || entries[..index].iter().any(|other| {
                        target.path.starts_with(&other.path) || other.path.starts_with(&target.path)
                    })
                {
                    return Err(failure(
                        "storage destinations must be distinct nonoverlapping absolute files or directories",
                    ));
                }
            }
        }
        for target in &self.targets {
            if !self.masks.contains(target) {
                return Err(failure(
                    "every publication destination needs an identical initial mask",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn request(raw: RawFd) -> Result<ProductionRequest, ContainmentError> {
    if raw <= 2 {
        return Err(failure(
            "storage control descriptor must not be standard IO",
        ));
    }
    // SAFETY: cloning validates that the caller-supplied descriptor is open; it is not consumed.
    let owned = unsafe { BorrowedFd::borrow_raw(raw) }
        .try_clone_to_owned()
        .map_err(io_failure)?;
    let control = UnixStream::from(owned);
    control.peer_addr().map_err(io_failure)?;
    control.set_read_timeout(None).map_err(io_failure)?;
    control.set_write_timeout(None).map_err(io_failure)?;
    let mut kind: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
    // SAFETY: both output pointers have their declared sizes.
    if unsafe {
        libc::getsockopt(
            control.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut size,
        )
    } != 0
        || kind != libc::SOCK_STREAM
    {
        return Err(failure("storage control must be a connected Unix stream"));
    }
    let ControllerCommand::Initialize(layout) = protocol::receive_command(&control)? else {
        return Err(failure(
            "storage control must initialize its immutable layout first",
        ));
    };
    layout.validate()?;
    let sources = UnixStream::from(transport::receive_fd(&control)?);
    sources.peer_addr().map_err(io_failure)?;
    Ok(ProductionRequest {
        layout,
        control,
        sources,
    })
}

pub(in crate::backend::linux::namespace) fn prepare(
    request: ProductionRequest,
) -> Result<Setup, ContainmentError> {
    let (registration, receiver_registration) = UnixStream::pair().map_err(io_failure)?;
    let (lifetime, receiver_lifetime) = UnixStream::pair().map_err(io_failure)?;
    propagation(libc::MS_SLAVE)?;
    // SAFETY: the containment trampoline is single-threaded before workload execution.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    if child == 0 {
        drop(registration);
        drop(lifetime);
        let result = (|| {
            authority::close_inherited_descriptors(&[
                0,
                1,
                2,
                request.control.as_raw_fd(),
                request.sources.as_raw_fd(),
                receiver_registration.as_raw_fd(),
                receiver_lifetime.as_raw_fd(),
            ])?;
            authority::refuse_process_memory_access()?;
            authority::retain_storage_mount_access()?;
            authority::set_no_new_privileges()?;
            if !reaper::arm_parent_death(&receiver_lifetime) {
                return Err(failure("storage receiver parent-death handshake failed"));
            }
            protocol::send_owner(&request.control)?;
            super::receiver::run(
                &request.layout,
                &request.control,
                &receiver_registration,
                &receiver_lifetime,
                &request.sources,
            )
        })();
        match &result {
            Ok(true) => {
                let _ = protocol::send_event(&request.control, &HelperEvent::Complete);
            }
            Ok(false) => {}
            Err(error) => {
                let _ = protocol::send_event(
                    &request.control,
                    &HelperEvent::Failed {
                        stage: "receiver".into(),
                        message: error.to_string(),
                    },
                );
                eprintln!("strands-box: storage receiver failed: {error}");
            }
        }
        // SAFETY: the receiver never returns to launcher or workload code.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 125 }) };
    }
    drop(receiver_registration);
    drop(receiver_lifetime);
    let mut setup = Setup {
        targets: request
            .layout
            .targets
            .iter()
            .map(|target| (target.path.clone(), target.scope))
            .collect(),
        registration: Some(registration),
        lifetime: Some(lifetime),
        child,
        export_view: true,
    };
    if !reaper::confirm_parent_death(setup.lifetime.as_ref().expect("lifetime is retained")) {
        setup.finish();
        return Err(failure(
            "storage receiver did not acknowledge parent-death protection",
        ));
    }
    // SAFETY: the workload leaves the receiver's slave mount namespace before materialization.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    Ok(setup)
}

/// Enter a captured-source inspection view only in a fresh, single-threaded compiler executable.
pub fn enter_compiler_view(
    userns_fd: RawFd,
    roots: &[(&Path, RawFd)],
) -> Result<(), ContainmentError> {
    if std::fs::read_dir("/proc/self/task")
        .map_err(io_failure)?
        .count()
        != 1
    {
        return Err(failure(
            "storage compiler namespace setup requires a single-threaded fresh executable",
        ));
    }
    // SAFETY: NS_GET_NSTYPE verifies the private namespace descriptor before joining it.
    if unsafe { libc::ioctl(userns_fd, 0xb703 as libc::c_ulong) } != libc::CLONE_NEWUSER {
        return Err(failure("compiler owner descriptor is not a user namespace"));
    }
    // SAFETY: this process is the explicitly designated disposable compiler worker.
    if unsafe { libc::setns(userns_fd, libc::CLONE_NEWUSER) } != 0 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    install_sources(roots)?;
    authority::drop_all_capabilities()?;
    authority::set_no_new_privileges()
}

pub(super) fn install_sources(roots: &[(&Path, RawFd)]) -> Result<(), ContainmentError> {
    // SAFETY: only this disposable worker changes its private mount table.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(io_failure(std::io::Error::last_os_error()));
    }
    propagation(libc::MS_PRIVATE)?;
    for (path, raw) in roots {
        // SAFETY: descriptors are borrowed from the private, identity-bound snapshot handoff.
        let source = unsafe { BorrowedFd::borrow_raw(*raw) }
            .try_clone_to_owned()
            .map_err(io_failure)?;
        let expected = identity(&source)?.object();
        let target = open_path(path)?;
        attach(&source, &target)?;
        if identity(&open_path(path)?)?.object() != expected {
            return Err(failure("captured source changed during attachment"));
        }
    }
    Ok(())
}
