//! Bounded private storage frames whose indices refer to the immutable launch layout.

use super::{CONTROL_LIMIT, failure, own, transport};
use crate::{ContainmentError, Scope};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// Version of the private storage handoff.
pub const VERSION: u16 = 2;

/// One immutable publication or pending-mask destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageTarget {
    /// Absolute logical path in the workload view.
    pub path: PathBuf,
    /// Directory-tree or regular-file destination kind.
    pub scope: Scope,
}

/// The layout retained before any workload executes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageLayout {
    /// Private protocol version.
    pub version: u16,
    /// Provider roots, in their permanent index order.
    pub roots: Vec<PathBuf>,
    /// Logical objects hidden until a protected projection replaces them.
    pub masks: Vec<StorageTarget>,
    /// Possible publication destinations, in their permanent index order.
    pub targets: Vec<StorageTarget>,
}

/// A command accepted only on the launcher's private storage socket.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControllerCommand {
    /// Fix the complete layout before namespace setup.
    Initialize(StorageLayout),
    /// Obtain independent compiler clones of every currently reported capture.
    Snapshot {
        /// Nonzero, increasing transaction identifier.
        generation: u64,
    },
    /// Build a protected view from the frozen compiler snapshot.
    Prepare(GenerationRequest),
    /// Release a compiler snapshot that produced no new publication targets.
    Release {
        /// Identifier of the unstaged snapshot being released.
        generation: u64,
    },
    /// Authorize attachment of an already prepared transaction.
    Commit {
        /// Identifier returned by the prepared event.
        generation: u64,
    },
    /// Stop this receiver and every pending admission worker.
    Abort,
}

/// The compiler's requested generation. Paths are not accepted as routing authority in this frame.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationRequest {
    /// Nonzero identifier that the controller assigns to this publication transaction.
    pub generation: u64,
    /// Unique indices of captured sources required to compile this transaction.
    pub captured_roots: Vec<u32>,
    /// Unique indices of the launch-time targets to publish in this transaction.
    pub targets: Vec<u32>,
    /// Deserialize this only after every named captured root is installed at its original path.
    pub config_json: String,
}

impl GenerationRequest {
    /// Check frame shape. The receiver must separately check captured and unpublished indices.
    pub fn validate(&self) -> Result<(), ContainmentError> {
        if self.generation == 0 || self.captured_roots.is_empty() || self.targets.is_empty() {
            return Err(failure(
                "a storage generation must have a nonzero ID, captured roots, and targets",
            ));
        }
        for indices in [&self.captured_roots, &self.targets] {
            if indices.iter().collect::<BTreeSet<_>>().len() != indices.len() {
                return Err(failure("a storage generation repeats an index"));
            }
        }
        if self.config_json.is_empty() || self.config_json.len() > CONTROL_LIMIT {
            return Err(failure(
                "a storage generation has an empty or oversized configuration",
            ));
        }
        Ok(())
    }
}

/// Identity of the root object observed before making independent private clones.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    /// Filesystem device identity, with the major number in the high 32 bits.
    pub device: u64,
    /// Inode number of the captured root object on that filesystem.
    pub inode: u64,
    /// Mount identifier reported for the freshly opened root in the receiving namespace.
    pub mount_id: u64,
}

/// Events on the private helper/controller channel with explicit descriptor counts.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperEvent {
    /// Followed by the namespace FD that owns the helper's mount authority.
    Started {
        /// Version of the private helper/controller wire protocol.
        version: u16,
    },
    /// Followed by the sealed workload root descriptor used for protected hosted access.
    ViewReady,
    /// A source is retained; compiler descriptors arrive only in a snapshot event.
    Captured {
        /// Index of the source in the immutable launch-time root layout.
        root: u32,
        /// Identity observed before the helper made independent private source clones.
        identity: SourceIdentity,
        /// Filesystem type reported by the matching active mount-table record.
        filesystem: String,
    },
    /// Followed by one fresh private clone FD for each listed root, in order.
    Snapshot {
        /// Transaction whose complete source set is now frozen.
        generation: u64,
        /// Permanent root indices supplied to the fresh compiler.
        captured_roots: Vec<u32>,
    },
    /// Every requested projection is protected and waiting for owner authorization.
    Prepared {
        /// Transaction waiting for a matching commit command.
        generation: u64,
        /// Permanent target indices staged by this transaction.
        targets: Vec<u32>,
    },
    /// The helper attached every listed protected target for one transaction.
    Published {
        /// Identifier of the completed publication transaction.
        generation: u64,
        /// Launch-time target indices whose protected mounts were attached.
        targets: Vec<u32>,
    },
    /// The owned workload exited and every receiver worker was stopped, even if roots stayed pending.
    Complete,
    /// Admission failed; the controller must route this failure to whole-Box shutdown.
    Failed {
        /// Admission stage that reported the failure.
        stage: String,
        /// Bounded diagnostic describing why admission failed.
        message: String,
    },
}

pub(super) fn send_owner(control: &UnixStream) -> Result<(), ContainmentError> {
    // SAFETY: the procfs namespace link is an intentional kernel namespace handle.
    let owner = own(unsafe {
        libc::open(
            c"/proc/self/ns/user".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    } as libc::c_long)?;
    send_event(control, &HelperEvent::Started { version: VERSION })?;
    transport::send_fd(control, &owner)
}

/// Receive and validate the helper owning-user-namespace descriptor.
pub fn receive_owner(control: &UnixStream) -> Result<OwnedFd, ContainmentError> {
    if receive_event(control)? != (HelperEvent::Started { version: VERSION }) {
        return Err(failure(
            "storage helper did not send a supported owner-namespace handshake",
        ));
    }
    let owner = transport::receive_fd(control)?;
    use std::os::fd::AsRawFd;
    // SAFETY: NS_GET_NSTYPE inspects the received namespace descriptor without changing namespaces.
    const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
    if unsafe { libc::ioctl(owner.as_raw_fd(), NS_GET_NSTYPE) } != libc::CLONE_NEWUSER {
        return Err(failure("storage owner handoff is not a user namespace"));
    }
    Ok(owner)
}

pub(super) fn send_event(
    control: &UnixStream,
    event: &HelperEvent,
) -> Result<(), ContainmentError> {
    let json = serde_json::to_string(event)
        .map_err(|error| failure(format!("encoding storage event: {error}")))?;
    transport::send_text(control, &json)
}

/// Receive one bounded event without consuming any following descriptors.
pub fn receive_event(control: &UnixStream) -> Result<HelperEvent, ContainmentError> {
    serde_json::from_str(&transport::receive_text(control, CONTROL_LIMIT)?)
        .map_err(|error| failure(format!("invalid storage event: {error}")))
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn send_generation(
    control: &UnixStream,
    request: &GenerationRequest,
) -> Result<(), ContainmentError> {
    request.validate()?;
    let json = serde_json::to_string(request)
        .map_err(|error| failure(format!("encoding storage generation: {error}")))?;
    transport::send_text(control, &json)
}

/// Send one controller command on the private socket.
pub fn send_command(
    control: &UnixStream,
    command: &ControllerCommand,
) -> Result<(), ContainmentError> {
    let json = serde_json::to_string(command)
        .map_err(|error| failure(format!("encoding storage command: {error}")))?;
    transport::send_text(control, &json)
}

pub(super) fn receive_command(control: &UnixStream) -> Result<ControllerCommand, ContainmentError> {
    serde_json::from_str(&transport::receive_text(control, CONTROL_LIMIT)?)
        .map_err(|error| failure(format!("invalid storage command: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn owner_handoff_transfers_a_cloexec_user_namespace_without_joining_it() {
        let before = std::fs::read_link("/proc/self/ns/user").unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        send_owner(&sender).unwrap();
        let owner = receive_owner(&receiver).unwrap();
        // SAFETY: F_GETFD inspects an owned descriptor.
        assert_ne!(
            unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert_eq!(std::fs::read_link("/proc/self/ns/user").unwrap(), before);
    }

    #[test]
    fn generation_shape_rejects_duplicate_or_empty_routes_without_loading_config_paths() {
        let mut request = GenerationRequest {
            generation: 1,
            captured_roots: vec![0, 2],
            targets: vec![3],
            config_json: "{}".into(),
        };
        request.validate().unwrap();
        request.captured_roots.push(0);
        assert!(request.validate().is_err());
        request.captured_roots = vec![0];
        request.targets.clear();
        assert!(request.validate().is_err());
        assert!(serde_json::from_str::<GenerationRequest>(r#"{"generation":1,"captured_roots":[0],"targets":[0],"config_json":"{}","path":"/unexpected"}"#).is_err());
    }

    #[test]
    fn owner_handshake_rejects_a_mount_namespace_descriptor() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        send_event(&sender, &HelperEvent::Started { version: VERSION }).unwrap();
        // SAFETY: open returns a new owned namespace descriptor.
        let wrong = own(unsafe {
            libc::open(
                c"/proc/self/ns/mnt".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        } as libc::c_long)
        .unwrap();
        transport::send_fd(&sender, &wrong).unwrap();
        assert!(receive_owner(&receiver).is_err());
    }
}
