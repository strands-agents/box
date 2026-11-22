//! Private transport shared by the Box coordinator and its containment workers.

pub use crate::backend::linux::namespace::storage::production::enter_compiler_view;
pub use crate::backend::linux::namespace::storage::protocol::{
    ControllerCommand, GenerationRequest, HelperEvent, SourceIdentity, StorageLayout,
    StorageTarget, VERSION, receive_event, receive_owner, send_command,
};
pub use crate::backend::linux::namespace::storage::sources;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

/// Receive one close-on-exec descriptor following a descriptor-bearing event.
pub fn receive_fd(control: &UnixStream) -> crate::Result<OwnedFd> {
    crate::backend::linux::namespace::storage::receive_descriptor(control)
}

/// Match workload filesystem credentials on the dedicated hosted interpreter thread.
pub fn drop_hosted_capabilities() -> crate::Result<()> {
    crate::backend::linux::namespace::authority::drop_hosted_capabilities()
}

/// Send one private descriptor to the containment receiver.
pub fn send_fd(control: &UnixStream, descriptor: &OwnedFd) -> crate::Result<()> {
    crate::backend::linux::namespace::storage::send_descriptor(control, descriptor)
}
