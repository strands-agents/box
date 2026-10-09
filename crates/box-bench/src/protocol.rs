//! The readiness handshake between the runner and the probe.

/// The probe mode that measures startup.
pub(crate) const STARTUP: &str = "startup";
/// The marker the probe writes when it is ready.
pub(crate) const READY: &[u8; 6] = b"READY\n";
/// The byte the runner writes to let the probe exit.
pub(crate) const RELEASE: &[u8; 1] = b"\n";
