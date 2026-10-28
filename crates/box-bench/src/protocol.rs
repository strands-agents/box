//! The handshakes between the runner and the probe.

/// The probe mode that measures startup.
pub(crate) const STARTUP: &str = "startup";
/// The probe mode that sends HTTP requests on the runner's commands.
pub(crate) const EGRESS: &str = "egress";
/// The marker the probe writes when it is ready.
pub(crate) const READY: &[u8; 6] = b"READY\n";
/// The byte the runner writes to let the probe exit.
pub(crate) const RELEASE: &[u8; 1] = b"\n";
/// The egress command that sends a fixed number of requests: `load STATUS URL CONCURRENCY COUNT`.
/// The reply is `ELAPSED_NS FAILURES LATENCY_NS...`.
pub(crate) const LOAD: &str = "load";
/// The egress command that sends one request and times its first byte: `stream URL`.
/// The reply is `FIRST_BYTE_NS TOTAL_NS`.
pub(crate) const STREAM: &str = "stream";
