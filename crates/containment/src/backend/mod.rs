//! Backend trait and platform-specific implementations.

mod dependencies;
pub(crate) mod macos;

#[cfg(target_os = "linux")]
pub(crate) mod linux;

use crate::ContainmentConfig;
use crate::error::ContainmentError;
use crate::platform::Platform;

/// Uniform interface for platform-specific enforcement backends.
pub(crate) trait ContainmentBackend: Send + Sync + std::fmt::Debug {
    /// Validate that this backend can enforce the given configuration.
    fn validate_config(&self, config: &ContainmentConfig) -> Result<(), ContainmentError>;

    /// Apply this backend's enforcement to the current process, irreversibly.
    fn apply(
        &self,
        config: &ContainmentConfig,
        egress_handoff: Option<&std::os::unix::net::UnixStream>,
        confirm_fd: Option<std::os::fd::RawFd>,
        native_filesystem_handoff: Option<&std::os::unix::net::UnixStream>,
    ) -> Result<(), ContainmentError>;

    /// Report this backend's enforcement capability on the current host.
    fn support_info(&self) -> SupportInfo;
}

/// A backend's truthful report of what it can enforce on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SupportInfo {
    /// Whether this backend can enforce on the current platform.
    pub(crate) is_supported: bool,
    /// The platform this backend targets.
    pub(crate) platform: Platform,
    /// Short name of the mechanism (e.g. `"seatbelt"`, `"namespace"`).
    pub(crate) mechanism: String,
    /// Human-readable detail for diagnostics.
    pub(crate) details: String,
}
