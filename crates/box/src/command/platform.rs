//! Operator consent follows [the Linux decision](../../../../docs/design/decisions.md#linux-evaluation-requires-explicit-consent).

use crate::error::ConfigError;

pub(crate) fn preflight() -> Result<(), ConfigError> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("EXPERIMENTAL_LINUX_SUPPORT").as_deref()
        != Some(std::ffi::OsStr::new("TRUE"))
    {
        return Err(ConfigError::ExperimentalLinuxSupport);
    }
    Ok(())
}
