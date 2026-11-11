//! Explicit operator consent for experimental platform support.

use crate::error::ConfigError;

pub(crate) fn preflight() -> Result<(), ConfigError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if std::env::var_os("EXPERIMENTAL_X86_SUPPORT").as_deref() != Some(std::ffi::OsStr::new("TRUE"))
    {
        return Err(ConfigError::ExperimentalX86Support);
    }
    Ok(())
}
