//! Platform detection and host details.

/// Target platform for containment enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Platform {
    /// macOS (Seatbelt enforcement).
    MacOS,
    /// Linux (namespace launcher enforcement).
    Linux,
    /// Windows. Detection-only; no backend currently claims support.
    Windows,
    /// Any unsupported host target that is not macOS, Linux, or Windows.
    Other,
}

/// Detected host platform details.
#[derive(Debug, Clone)]
pub(crate) struct PlatformInfo {
    /// The detected platform.
    pub(crate) platform: Platform,
    /// Human-readable details.
    pub(crate) details: String,
}

/// Detect the current host platform.
pub(crate) fn detect() -> PlatformInfo {
    #[cfg(target_os = "macos")]
    {
        PlatformInfo {
            platform: Platform::MacOS,
            details: "macOS, Seatbelt available".to_string(),
        }
    }

    #[cfg(target_os = "linux")]
    {
        linux_platform_info()
    }

    #[cfg(target_os = "windows")]
    {
        PlatformInfo {
            platform: Platform::Windows,
            details: "Windows, no containment backend available".to_string(),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PlatformInfo {
            platform: Platform::Other,
            details: format!(
                "unsupported host target {} (no containment backend)",
                std::env::consts::OS
            ),
        }
    }
}

/// Build Linux host details. The mechanism reports its own live probe, so detection carries the
/// architecture the facade decides on and nothing more.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_platform_info() -> PlatformInfo {
    PlatformInfo {
        platform: Platform::Linux,
        details: format!("Linux {}", std::env::consts::ARCH),
    }
}

#[cfg(test)]
mod tests {
    use super::{Platform, linux_platform_info};

    #[test]
    fn linux_details_name_the_architecture() {
        let info = linux_platform_info();
        assert_eq!(info.platform, Platform::Linux);
        assert!(info.details.contains(std::env::consts::ARCH), "{info:?}");
    }
}
