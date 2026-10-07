//! One-step containment facade.

use crate::backend::ContainmentBackend;
use crate::config::ContainmentConfig;
use crate::error::ContainmentError;
use crate::platform::{Platform, PlatformInfo};

/// Detects the host backend and contains the calling process in one operation.
pub struct Containment {
    _private: (),
}

impl Containment {
    /// Detect the host backend and contain this process using `config`.
    pub fn apply(
        config: &ContainmentConfig,
        egress_handoff: Option<&std::os::unix::net::UnixStream>,
        confirm_fd: Option<std::os::fd::RawFd>,
    ) -> Result<(), ContainmentError> {
        apply_backend(Self::detect_backend, config, egress_handoff, confirm_fd)
    }

    fn detect_backend() -> Result<Box<dyn ContainmentBackend>, ContainmentError> {
        let platform_info = crate::platform::detect();

        #[cfg(target_os = "macos")]
        {
            use crate::backend::macos::seatbelt::SeatbeltBackend;

            match platform_info.platform {
                Platform::MacOS => {
                    let backend = Box::new(SeatbeltBackend::new());
                    checked_backend(&platform_info, backend)
                }
                other => Err(ContainmentError::PlatformUnsupported {
                    platform: other,
                    reason: format!("this macOS build has no backend for platform {other:?}"),
                }),
            }
        }

        #[cfg(target_os = "linux")]
        {
            linux_backend(&platform_info)
        }

        #[cfg(all(unix, not(target_os = "macos"), not(target_os = "linux")))]
        {
            Err(ContainmentError::PlatformUnsupported {
                platform: platform_info.platform,
                reason: "no containment backend compiled for this unix target".to_string(),
            })
        }

        #[cfg(not(unix))]
        {
            Err(ContainmentError::PlatformUnsupported {
                platform: platform_info.platform,
                reason: "containment is macOS (Seatbelt) / Linux (namespaces) only".to_string(),
            })
        }
    }
}

/// Which Linux mechanism this host gets, from what was probed.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LinuxMechanism {
    /// The namespace launcher on ARM64 at every probed ABI.
    Namespace,
    /// Refused. Carries why, so the caller does not compose the message.
    Refused(String),
}

/// Decide the Linux mechanism.
#[cfg(target_os = "linux")]
pub(crate) fn linux_mechanism(platform: Platform, architecture: &str) -> LinuxMechanism {
    // Selection is by platform, not a config key and not a build flag.
    match platform {
        // The namespace launcher is the one mechanism on the measured architecture.
        Platform::Linux if architecture == "aarch64" => LinuxMechanism::Namespace,
        Platform::Linux => LinuxMechanism::Refused(format!(
            "Linux containment supports ARM64 (aarch64), not {architecture}"
        )),
        other => LinuxMechanism::Refused(format!(
            "this Linux build has no backend for platform {other:?}"
        )),
    }
}

/// Build the Linux backend the decision above selected.
#[cfg(target_os = "linux")]
fn linux_backend(
    platform_info: &PlatformInfo,
) -> Result<Box<dyn ContainmentBackend>, ContainmentError> {
    use crate::backend::linux::namespace::NamespaceBackend;

    match linux_mechanism(platform_info.platform, std::env::consts::ARCH) {
        LinuxMechanism::Namespace => {
            // The backend reports `is_supported` from a live probe, and `checked_backend` refuses
            // it when that probe says no — so a host that also forbids user namespaces still fails
            // closed rather than running uncontained.
            checked_backend(platform_info, Box::new(NamespaceBackend::new()))
        }
        LinuxMechanism::Refused(reason) => Err(ContainmentError::PlatformUnsupported {
            platform: platform_info.platform,
            reason,
        }),
    }
}

/// Validate a selected backend against the detected host before it can apply.
pub(crate) fn checked_backend(
    platform_info: &PlatformInfo,
    backend: Box<dyn ContainmentBackend>,
) -> Result<Box<dyn ContainmentBackend>, ContainmentError> {
    let support = backend.support_info();
    if support.platform != platform_info.platform {
        return Err(ContainmentError::PlatformUnsupported {
            platform: platform_info.platform,
            reason: format!(
                "backend '{}' targets {:?}, not detected platform {:?}",
                support.mechanism, support.platform, platform_info.platform
            ),
        });
    }
    if !support.is_supported {
        return Err(ContainmentError::PlatformUnsupported {
            platform: platform_info.platform,
            reason: format!(
                "backend '{}' reports it cannot enforce on this host: {} (detected: {})",
                support.mechanism, support.details, platform_info.details
            ),
        });
    }

    Ok(backend)
}

/// Apply every floor, validate backend support, then apply.
///
/// The floors run beneath every backend, and [`crate::floors`] states why in that order.
pub(crate) fn apply_backend<B: std::ops::Deref<Target = dyn ContainmentBackend>>(
    select_backend: impl FnOnce() -> Result<B, ContainmentError>,
    config: &ContainmentConfig,
    egress_handoff: Option<&std::os::unix::net::UnixStream>,
    confirm_fd: Option<std::os::fd::RawFd>,
) -> Result<(), ContainmentError> {
    crate::floors::require_all(config)?;
    let backend = select_backend()?;
    backend.validate_config(config)?;
    backend.apply(config, egress_handoff, confirm_fd)
}

#[cfg(test)]
mod tests {
    use super::{apply_backend, checked_backend};
    use crate::backend::{ContainmentBackend, SupportInfo};
    use crate::config::ContainmentConfig;
    use crate::error::ContainmentError;
    use crate::model::{Operation, Scope};
    use crate::platform::{Platform, PlatformInfo};
    use crate::test_support::MockBackend;

    fn platform_info(platform: Platform) -> PlatformInfo {
        PlatformInfo {
            platform,
            details: "synthetic facade test".to_string(),
        }
    }

    /// An ARM64 kernel gets the namespace launcher.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_arm64_kernel_selects_the_namespace_launcher() {
        use super::{LinuxMechanism, linux_mechanism};

        assert_eq!(
            linux_mechanism(Platform::Linux, "aarch64"),
            LinuxMechanism::Namespace
        );
    }

    /// A non-Linux platform reaching the Linux arm is refused rather than defaulted.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_non_linux_platform_in_the_linux_arm_is_refused() {
        use super::{LinuxMechanism, linux_mechanism};

        assert!(matches!(
            linux_mechanism(Platform::Windows, "aarch64"),
            LinuxMechanism::Refused(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_non_arm64_linux_architecture_is_refused() {
        use super::{LinuxMechanism, linux_mechanism};

        let decision = linux_mechanism(Platform::Linux, "x86_64");
        assert!(matches!(decision, LinuxMechanism::Refused(reason) if
            reason.contains("ARM64") && reason.contains("x86_64")));
    }

    #[test]
    fn rejects_backend_for_a_different_platform() {
        let backend = MockBackend::new(SupportInfo {
            is_supported: true,
            platform: Platform::Linux,
            mechanism: "namespace".to_string(),
            details: "synthetic".to_string(),
        });

        let error = checked_backend(&platform_info(Platform::MacOS), Box::new(backend))
            .expect_err("platform mismatch must be refused");

        assert!(matches!(
            error,
            ContainmentError::PlatformUnsupported {
                platform: Platform::MacOS,
                ..
            }
        ));
    }

    #[test]
    fn rejects_backend_that_reports_unsupported() {
        let backend = MockBackend::new(SupportInfo {
            is_supported: false,
            platform: Platform::MacOS,
            mechanism: "seatbelt".to_string(),
            details: "synthetic refusal".to_string(),
        });

        let error = checked_backend(&platform_info(Platform::MacOS), Box::new(backend))
            .expect_err("unsupported backend must be refused");

        assert!(matches!(
            error,
            ContainmentError::PlatformUnsupported {
                platform: Platform::MacOS,
                ..
            }
        ));
    }

    #[test]
    fn a_credential_grant_is_refused_before_backend_selection() {
        let home = tempfile::tempdir().expect("operator home");
        let credentials = home.path().join(".aws");
        std::fs::create_dir(&credentials).expect("credential store");
        let config = ContainmentConfig::new()
            .anchored_at(home.path())
            .allow(&credentials, Operation::Read, Scope::Root)
            .expect("well-formed grant");
        let selected = std::cell::Cell::new(false);

        let error = apply_backend(
            || -> Result<Box<dyn ContainmentBackend>, ContainmentError> {
                selected.set(true);
                Err(ContainmentError::PlatformUnsupported {
                    platform: Platform::Linux,
                    reason: "synthetic unavailable backend".to_string(),
                })
            },
            &config,
            None,
            None,
        )
        .expect_err("the credential floor must refuse the request");

        assert!(!selected.get(), "a refused grant must not select a backend");
        assert!(
            matches!(error, ContainmentError::GrantTooBroad { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("credential"), "{error}");
    }

    #[test]
    fn a_valid_config_still_refuses_an_unavailable_backend() {
        let selected = std::cell::Cell::new(false);
        let error = apply_backend(
            || -> Result<Box<dyn ContainmentBackend>, ContainmentError> {
                selected.set(true);
                Err(ContainmentError::PlatformUnsupported {
                    platform: Platform::Linux,
                    reason: "synthetic unavailable backend".to_string(),
                })
            },
            &ContainmentConfig::new(),
            None,
            None,
        )
        .expect_err("backend selection must still refuse unsupported hosts");

        assert!(
            selected.get(),
            "a valid config must reach backend selection"
        );
        assert!(
            matches!(error, ContainmentError::PlatformUnsupported {
                platform: Platform::Linux,
                ref reason,
            } if reason == "synthetic unavailable backend"),
            "{error}"
        );
    }
}
