//! Error types for the containment crate.

use crate::platform::Platform;
use std::path::PathBuf;

/// Errors that can occur during containment operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ContainmentError {
    /// The backend cannot isolate a write grant from content reads.
    #[error("backend '{backend}' cannot enforce write-only access at {}", path.display())]
    WriteOnlyUnsupported {
        /// The writable path without sufficient read authority.
        path: PathBuf,
        /// The backend that requires read authority.
        backend: String,
    },

    /// Requested mechanism not available on this platform.
    #[error("mechanism '{requested}' is not available on {platform:?}")]
    MechanismUnavailable {
        /// The mechanism that was requested.
        requested: String,
        /// The detected platform.
        platform: Platform,
    },

    /// Backend failed to apply enforcement.
    #[error("backend '{backend}' failed to apply: {reason}")]
    ApplyFailed {
        /// Which backend failed.
        backend: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Config contains a capability the backend cannot enforce.
    #[error("backend '{backend}' cannot enforce capability '{capability}'")]
    UnsupportedCapability {
        /// The unsupported capability.
        capability: String,
        /// The backend that rejected it.
        backend: String,
    },

    /// Platform unsupported with structured detail.
    #[error("platform {platform:?} unsupported: {reason}")]
    PlatformUnsupported {
        /// The unsupported platform.
        platform: Platform,
        /// Human-readable reason.
        reason: String,
    },

    /// A caller-supplied path (e.g. to [`crate::ContainmentConfig::allow`])
    /// does not exist.
    #[error("path does not exist: {}", .0.display())]
    PathNotFound(PathBuf),

    /// A directory was required but the path is a file.
    #[error("expected a directory but got a file: {}", .0.display())]
    ExpectedDirectory(PathBuf),

    /// A file was required but the path is a directory.
    #[error("expected a file but got a directory: {}", .0.display())]
    ExpectedFile(PathBuf),

    /// Port zero is not a concrete proxy, bind, or localhost service port.
    #[error("{field} port {port} is invalid; expected a port in 1..=65535")]
    InvalidPort {
        /// Config field containing the invalid port.
        field: &'static str,
        /// Rejected port value.
        port: u16,
    },

    /// `std::fs::canonicalize` failed for a reason other than absence.
    #[error("failed to canonicalize path '{}': {source}", path.display())]
    PathCanonicalization {
        /// The path that failed to canonicalize.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// A caller-supplied SBPL rule failed validation (malformed S-expression
    /// or a whole-containment-defeating allow).
    #[error("invalid platform rule: {0}")]
    InvalidPlatformRule(String),

    /// A serialized [`crate::ContainmentConfig`] failed conversion or revalidation due to malformed
    /// JSON, canonical path drift, or an invalid platform rule.
    #[error("containment config validation failed: {0}")]
    ConfigValidation(String),

    /// Two grants that are individually expressible combine into more authority
    /// than either states.
    #[error("conflicting grants: {reason}")]
    ConflictingGrants {
        /// Which two grants conflict, and what the union would have permitted.
        reason: String,
    },

    /// A grant names a path so broad that it would authorize an entire tree the
    /// caller cannot have meant to hand over.
    #[error("grant is too broad to be authorized: {} ({reason})", path.display())]
    GrantTooBroad {
        /// The offending path.
        path: PathBuf,
        /// Why this path is refused.
        reason: &'static str,
    },
}

impl ContainmentError {
    /// The class of the floor row that refused a grant, or `None` for any other error.
    pub fn forbidden_class(&self) -> Option<crate::ForbiddenClass> {
        match self {
            Self::GrantTooBroad { reason, .. } => crate::ForbiddenClass::ALL
                .into_iter()
                .find(|class| class.reason() == *reason),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ForbiddenClass;

    #[test]
    fn a_floor_refusal_names_its_class_and_any_other_refusal_names_none() {
        for class in ForbiddenClass::ALL {
            let refused = ContainmentError::GrantTooBroad {
                path: PathBuf::from("/a"),
                reason: class.reason(),
            };
            assert_eq!(refused.forbidden_class(), Some(class), "{class:?}");
        }
        let box_state = ContainmentError::GrantTooBroad {
            path: PathBuf::from("/a"),
            reason: "a reason no floor row states",
        };
        assert_eq!(box_state.forbidden_class(), None);
        assert_eq!(
            ContainmentError::PathNotFound(PathBuf::from("/a")).forbidden_class(),
            None
        );
    }

    #[test]
    fn every_class_is_listed_once_and_states_its_own_reason() {
        let position = |class: ForbiddenClass| match class {
            ForbiddenClass::WholeFilesystem => 0,
            ForbiddenClass::HomeNamespace => 1,
            ForbiddenClass::SystemTree => 2,
            ForbiddenClass::LoaderDirectory => 3,
            ForbiddenClass::CredentialStore => 4,
            ForbiddenClass::PasswordDatabase => 5,
            ForbiddenClass::MachineCredential => 6,
            ForbiddenClass::PrivilegeConfiguration => 7,
        };
        for (index, class) in ForbiddenClass::ALL.into_iter().enumerate() {
            assert_eq!(position(class), index, "{class:?}");
            for other in &ForbiddenClass::ALL[index + 1..] {
                assert_ne!(class.reason(), other.reason(), "{class:?} and {other:?}");
            }
        }
    }
}
