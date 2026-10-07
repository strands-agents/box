//! Test doubles for the containment framework, gated behind the `test-support`
//! cargo feature.

use crate::ContainmentConfig;
use crate::backend::{ContainmentBackend, SupportInfo};
use crate::error::ContainmentError;
use crate::platform::{Platform, PlatformInfo};
use std::sync::{Arc, Mutex};

/// Render a Seatbelt profile without applying or live-validating it.
pub fn generate_seatbelt_profile(config: &ContainmentConfig) -> Result<String, ContainmentError> {
    // The floors first, in the order `apply` runs them: they refuse a grant *set* that combines into
    // more than any member states, and a caller of this helper is asking what a real box would do.
    crate::floors::require_all(config)?;
    crate::backend::macos::seatbelt::render_profile(config)
}

/// The passwd database's home for this uid, which the floor anchors its `~/` rows at.
///
/// Exposed so a test can name a path the floor protects without a declared home, and therefore tell
/// an added anchor from a replaced one.
#[must_use]
pub fn passwd_home_for_test() -> Option<std::path::PathBuf> {
    crate::floors::operator_home()
        .ok()
        .map(std::path::Path::to_path_buf)
}

/// Every name the operator's home answers to, as the floor derives them.
pub fn operator_home_spellings() -> Result<Vec<std::path::PathBuf>, ContainmentError> {
    crate::floors::operator_home_spellings(None)
}

/// Every credential store the floor protects, at each spelling a lookup can name it by.
pub fn credential_store_paths() -> Result<Vec<std::path::PathBuf>, ContainmentError> {
    crate::floors::credential_store_paths(None)
}

/// The `file-write*` leaves a write root grants, so an absence assertion covers all of them.
///
/// Exposed because a hand-copied list silently stops covering a leaf the renderer adds, and the one
/// test that bounds write authority on a non-writable path is an absence assertion. Ungated, like
/// `generate_seatbelt_profile` above and for the same reason: `profile_read_write_roots.rs` runs on
/// every platform, so a `target_os` gate here breaks the Linux build.
#[must_use]
pub fn write_root_leaves() -> &'static [&'static str] {
    &crate::backend::macos::seatbelt::WRITE_ROOT_LEAVES
}

/// Whether the private Seatbelt backend supports the current macOS host.
#[cfg(target_os = "macos")]
#[must_use]
pub fn seatbelt_supports_current_host() -> bool {
    crate::backend::macos::seatbelt::SeatbeltBackend::new()
        .support_info()
        .is_supported
}

/// Verbatim record of how the private apply pipeline was exercised in a test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedCall {
    /// The private backend apply hook was invoked.
    Apply,
}

/// Private backend used by crate-internal facade tests and [`MockContainment`].
#[derive(Debug)]
pub(crate) struct MockBackend {
    inner: Arc<MockInner>,
}

#[derive(Debug)]
struct MockInner {
    support: SupportInfo,
    records: Mutex<Vec<RecordedCall>>,
    /// If `Some`, `apply` returns `Err(ApplyFailed { backend, reason })` using the stored reason.
    apply_failure: Mutex<Option<String>>,
}

impl MockBackend {
    /// Construct a mock backend that succeeds on `apply`.
    #[must_use]
    pub(crate) fn new(support: SupportInfo) -> Self {
        Self {
            inner: Arc::new(MockInner {
                support,
                records: Mutex::new(Vec::new()),
                apply_failure: Mutex::new(None),
            }),
        }
    }

    /// Convenience: build a mock reporting a fully-supported macOS Seatbelt
    /// backend. The most common shape for tests.
    #[must_use]
    pub(crate) fn macos_seatbelt() -> Self {
        Self::new(SupportInfo {
            is_supported: true,
            platform: Platform::MacOS,
            mechanism: "seatbelt".to_string(),
            details: "MockBackend simulating macOS Seatbelt".to_string(),
        })
    }
}

impl ContainmentBackend for MockBackend {
    /// A mock enforces nothing, so it refuses nothing.
    fn validate_config(&self, _config: &ContainmentConfig) -> Result<(), ContainmentError> {
        Ok(())
    }

    fn apply(
        &self,
        _config: &ContainmentConfig,
        _egress_handoff: Option<&std::os::unix::net::UnixStream>,
        _confirm_fd: Option<std::os::fd::RawFd>,
    ) -> Result<(), ContainmentError> {
        self.inner
            .records
            .lock()
            .expect("mock lock")
            .push(RecordedCall::Apply);
        if let Some(reason) = self.inner.apply_failure.lock().expect("mock lock").clone() {
            return Err(ContainmentError::ApplyFailed {
                backend: self.inner.support.mechanism.clone(),
                reason,
            });
        }
        Ok(())
    }

    fn support_info(&self) -> SupportInfo {
        self.inner.support.clone()
    }
}

/// Test-only facade backed by a private, deterministic mock backend.
#[derive(Debug)]
pub struct MockContainment {
    backend: Box<dyn ContainmentBackend>,
    inner: Arc<MockInner>,
}

impl MockContainment {
    /// Construct a mock of a supported macOS containment path.
    #[must_use]
    pub fn macos_seatbelt() -> Self {
        let mock = MockBackend::macos_seatbelt();
        let inner = Arc::clone(&mock.inner);
        let platform_info = PlatformInfo {
            platform: Platform::MacOS,
            details: "test_support synthetic macOS".to_string(),
        };
        let backend = crate::facade::checked_backend(&platform_info, Box::new(mock))
            .expect("mock backend selection");
        Self { backend, inner }
    }

    /// Make subsequent applies fail with [`ContainmentError::ApplyFailed`].
    pub fn fail_apply(&self, reason: impl Into<String>) {
        *self.inner.apply_failure.lock().expect("mock lock") = Some(reason.into());
    }

    /// Exercise the same validate-then-apply pipeline as the public facade.
    pub fn apply(&self, config: &ContainmentConfig) -> Result<(), ContainmentError> {
        // Test harnesses do not exercise the egress handoff (the transport is proven in
        // `backend::linux::namespace::netns`'s own kernel test) nor the exec-confirm fd.
        crate::facade::apply_backend(|| Ok(self.backend.as_ref()), config, None, None)
    }

    /// Snapshot every backend apply call in order.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.inner.records.lock().expect("mock lock").clone()
    }
}
