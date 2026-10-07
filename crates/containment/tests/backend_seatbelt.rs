//! Framework-level support-gate test for the private Seatbelt backend.
//!
//! Complements `enforce_macos.rs` (which drives the probe subprocess for real
//! kernel enforcement) by checking the host-support gate.
//!
//! The macOS-only apply path is exercised by `enforce_macos.rs` and by the
//! probe binary spawned there; this file NEVER calls `apply` in libtest (which
//! would contain the multi-threaded test process irreversibly).
//!
//! The concrete backend and backend trait remain crate-private.
#![cfg(target_os = "macos")]

use containment::test_support::seatbelt_supports_current_host;

#[test]
fn seatbelt_support_gate_accepts_macos() {
    assert!(seatbelt_supports_current_host());
}
