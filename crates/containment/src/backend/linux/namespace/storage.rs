//! Bounded mount observations and private framing for protected storage admission.
//!
//! These foundations are exercised in the library tests until the receiver supplies a
//! production caller. They do not enable storage configuration or change workload mounts.

use super::apply_failure;
use crate::ContainmentError;

mod mountinfo;
mod transport;

const CONTROL_LIMIT: usize = 1024 * 1024;

fn failure(reason: impl Into<String>) -> ContainmentError {
    apply_failure(format!("storage admission: {}", reason.into()))
}
