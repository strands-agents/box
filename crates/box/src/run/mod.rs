//! One box's trusted half, alive for one run
//! (docs/design/decisions.md#one-trusted-process-per-box).
//!
//! | Module | Owns |
//! |---|---|
//! | [`hosted`] | this box's `PolicyEngine`, its gateway, its broker, and its resolved secrets |
//! | [`lock`] | which process owns a box, and the record naming it |
//! | [`hardening`] | refusing another process that `PolicyEngine`, the CA key, and the secrets |
//! | [`credential`] | dereferencing a stored locator into a phantom |
//! | [`broker`] | the one socket, its protocol, and both interpreters |
//! | [`configure`] | writing a validated authority to disk, for `run` |
//! | [`contain`] | the ordered path from an argv to a contained process |
//! | [`telemetry`] | this box's own collector and effective decision recorder |
//! | `netns_relay` | splicing the workload's namespace-bound listeners to their sinks (Linux) |

pub(crate) mod broker;
pub(crate) mod configure;
pub(crate) mod contain;
pub(crate) mod credential;
pub(crate) mod hardening;
pub(crate) mod hosted;
pub(crate) mod lock;
#[cfg(feature = "kernel-policy-integration")]
mod native_policy;
#[cfg(target_os = "linux")]
pub(crate) mod netns_relay;
pub(crate) mod telemetry;
