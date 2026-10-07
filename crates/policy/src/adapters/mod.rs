//! Adapters from the policy facade to each enforcement point's own effect seam.
//!
//! | | `egress` | `shell` | `script` |
//! |---|---|---|---|
//! | boundary | egress-proxy | Strands Shell | Monty |
//! | feature | `egress-adapter` | `shell-adapter` | `script-adapter` |
//! | actions | `net:connect`, `http:request` | `shell:exec`, `fs:*` | `fs:*` |
//! | refusal | `io::Error` | `io::Error` | a Python exception |
//!
//! The egress row names two actions because the release of a reply raises no decision. The
//! reply reaches history once, as `output.status` on the request's `http:request::response`.
//!
//! [`Request`]: crate::Request
//! [`PolicyEngine::decide`]: crate::PolicyEngine::decide
//! [`PolicyEngine::record`]: crate::PolicyEngine::record
//! [`Decision::Allow`]: crate::Decision::Allow

#[cfg(feature = "egress-adapter")]
pub(crate) mod egress;
#[cfg(feature = "script-adapter")]
pub(crate) mod script;
#[cfg(feature = "shell-adapter")]
pub(crate) mod shell;
