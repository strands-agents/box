//! The Strands box's inbound relay.
//!
//! | Part | Role |
//! |---|---|
//! | [`Source`] | where callers arrive |
//! | [`Workload`] | the contained workload's port, and how it is reached |
//! | [`Ingress`] | the relay between the two |

#![warn(missing_docs, unreachable_pub)]

mod config;
mod error;
mod relay;
mod source;
mod workload;

pub use config::IngressConfig;
pub use error::IngressError;
pub use relay::Ingress;
pub use source::Source;
pub use workload::Workload;
