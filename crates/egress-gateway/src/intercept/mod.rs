//! The [`mitm`] adapter: the egress gateway.

#[cfg(feature = "tls-intercept")]
pub(crate) mod mitm;

#[cfg(feature = "tls-intercept")]
pub use mitm::{MitmConfig, MitmHandle, MitmInterceptor, ResponseLimits};
