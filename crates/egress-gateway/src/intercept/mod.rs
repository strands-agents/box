//! Part A — interception. The [`Interceptor`] port and its v1 [`mitm`] adapter.

mod port;

#[cfg(feature = "tls-intercept")]
mod mitm;

pub use port::Interceptor;

#[cfg(feature = "tls-intercept")]
pub use mitm::{MitmConfig, MitmHandle, MitmInterceptor, ResponseLimits};
