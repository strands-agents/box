//! Outbound enforcement for the Strands box.

#![warn(missing_docs, unreachable_pub)]

mod audit;
mod boundary;
mod capability;
mod effect;
mod error;
mod intercept;
mod mcp;
mod seams;

pub use audit::{
    Decision as AuditDecision, EgressDecision, NetworkAuditEvent, RequestId, SharedAuditLog,
};
pub use boundary::{
    BodyRef, DenyReason, HeaderMap, InterceptedRequest, InterceptedResponse, Mutation,
    MutationTarget, Target, Verdict,
};
pub use capability::{
    CapabilityContext, CapabilityFault, CapabilityOutcome, CapabilitySet, CapabilitySetBuilder,
    CredentialCapability,
};
pub use effect::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, McpFrame, McpListReply,
};
pub use error::{PROXY_ORIGIN_HEADER, PROXY_ORIGIN_VALUE, ProxyError, Result};
pub use intercept::Interceptor;
pub use mcp::{McpTarget, McpTargetIdentity, canonicalize_mcp_frame, mcp_denial_response};
pub use seams::{Emitter, StubEmitter};

#[cfg(feature = "tls-intercept")]
pub use intercept::{MitmConfig, MitmHandle, MitmInterceptor, ResponseLimits};
