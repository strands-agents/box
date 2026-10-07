//! The boundary interface — the narrow, normalized, interception-agnostic contract where Part A
//! (interception) meets Part B (functionality).

mod request;
mod response;
mod verdict;

pub use request::{BodyRef, HeaderMap, InterceptedRequest, Target};
pub use response::InterceptedResponse;
pub use verdict::{DenyReason, Mutation, MutationTarget, Verdict};
