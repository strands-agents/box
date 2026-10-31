//! The boundary interface — the narrow, normalized, interception-agnostic contract where Part A
//! (interception) meets Part B (functionality).

mod request;
mod response;
mod verdict;

pub use request::{HeaderMap, InterceptedRequest, Target};
pub use response::InterceptedResponse;
pub(crate) use verdict::hex_value;
pub use verdict::{Mutation, MutationTarget};
