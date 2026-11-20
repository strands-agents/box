//! The response-leg boundary type: [`InterceptedResponse`].

use crate::boundary::HeaderMap;

/// What an interceptor captured for the return (response) leg — a **separate** type from
/// [`InterceptedRequest`](crate::boundary::InterceptedRequest), carrying response-centric fields.
#[derive(Clone)]
pub struct InterceptedResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The response headers.
    pub headers: HeaderMap,
    /// The response body.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for InterceptedResponse {
    /// The shape, never the payload: headers redact per-value and the body prints as its length.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterceptedResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl InterceptedResponse {
    /// Build an `Http`-visibility response from its status, headers, and body.
    pub fn http(status: u16, headers: HeaderMap, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}
