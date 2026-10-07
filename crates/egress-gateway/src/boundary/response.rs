//! The response-leg boundary type: [`InterceptedResponse`].

use crate::boundary::{BodyRef, HeaderMap};

/// What an interceptor captured for the return (response) leg — a **separate** type from
/// [`InterceptedRequest`](crate::boundary::InterceptedRequest), carrying response-centric fields.
#[derive(Clone)]
pub struct InterceptedResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The response headers.
    pub headers: HeaderMap,
    /// The response body (borrowed/streamed).
    pub body: BodyRef,
}

impl std::fmt::Debug for InterceptedResponse {
    /// The shape, never the payload: headers redact per-value and the body prints as its length.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterceptedResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.as_bytes().len())
            .finish()
    }
}

impl InterceptedResponse {
    /// Build an `Http`-visibility response from its status, headers, and body.
    pub fn http(status: u16, headers: HeaderMap, body: BodyRef) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// Whether this is a 3xx redirect (its `Location` re-enters the request path at DNS and
    /// `net:connect` rather than being followed blind).
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    /// The `Location` header value for a redirect, if present.
    pub fn location(&self) -> Option<&str> {
        self.headers.get("location")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_detection_and_location() {
        let mut headers = HeaderMap::new();
        headers.append("Location", "http://169.254.169.254/");
        let res = InterceptedResponse::http(302, headers, BodyRef::Empty);
        assert!(res.is_redirect());
        assert_eq!(res.location(), Some("http://169.254.169.254/"));

        let ok = InterceptedResponse::http(200, HeaderMap::new(), BodyRef::Empty);
        assert!(!ok.is_redirect());
        assert!(ok.location().is_none());
    }
}
