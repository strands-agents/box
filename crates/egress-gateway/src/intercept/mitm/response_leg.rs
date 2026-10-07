//! The response-leg evaluate → apply decision.

use crate::boundary::{InterceptedResponse, Mutation, Verdict};
use crate::capability::{CapabilityContext, CapabilitySet};

/// The result of evaluating + applying the response leg.
pub(super) enum ResponseDecision {
    /// Return the (possibly scrubbed) response to the workload.
    Return,
    /// Block the response with this reason (a control denial or a limit breach).
    Block(crate::boundary::DenyReason),
    /// The response is a 3xx redirect to a new host; the adapter must re-enter the request path at
    /// DNS and `net:connect` for `location` rather than follow it blind.
    RedirectReentry(String),
}

/// Evaluate `res` against `controls`, applying any allowed mutations in place, and return the
/// return/block/redirect decision.
pub(super) fn evaluate_and_apply(
    controls: &CapabilitySet,
    res: &mut InterceptedResponse,
    cx: &CapabilityContext,
) -> ResponseDecision {
    match controls.evaluate_response(res, cx) {
        Verdict::Allow { mutations } => {
            apply_all(mutations, res);
            // Redirect classification happens only after every response control and mutation. This
            // guarantees leakback scrubbing precedes both redirect release and client re-entry.
            if res.is_redirect()
                && let Some(location) = res.location()
                && redirects_to_new_host(location, &cx.target.host)
            {
                ResponseDecision::RedirectReentry(location.to_string())
            } else {
                ResponseDecision::Return
            }
        }
        Verdict::Deny { reason } => ResponseDecision::Block(reason),
    }
}

/// Whether `location` points at a host different from `current_host` (an absolute-URL redirect to a
/// new authority). A relative redirect (no scheme/authority) stays on the same host.
fn redirects_to_new_host(location: &str, current_host: &str) -> bool {
    // Absolute URL: scheme://authority/... — extract the authority's host.
    let after_scheme = match location.split_once("://") {
        Some((_, rest)) => rest,
        None => return false, // relative redirect → same host
    };
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
    !host.eq_ignore_ascii_case(current_host) && !host.is_empty()
}

/// Apply every response mutation (header redactions from leak-back scrubbing, etc.) in place.
/// Consumes the owned `Vec` and moves each mutation's value in (no secret copy).
fn apply_all(mutations: Vec<Mutation>, res: &mut InterceptedResponse) {
    // Response mutations only touch headers; the target is irrelevant on the response leg, so a
    // throwaway target absorbs the (unused) path/query edits.
    let mut scratch = crate::boundary::Target::new("", 0);
    for m in mutations {
        m.into_apply(&mut res.headers, &mut scratch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{BodyRef, HeaderMap, InterceptedResponse, Target};
    use crate::capability::{CapabilityOutcome, CapabilitySet, EgressCapability};
    use credentials::DestinationPattern;

    use crate::audit::RequestId;

    fn cx(host: &str) -> CapabilityContext {
        CapabilityContext::new(RequestId::new("t"), 0, Target::new(host, 443))
    }

    #[test]
    fn cross_host_redirect_triggers_reentry() {
        let mut headers = HeaderMap::new();
        headers.append("Location", "http://169.254.169.254/latest/meta-data");
        let mut res = InterceptedResponse::http(302, headers, BodyRef::Empty);
        let set = CapabilitySet::default();
        match evaluate_and_apply(&set, &mut res, &cx("api.example.com")) {
            ResponseDecision::RedirectReentry(loc) => {
                assert!(loc.contains("169.254.169.254"));
            }
            _ => panic!("expected redirect re-entry"),
        }
    }

    #[test]
    fn response_controls_run_before_cross_host_redirect_classification() {
        struct ScrubControl {
            pattern: DestinationPattern,
        }

        impl EgressCapability for ScrubControl {
            fn pattern(&self) -> &DestinationPattern {
                &self.pattern
            }

            fn on_request(
                &self,
                _req: &mut crate::boundary::InterceptedRequest,
                _cx: &CapabilityContext,
            ) -> CapabilityOutcome {
                CapabilityOutcome::none()
            }

            fn on_response(
                &self,
                res: &mut InterceptedResponse,
                _cx: &CapabilityContext,
            ) -> CapabilityOutcome {
                res.body = BodyRef::Bytes(b"[REDACTED]".to_vec());
                CapabilityOutcome::applied(vec![Mutation::SetHeader {
                    name: "X-Echo".to_string(),
                    value: zeroize::Zeroizing::new("[REDACTED]".to_string()),
                }])
            }
        }

        let mut headers = HeaderMap::new();
        headers.append("Location", "https://other.example/v2");
        headers.append("X-Echo", "secret");
        let mut res = InterceptedResponse::http(302, headers, BodyRef::Bytes(b"secret".to_vec()));
        let set = CapabilitySet::from_parts(vec![Box::new(ScrubControl {
            pattern: DestinationPattern::parse("api.example.com").unwrap(),
        })]);

        assert!(matches!(
            evaluate_and_apply(&set, &mut res, &cx("api.example.com")),
            ResponseDecision::RedirectReentry(_)
        ));
        assert_eq!(res.headers.get("x-echo"), Some("[REDACTED]"));
        assert_eq!(res.body.as_bytes(), b"[REDACTED]");
    }

    #[test]
    fn same_host_redirect_returns_normally() {
        let mut headers = HeaderMap::new();
        headers.append("Location", "https://api.example.com/v2/x");
        let mut res = InterceptedResponse::http(301, headers, BodyRef::Empty);
        let set = CapabilitySet::default();
        assert!(matches!(
            evaluate_and_apply(&set, &mut res, &cx("api.example.com")),
            ResponseDecision::Return
        ));
    }

    #[test]
    fn relative_redirect_stays_same_host() {
        assert!(!redirects_to_new_host("/v2/x", "api.example.com"));
        assert!(redirects_to_new_host(
            "https://evil.example/x",
            "api.example.com"
        ));
        assert!(!redirects_to_new_host(
            "https://api.example.com/x",
            "api.example.com"
        ));
    }
}
