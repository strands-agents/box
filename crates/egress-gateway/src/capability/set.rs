//! [`CapabilitySet`] — the credential mutators the interceptor drives on the L7 legs.

use crate::boundary::{InterceptedRequest, InterceptedResponse, Verdict};
use crate::capability::decider::decide_request;
use crate::capability::traits::{CapabilityContext, CapabilityOutcome, EgressCapability};
use crate::error::{ProxyError, Result};

/// The credential mutators the interceptor drives. Built via
/// [`CapabilitySet::builder`](crate::capability::CapabilitySetBuilder).
#[derive(Default)]
pub struct CapabilitySet {
    controls: Vec<Box<dyn EgressCapability>>,
}

impl CapabilitySet {
    /// Start a [`CapabilitySetBuilder`](crate::capability::CapabilitySetBuilder).
    pub fn builder() -> crate::capability::CapabilitySetBuilder {
        crate::capability::CapabilitySetBuilder::new()
    }

    /// Build directly from the boxed controls (used by the builder).
    /// Build directly from boxed capabilities.
    pub(crate) fn from_parts(controls: Vec<Box<dyn EgressCapability>>) -> Self {
        Self { controls }
    }

    /// The number of controls.
    pub fn len(&self) -> usize {
        self.controls.len()
    }

    /// Whether there are no controls — "inject no credentials" (see the type docs: this is *not* an
    /// authorization posture).
    pub fn is_empty(&self) -> bool {
        self.controls.is_empty()
    }

    /// Whether any credential control matches `destination`. Every control here is a credential
    /// mutator, so a match means a secret would be attached. The plain-HTTP path uses this to refuse
    /// a request a credential would fire on — a secret must only ever ride TLS
    /// (docs/design/decisions.md#a-secret-rides-only-tls), never a
    /// cleartext request.
    pub fn matches_any(&self, destination: &credentials::Destination<'_>) -> bool {
        self.controls
            .iter()
            .any(|control| control.pattern().matches(destination))
    }

    /// Evaluate the **request leg** to a [`Verdict`] — deny-overrides. Runs every control
    /// whose pattern matches against the terminated request. An all-abstain leg (the normal
    /// credential-injection path) allows and carries the accumulated mutations — safe because Cedar
    /// already authorized this request at the effect seam.
    pub fn evaluate_request(
        &self,
        req: &mut InterceptedRequest,
        cx: &CapabilityContext,
    ) -> Verdict {
        let mut outcomes: Vec<CapabilityOutcome> = Vec::new();
        for control in &self.controls {
            // Structural pattern prefilter: skip any control whose pattern does not match,
            // once and in one place, so scoping is an invariant of the set rather than a per-impl MUST
            // each `on_request`/`on_response` has to honor by hand. A skipped control contributes no
            // CapabilityOutcome — identical to an `Abstain`. This is what makes an out-of-pattern control unable
            // to spuriously deny/mutate by construction.
            if !control.pattern().matches(&req.target.as_destination()) {
                continue;
            }
            outcomes.push(control.on_request(req, cx));
        }
        decide_request(outcomes)
    }

    /// Evaluate the **response leg** to a [`Verdict`] — likewise deny-overrides:
    /// a response is delivered unless a matching control denies. An out-of-pattern control
    /// is skipped, so no positive allow is required.
    pub fn evaluate_response(
        &self,
        res: &mut InterceptedResponse,
        cx: &CapabilityContext,
    ) -> Verdict {
        let mut outcomes: Vec<CapabilityOutcome> = Vec::new();
        for control in &self.controls {
            // Structural pattern prefilter: skip any control whose pattern does not
            // match the request target (carried on `cx.target`, since the response leg has no target of
            // its own). This is the response-leg twin of the request-leg guard — it prevents an
            // out-of-pattern control's `on_response` from running at all, so e.g. a `CredentialCapability`
            // for a different destination cannot emit a leak-back scrub `SetHeader` that collides with
            // the governing control's under the shared-store wiring.
            if !control.pattern().matches(&cx.target.as_destination()) {
                continue;
            }
            outcomes.push(control.on_response(res, cx));
        }
        decide_request(outcomes)
    }

    /// Config-load fail-closed gate: a hard [`Config`](ProxyError::Config) error, never
    /// a silent downgrade.
    pub fn validate(&self) -> Result<()> {
        // One control per pattern. `DestinationPattern` is `Eq` but not `Hash`, so a pairwise
        // check rather than a set. O(n^2) over a handful of credential routes — trivially small.
        for (i, a) in self.controls.iter().enumerate() {
            for b in &self.controls[i + 1..] {
                if a.pattern() == b.pattern() {
                    return Err(ProxyError::Config(format!(
                        "two credential controls share the same pattern ({:?}); a destination is one \
                         credential authority, so merge them into a single control rather than \
                         registering a duplicate",
                        a.pattern()
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{HeaderMap, InterceptedRequest, Mutation, Target};
    use credentials::DestinationPattern;

    use crate::audit::RequestId;

    fn cx(host: &str) -> CapabilityContext {
        CapabilityContext::new(RequestId::new("t"), 0, Target::new(host, 443))
    }

    /// A fixed-outcome control: like the real credential control, it **abstains** when its pattern does
    /// not match.
    struct StubControl {
        pattern: DestinationPattern,
        outcome: CapabilityOutcome,
    }
    impl StubControl {
        fn new(pattern: &str, outcome: CapabilityOutcome) -> Self {
            Self {
                pattern: DestinationPattern::parse(pattern).unwrap(),
                outcome,
            }
        }
    }
    impl EgressCapability for StubControl {
        fn pattern(&self) -> &DestinationPattern {
            &self.pattern
        }
        fn on_request(
            &self,
            req: &mut InterceptedRequest,
            _cx: &CapabilityContext,
        ) -> CapabilityOutcome {
            if !self.pattern.matches(&req.target.as_destination()) {
                return CapabilityOutcome::none();
            }
            self.outcome.clone()
        }
        fn on_response(
            &self,
            res: &mut InterceptedResponse,
            _cx: &CapabilityContext,
        ) -> CapabilityOutcome {
            let _ = res;
            self.outcome.clone()
        }
    }

    fn http_req(host: &str) -> InterceptedRequest {
        let mut target = Target::new(host, 443);
        target.path = "/".to_string();
        InterceptedRequest {
            target,
            method: Some("GET".to_string()),
            headers: HeaderMap::new(),
            body: Default::default(),
            advisory_note: None,
        }
    }

    fn swap(header: &str, value: &str) -> CapabilityOutcome {
        CapabilityOutcome::applied(vec![Mutation::SetHeader {
            name: header.to_string(),
            value: zeroize::Zeroizing::new(value.to_string()),
        }])
    }

    // --- the set holds no authorization authority ----------------------------

    /// An empty set allows: it means "inject no credentials", not "deny everything". Authorization is
    /// Cedar's at the effect seam, not this type's job.
    #[test]
    fn empty_set_allows_with_no_mutations() {
        let s = CapabilitySet::default();
        assert_eq!(
            s.evaluate_request(&mut http_req("api.example.com"), &cx("api.example.com")),
            Verdict::Allow { mutations: vec![] }
        );
    }

    // --- request leg: mutating abstain allows and carries edits ----

    #[test]
    fn credential_abstain_is_allow_carrying_mutations() {
        let cred: Box<dyn EgressCapability> = Box::new(StubControl::new(
            "*.example.com",
            swap("Authorization", "Bearer real"),
        ));
        let s = CapabilitySet::from_parts(vec![cred]);
        match s.evaluate_request(&mut http_req("api.example.com"), &cx("api.example.com")) {
            Verdict::Allow { mutations } => assert_eq!(mutations.len(), 1),
            v => panic!("expected allow, got {v:?}"),
        }
    }

    /// An out-of-pattern control never runs, so it neither mutates nor denies.
    #[test]
    fn out_of_pattern_control_is_skipped_on_the_request_leg() {
        let cred: Box<dyn EgressCapability> = Box::new(StubControl::new(
            "api.other.com",
            CapabilityOutcome::unavailable("would deny if it ran".to_string()),
        ));
        let s = CapabilitySet::from_parts(vec![cred]);
        assert_eq!(
            s.evaluate_request(&mut http_req("api.example.com"), &cx("api.example.com")),
            Verdict::Allow { mutations: vec![] }
        );
    }

    /// A credential **integrity** failure (phantom mismatch) denies — the one deny a mutator may emit.
    #[test]
    fn integrity_deny_blocks_the_request() {
        let cred: Box<dyn EgressCapability> = Box::new(StubControl::new(
            "*.example.com",
            CapabilityOutcome::unavailable("phantom mismatch".to_string()),
        ));
        let s = CapabilitySet::from_parts(vec![cred]);
        assert!(
            s.evaluate_request(&mut http_req("api.example.com"), &cx("api.example.com"))
                .is_deny()
        );
    }

    // --- response leg stays deny-overrides ------------------------

    #[test]
    fn response_leg_is_deny_overrides() {
        let cred: Box<dyn EgressCapability> =
            Box::new(StubControl::new("*.example.com", CapabilityOutcome::none()));
        let s = CapabilitySet::from_parts(vec![cred]);
        let mut res = InterceptedResponse::http(200, HeaderMap::new(), Default::default());
        assert_eq!(
            s.evaluate_response(&mut res, &cx("api.example.com")),
            Verdict::Allow { mutations: vec![] }
        );
    }

    /// An out-of-pattern control must be skipped on the **response** leg too, so its
    /// scrub cannot collide with the governing control's and turn a delivered response into a deny.
    #[test]
    fn out_of_pattern_response_control_is_skipped_no_collision() {
        let governing: Box<dyn EgressCapability> = Box::new(StubControl::new(
            "api.stripe.com",
            swap("X-Echo", "[REDACTED]"),
        ));
        let off_pattern: Box<dyn EgressCapability> = Box::new(StubControl::new(
            "api.other.com",
            swap("X-Echo", "[REDACTED]"),
        ));
        let s = CapabilitySet::from_parts(vec![governing, off_pattern]);
        let mut res = InterceptedResponse::http(200, HeaderMap::new(), Default::default());
        match s.evaluate_response(&mut res, &cx("api.stripe.com")) {
            Verdict::Allow { mutations } => assert_eq!(
                mutations.len(),
                1,
                "only the in-pattern control's scrub should be emitted"
            ),
            Verdict::Deny { reason } => {
                panic!("a phantom collision from an off-pattern control must not deny: {reason:?}")
            }
        }
    }

    // --- validate() config-load gate --------------------------

    /// One mutator on one pattern validates — plaintext is always available, so the only
    /// remaining rule is one-control-per-pattern.
    #[test]
    fn validate_accepts_one_control_per_pattern() {
        let cred: Box<dyn EgressCapability> =
            Box::new(StubControl::new("*.example.com", CapabilityOutcome::none()));
        let s = CapabilitySet::from_parts(vec![cred]);
        assert!(s.validate().is_ok());
    }

    /// An empty set validates — "inject no credentials" is always satisfiable.
    #[test]
    fn validate_accepts_an_empty_set() {
        let s = CapabilitySet::default();
        assert!(s.validate().is_ok());
        assert!(s.validate().is_ok());
    }

    #[test]
    fn validate_rejects_duplicate_patterns() {
        let a: Box<dyn EgressCapability> =
            Box::new(StubControl::new("*.example.com", CapabilityOutcome::none()));
        let b: Box<dyn EgressCapability> =
            Box::new(StubControl::new("*.example.com", CapabilityOutcome::none()));
        let s = CapabilitySet::from_parts(vec![a, b]);
        assert!(
            s.validate().is_err(),
            "two controls on the same pattern must be a config-load error"
        );
    }

    #[test]
    fn validate_allows_distinct_patterns() {
        let a: Box<dyn EgressCapability> =
            Box::new(StubControl::new("*.example.com", CapabilityOutcome::none()));
        let b: Box<dyn EgressCapability> =
            Box::new(StubControl::new("*.other.com", CapabilityOutcome::none()));
        let s = CapabilitySet::from_parts(vec![a, b]);
        assert!(s.validate().is_ok());
    }
    /// Edits from distinct capabilities accumulate onto one request.
    #[test]
    fn edits_from_distinct_capabilities_accumulate() {
        let a: Box<dyn EgressCapability> =
            Box::new(StubControl::new("*.example.com", swap("X-A", "1")));
        let b: Box<dyn EgressCapability> =
            Box::new(StubControl::new("api.example.com", swap("X-B", "2")));
        let s = CapabilitySet::from_parts(vec![a, b]);
        match s.evaluate_request(&mut http_req("api.example.com"), &cx("api.example.com")) {
            Verdict::Allow { mutations } => assert_eq!(mutations.len(), 2),
            v => panic!("expected allow, got {v:?}"),
        }
    }

    /// An unavailable capability stops the exchange regardless of registration order.
    #[test]
    fn unavailability_is_order_independent() {
        let unavailable = || {
            StubControl::new(
                "*.example.com",
                CapabilityOutcome::unavailable("phantom mismatch"),
            )
        };
        let mutating = || StubControl::new("api.example.com", swap("X-A", "1"));
        for capabilities in [
            vec![
                Box::new(unavailable()) as Box<dyn EgressCapability>,
                Box::new(mutating()),
            ],
            vec![
                Box::new(mutating()) as Box<dyn EgressCapability>,
                Box::new(unavailable()),
            ],
        ] {
            let s = CapabilitySet::from_parts(capabilities);
            assert!(
                s.evaluate_request(&mut http_req("api.example.com"), &cx("api.example.com"))
                    .is_deny(),
                "an unavailable capability must stop the exchange regardless of order"
            );
        }
    }

    /// Two capabilities setting the same target (case-insensitively) fail closed.
    #[test]
    fn conflicting_edits_to_one_target_fail_closed() {
        let a: Box<dyn EgressCapability> = Box::new(StubControl::new(
            "*.example.com",
            swap("Authorization", "one"),
        ));
        let b: Box<dyn EgressCapability> = Box::new(StubControl::new(
            "api.example.com",
            swap("authorization", "two"),
        ));
        let s = CapabilitySet::from_parts(vec![a, b]);
        assert!(
            s.evaluate_request(&mut http_req("api.example.com"), &cx("api.example.com"))
                .is_deny(),
            "conflicting edits to one target must fail closed"
        );
    }

    /// One capability's strip+set of the same header is the swap idiom, not a collision.
    #[test]
    fn strip_then_set_from_one_capability_is_not_a_collision() {
        let swap_idiom = CapabilityOutcome::applied(vec![
            Mutation::StripHeader {
                name: "Authorization".to_string(),
            },
            Mutation::SetHeader {
                name: "Authorization".to_string(),
                value: zeroize::Zeroizing::new("Bearer real".to_string()),
            },
        ]);
        let s =
            CapabilitySet::from_parts(vec![
                Box::new(StubControl::new("*.example.com", swap_idiom))
                    as Box<dyn EgressCapability>,
            ]);
        match s.evaluate_request(&mut http_req("api.example.com"), &cx("api.example.com")) {
            Verdict::Allow { mutations } => assert_eq!(mutations.len(), 2, "both edits survive"),
            v => panic!("the swap idiom must not be a collision, got {v:?}"),
        }
    }
}
