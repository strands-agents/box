//! Credential injection: the edits the gateway applies to a request, and the leak-back scrub of its
//! response.

mod credential;
mod host;

use std::collections::HashMap;

pub use credential::CredentialCapability;
pub use host::{is_bindable_host, normalize_host};

use crate::boundary::{InterceptedRequest, InterceptedResponse, Mutation, MutationTarget, Target};
use crate::error::{ProxyError, Result};

/// What one capability produced for a request or a response: the edits to apply (empty when it
/// does not apply), or the non-secret reason it cannot perform its edit safely, so nothing may
/// egress.
type Outcome = std::result::Result<Vec<Mutation>, String>;

/// The credential capabilities the gateway applies, at most one per destination pattern.
#[derive(Default)]
pub struct CapabilitySet {
    credentials: Vec<CredentialCapability>,
}

impl CapabilitySet {
    /// The set of `credentials`. [`validate`](Self::validate) refuses two on one pattern.
    pub fn new(credentials: Vec<CredentialCapability>) -> Self {
        Self { credentials }
    }

    /// Whether any credential matches `destination`, that is, whether a secret would be attached.
    /// The plain-HTTP path uses this to refuse a request a credential would fire on: a secret must
    /// only ever ride TLS (docs/design/decisions.md#a-secret-rides-only-tls), never a cleartext
    /// request.
    pub fn matches_any(&self, destination: &credentials::Destination<'_>) -> bool {
        self.credentials
            .iter()
            .any(|credential| credential.pattern().matches(destination))
    }

    /// The credentials whose pattern matches `destination`. Only these act, so an off-route
    /// credential never adds an edit that collides with the governing one's.
    fn matching(&self, destination: &credentials::Destination<'_>) -> Vec<&CredentialCapability> {
        self.credentials
            .iter()
            .filter(|credential| credential.pattern().matches(destination))
            .collect()
    }

    /// Apply the edits of every credential that matches `req` in place, or return why the request
    /// must not go out. Cedar already authorized the request at the effect seam, so a request no
    /// credential matches goes out unedited.
    pub fn apply_to_request(
        &self,
        req: &mut InterceptedRequest,
    ) -> std::result::Result<(), String> {
        let outcomes = self
            .matching(&req.target.as_destination())
            .into_iter()
            .map(|credential| credential.on_request(req))
            .collect::<Vec<_>>();
        for mutation in fold(outcomes)? {
            mutation.apply(&mut req.headers, &mut req.target);
        }
        Ok(())
    }

    /// Scrub `res`, the response to a request for `target`, in place, or return why it must not
    /// reach the workload.
    pub fn apply_to_response(
        &self,
        res: &mut InterceptedResponse,
        target: &Target,
    ) -> std::result::Result<(), String> {
        let outcomes = self
            .matching(&target.as_destination())
            .into_iter()
            .map(|credential| credential.on_response(res, target))
            .collect::<Vec<_>>();
        // Response edits only touch headers, so a throwaway target absorbs path and query edits.
        let mut scratch = Target::new("", 0);
        for mutation in fold(outcomes)? {
            mutation.apply(&mut res.headers, &mut scratch);
        }
        Ok(())
    }

    /// Config-load fail-closed gate: a hard [`Config`](ProxyError::Config) error, never a silent
    /// downgrade.
    pub fn validate(&self) -> Result<()> {
        // One credential per pattern. `DestinationPattern` is `Eq` but not `Hash`, so a pairwise
        // check rather than a set. O(n^2) over a handful of credential routes — trivially small.
        for (i, a) in self.credentials.iter().enumerate() {
            for b in &self.credentials[i + 1..] {
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

/// Fold every capability's outcome into the edits to apply. The first unavailable capability
/// refuses the exchange whatever the order, and two edits of one target from different capabilities
/// refuse it as a configuration collision.
fn fold(outcomes: Vec<Outcome>) -> std::result::Result<Vec<Mutation>, String> {
    let mut mutations = Vec::new();
    let mut first_fault = None;
    for outcome in outcomes {
        match outcome {
            Ok(edits) => mutations.extend(edits),
            Err(message) => {
                first_fault.get_or_insert(message);
            }
        }
    }
    // A mechanism failure, not a policy verdict: the boundary could not perform the edit, so
    // nothing egresses.
    if let Some(message) = first_fault {
        return Err(format!("credential denied: {message}"));
    }
    if let Some(target) = first_collision(&mutations) {
        return Err(format!(
            "mutation collision: conflicting mutations to the same target ({target:?}) — a config \
             collision"
        ));
    }
    Ok(mutations)
}

/// The first target key edited by more than one mutation, if any. A strip is skipped, so one
/// capability's strip-then-set swap does not collide with itself.
fn first_collision(mutations: &[Mutation]) -> Option<MutationTarget> {
    let mut set_like: HashMap<MutationTarget, usize> = HashMap::new();
    for m in mutations {
        let is_set_like = !matches!(
            m,
            Mutation::StripHeader { .. } | Mutation::StripQueryParam { .. }
        );
        if is_set_like {
            let count = set_like.entry(m.target_key()).or_insert(0);
            *count += 1;
            if *count > 1 {
                return Some(m.target_key());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use credentials::{Backend, DestinationPattern, InjectMode, RouteSpec, Vault, VaultConfig};
    use zeroize::Zeroizing;

    use super::credential::tests::{env_locator, header_capability};
    use super::*;
    use crate::boundary::HeaderMap;

    fn set(name: &str, value: &str) -> Mutation {
        Mutation::SetHeader {
            name: name.to_string(),
            value: Zeroizing::new(value.to_string()),
        }
    }

    // --- the fold: deny-overrides, edits accumulate, collisions fail closed -----------------

    #[test]
    fn edits_are_carried_and_an_empty_fold_allows() {
        assert_eq!(
            fold(vec![Ok(vec![set("Authorization", "Bearer real")])])
                .unwrap()
                .len(),
            1
        );
        // No credential matched. Cedar already authorized this request at the effect seam; an empty
        // fold has nothing to add and nothing to deny.
        assert!(fold(Vec::new()).unwrap().is_empty());
    }

    #[test]
    fn an_unavailable_capability_refuses_regardless_of_order() {
        let denying = || Err("phantom mismatch".to_string());
        let editing = || Ok(vec![set("X-A", "1")]);
        for outcomes in [vec![denying(), editing()], vec![editing(), denying()]] {
            assert_eq!(
                fold(outcomes).unwrap_err(),
                "credential denied: phantom mismatch"
            );
        }
    }

    #[test]
    fn edits_from_distinct_capabilities_accumulate() {
        let edits = fold(vec![Ok(vec![set("X-A", "1")]), Ok(vec![set("X-B", "2")])]).unwrap();
        assert_eq!(edits.len(), 2);
    }

    #[test]
    fn strip_then_set_same_header_is_not_a_collision() {
        // The credential swap idiom (one capability emits strip + set of Authorization) is fine.
        let swap = vec![
            Mutation::StripHeader {
                name: "Authorization".to_string(),
            },
            set("Authorization", "Bearer real"),
        ];
        assert_eq!(fold(vec![Ok(swap)]).unwrap().len(), 2, "both edits survive");
    }

    #[test]
    fn two_capabilities_setting_same_header_collide() {
        // Two capabilities fighting over one header is a misconfiguration → fail closed
        // (case-insensitive).
        let refused = fold(vec![
            Ok(vec![set("Authorization", "one")]),
            Ok(vec![set("authorization", "two")]),
        ]);
        assert!(refused.unwrap_err().starts_with("mutation collision: "));
    }

    /// The `QueryParam` swap idiom from ONE capability must not self-collide.
    #[test]
    fn strip_then_add_query_param_from_one_capability_is_not_a_collision() {
        let swap = vec![
            Mutation::StripQueryParam {
                name: "api_key".to_string(),
            },
            Mutation::AddQueryParam {
                name: "api_key".to_string(),
                value: Zeroizing::new("wk_live_real".to_string()),
            },
        ];
        assert_eq!(fold(vec![Ok(swap)]).unwrap().len(), 2, "both edits survive");
    }

    /// Two capabilities adding the same parameter, or rewriting the path, still collide.
    #[test]
    fn two_capabilities_adding_one_query_param_or_path_collide() {
        let add = |value: &str| Mutation::AddQueryParam {
            name: "api_key".to_string(),
            value: Zeroizing::new(value.to_string()),
        };
        assert!(fold(vec![Ok(vec![add("one")]), Ok(vec![add("two")])]).is_err());
        let rewrite = |path: &str| Mutation::RewritePath {
            path: Zeroizing::new(path.to_string()),
        };
        assert!(fold(vec![Ok(vec![rewrite("/a")]), Ok(vec![rewrite("/b")])]).is_err());
    }

    // --- the set over real credentials --------------------------------------------------

    fn request(host: &str, headers: HeaderMap) -> InterceptedRequest {
        InterceptedRequest {
            target: Target::new(host, 443),
            method: "GET".to_string(),
            headers,
            body: Vec::new(),
            advisory_note: None,
        }
    }

    /// An empty set means "inject no credentials", not "deny everything": authorization is Cedar's.
    #[test]
    fn an_empty_set_leaves_the_request_alone() {
        let mut req = request("api.example.com", HeaderMap::new());
        assert!(CapabilitySet::default().apply_to_request(&mut req).is_ok());
        assert!(req.headers.is_empty());
    }

    /// One capability per host over one shared vault, so each one's vault also holds the other
    /// host's route. Returns them with the phantom each route minted.
    fn shared_vault(hosts: &[&str], secret: &str) -> (Vec<CredentialCapability>, Vec<String>) {
        let pattern = |host: &str| DestinationPattern::parse(host).unwrap();
        let mut config = VaultConfig::new(Backend::local(), "tenant");
        for host in hosts {
            let header = InjectMode::header("Bearer {}".to_string(), None).unwrap();
            config = config.route(RouteSpec::opaque(
                pattern(host),
                env_locator(secret),
                header,
            ));
        }
        let opened = Vault::open(config).unwrap();
        let phantoms = opened.phantoms().iter().map(|p| p.token().to_string());
        let phantoms = phantoms.collect();
        let vault = Arc::new(opened.into_vault());
        let capabilities = hosts
            .iter()
            .map(|host| CredentialCapability::new(pattern(host), vault.clone()))
            .collect();
        (capabilities, phantoms)
    }

    /// Only the credential whose pattern matches applies, and its edits land on the request. Over a
    /// shared vault, another credential would attach the same secret again and collide.
    #[test]
    fn only_the_matching_credential_applies() {
        let (credentials, phantoms) = shared_vault(&["api.github.com", "api.stripe.com"], "real");
        let set = CapabilitySet::new(credentials);
        let mut headers = HeaderMap::new();
        headers.append("Authorization", format!("Bearer {}", phantoms[0]));
        let mut req = request("api.github.com", headers);

        set.apply_to_request(&mut req).unwrap();

        assert_eq!(req.headers.get("authorization"), Some("Bearer real"));
    }

    /// A response is scrubbed only by the credential its request's target matches. Over a shared
    /// vault, another credential would emit a second scrub that collides and refuses the response.
    /// The scrub lands on both the headers and the body.
    #[test]
    fn only_the_matching_credential_scrubs_a_response() {
        let (credentials, _) = shared_vault(&["api.github.com", "api.stripe.com"], "real-secret");
        let set = CapabilitySet::new(credentials);
        let mut headers = HeaderMap::new();
        headers.append("X-Echo", "real-secret");
        let mut res = InterceptedResponse::http(200, headers, b"real-secret".to_vec());

        set.apply_to_response(&mut res, &Target::new("api.github.com", 443))
            .unwrap();

        assert_eq!(res.headers.get("x-echo"), Some("[REDACTED]"));
        assert_eq!(res.body, b"[REDACTED]");
    }

    #[test]
    fn validate_refuses_two_credentials_on_one_pattern() {
        let one = || header_capability("*.example.com", "secret").0;
        assert!(CapabilitySet::default().validate().is_ok());
        assert!(CapabilitySet::new(vec![one()]).validate().is_ok());
        assert!(
            CapabilitySet::new(vec![one(), header_capability("*.other.com", "s").0])
                .validate()
                .is_ok()
        );
        assert!(
            CapabilitySet::new(vec![one(), one()]).validate().is_err(),
            "two credentials on the same pattern must be a config-load error"
        );
    }
}
