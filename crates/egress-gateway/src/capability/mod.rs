//! Credential injection: the edits the gateway applies to a request, and the leak-back scrub of its
//! response.

mod credential;
mod host;

use std::collections::HashMap;

use credentials::ResponseRedactor;

pub use credential::CredentialCapability;
pub use host::{is_bindable_host, normalize_host};

use crate::boundary::{InterceptedRequest, InterceptedResponse, Mutation, MutationTarget, Target};
use crate::error::{ProxyError, Result};
#[cfg(feature = "tls-intercept")]
use {crate::boundary::HeaderMap, zeroize::Zeroizing};
// `BackendDial` lives in the `tls-intercept`-gated `intercept::mitm` module, and the backend
// signature pass that uses it runs only there, so keep this socket-free module buildable with
// `--no-default-features`.
#[cfg(feature = "tls-intercept")]
use crate::intercept::mitm::BackendDial;

/// What one capability produced for a request or a response: the edits to apply (empty when it
/// does not apply), or the non-secret reason it cannot perform its edit safely, so nothing may
/// egress.
type Outcome = std::result::Result<Vec<Mutation>, String>;

/// Whether the caller can retain the response scrubbers from the attachments it applies.
#[derive(Clone, Copy)]
enum RequestMode {
    Unpaired,
    #[cfg(feature = "tls-intercept")]
    Paired,
}

/// The response checks from the capabilities matched by this exchange's request.
pub(crate) enum ExchangeResponse {
    Unmatched,
    Matched(Vec<ResponseRedactor>),
}

impl ExchangeResponse {
    fn capture(&mut self, redactor: Option<ResponseRedactor>) {
        match self {
            Self::Unmatched => *self = Self::Matched(redactor.into_iter().collect()),
            Self::Matched(redactors) => redactors.extend(redactor),
        }
    }

    /// Apply the header checks and return the body checks from this request's attachments.
    #[cfg(feature = "tls-intercept")]
    pub(crate) fn controls(
        self,
        headers: &mut HeaderMap,
    ) -> std::result::Result<ResponseControls, String> {
        let Self::Matched(redactors) = self else {
            return Ok(ResponseControls::default());
        };
        let requires_empty_body = credential::content_encoding(headers).is_some();
        let outcomes = redactors
            .iter()
            .map(|redactor| {
                Ok(headers
                    .iter()
                    .filter_map(|(name, value)| {
                        redactor
                            .redact_header(value)
                            .map(|value| Mutation::SetHeader {
                                name: name.to_string(),
                                value: Zeroizing::new(value),
                            })
                    })
                    .collect())
            })
            .collect();
        let mut scratch = Target::new("", 0);
        for mutation in fold(outcomes)? {
            mutation.apply(headers, &mut scratch);
        }
        Ok(ResponseControls {
            redactors,
            requires_empty_body,
        })
    }
}

/// The host half of `pattern` as written, without its port or path, so a wildcard keeps its `*`.
#[cfg(feature = "tls-intercept")]
fn written_host(pattern: &credentials::DestinationPattern) -> String {
    let written = pattern.as_written();
    let end = written.find([':', '/']).unwrap_or(written.len());
    written[..end].to_string()
}

/// The body checks retained after response-header edits have passed the capability fold.
#[cfg(feature = "tls-intercept")]
#[derive(Debug, Default)]
pub(crate) struct ResponseControls {
    pub(crate) redactors: Vec<credentials::ResponseRedactor>,
    pub(crate) requires_empty_body: bool,
}

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

    /// Whether some credential matches `destination` and each match names `host` exactly.
    #[cfg(feature = "tls-intercept")]
    pub(crate) fn every_match_names_host(
        &self,
        destination: &credentials::Destination<'_>,
        host: &str,
    ) -> bool {
        let matching = self.matching(destination);
        !matching.is_empty()
            && matching
                .iter()
                .all(|credential| written_host(credential.pattern()) == host)
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
    ///
    /// Rotating credentials require the gateway's paired request and response legs and are refused
    /// by this method before the request edits are applied.
    pub fn apply_to_request(
        &self,
        req: &mut InterceptedRequest,
    ) -> std::result::Result<(), String> {
        self.apply_request_edits(req, RequestMode::Unpaired)
            .map(|_| ())
    }

    /// Apply the request edits and retain the response checks from the matched capabilities.
    #[cfg(feature = "tls-intercept")]
    pub(crate) fn apply_exchange_request(
        &self,
        req: &mut InterceptedRequest,
    ) -> std::result::Result<ExchangeResponse, String> {
        self.apply_request_edits(req, RequestMode::Paired)
    }

    fn apply_request_edits(
        &self,
        req: &mut InterceptedRequest,
        mode: RequestMode,
    ) -> std::result::Result<ExchangeResponse, String> {
        let mut response = ExchangeResponse::Unmatched;
        let mut advisory = None;
        let outcomes = self
            .matching(&req.target.as_destination())
            .into_iter()
            .map(|credential| {
                let edits = credential.on_request(req, mode)?;
                response.capture(edits.redactor);
                if let Some(reason) = edits.advisory {
                    advisory = Some(reason);
                }
                Ok(edits.mutations)
            })
            .collect::<Vec<_>>();
        for mutation in fold(outcomes)? {
            mutation.apply(&mut req.headers, &mut req.target);
        }
        // Each attachment forces `accept-encoding`, so a second one collides in the fold above and
        // at most one advisory note reaches here.
        if advisory.is_some() {
            req.advisory_note = advisory;
        }
        Ok(response)
    }

    /// Sign a re-routed request for its backend, AFTER the gateway has rewritten the `Host` to the
    /// backend and built the forwarded target. Finds the capability governing `original` (the backend
    /// vault, registered under the original destination) and applies the SigV4 edits its signed route
    /// produces over the BACKEND host and `fwd_target`. A backend with no signing auth produces no
    /// edits (its routes are keyed on the original destination, which the backend `Outbound` does not
    /// match), so this is a no-op for the env:// and no-auth cases.
    /// `req_headers` and `body` are the bytes that will leave (the `Host` already rewritten, the
    /// phantom already stripped, the forwarded body). Returns the mutations to apply to the request —
    /// the caller applies them, so this borrows nothing mutably and composes with a live borrow of
    /// the body. An empty result means no backend signature applies.
    #[cfg(feature = "tls-intercept")]
    pub fn backend_signature_mutations<'a>(
        &self,
        original: &credentials::Destination<'_>,
        method: &str,
        req_headers: impl Iterator<Item = (&'a str, &'a str)>,
        backend: &BackendDial,
        fwd_target: &str,
        body: &[u8],
    ) -> std::result::Result<Vec<Mutation>, String> {
        let matching = self.matching(original);
        if matching.is_empty() {
            return Ok(Vec::new());
        }
        // Sign over the headers already present (backend `Host`, phantom stripped) plus forced
        // `identity`, the forwarded target, and the forwarded body — the bytes that leave, less the
        // headers that botocore does not sign.
        let headers = credential::headers_for_signing(req_headers);
        let scheme = if backend.tls { "https" } else { "http" };
        let default_port = if backend.tls { 443 } else { 80 };
        let authority = if backend.port == default_port {
            backend.host.clone()
        } else {
            format!("{host}:{port}", host = backend.host, port = backend.port)
        };
        let url = format!("{scheme}://{authority}{fwd_target}");
        let (fwd_path, fwd_query) = fwd_target.split_once('?').unwrap_or((fwd_target, ""));
        let outcomes: Vec<Outcome> = matching
            .iter()
            .map(|credential| {
                credential.on_backend_request(credentials::Outbound {
                    destination: credentials::Destination {
                        host: &backend.host,
                        port: backend.port,
                        path: fwd_path,
                    },
                    method,
                    url: &url,
                    query: fwd_query,
                    headers: &headers,
                    body,
                })
            })
            .collect();
        fold(outcomes)
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

    /// Two controls in one set that both attach to a request refuse it as a collision, so neither
    /// edits the request and neither advisory note survives to overwrite the other. The controls set
    /// different headers, so they collide only on the `accept-encoding` each attachment forces.
    #[test]
    fn two_attaching_controls_in_one_set_collide_and_record_no_note() {
        let advisory = |host: &str, header: &str| {
            let route = RouteSpec::opaque(
                DestinationPattern::parse(host).unwrap(),
                env_locator("secret"),
                InjectMode::header("{}", Some(header.to_string())).unwrap(),
            )
            .phantom_check(credentials::PhantomCheck::Advisory);
            let vault = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(route))
                .unwrap()
                .into_vault();
            CredentialCapability::new(DestinationPattern::parse(host).unwrap(), Arc::new(vault))
        };
        let set = CapabilitySet::new(vec![
            advisory("*.example.com", "X-First"),
            advisory("api.example.com", "X-Second"),
        ]);
        set.validate().unwrap();
        let mut req = request("api.example.com", HeaderMap::new());
        let refusal = set.apply_to_request(&mut req).unwrap_err();
        assert!(refusal.starts_with("mutation collision:"), "{refusal}");
        assert!(req.headers.is_empty(), "a refused request carries no edit");
        assert!(req.advisory_note.is_none());
        #[cfg(feature = "tls-intercept")]
        {
            let refusal = set.apply_exchange_request(&mut req).err().unwrap();
            assert!(refusal.starts_with("mutation collision:"), "{refusal}");
            assert!(req.advisory_note.is_none());
        }
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

    #[cfg(feature = "tls-intercept")]
    mod streaming {
        use super::*;
        use crate::capability::credential::tests::advisory_header_capability;

        // Build the response state without the request fold, which refuses two attachments as a
        // collision (`two_attaching_controls_in_one_set_collide_and_record_no_note`). The gateway
        // never reaches this state; these tests pin `controls` for more than one scrubber.
        fn overlapping_response(set: &CapabilitySet, target: &Target) -> ExchangeResponse {
            let req = request(&target.host, HeaderMap::new());
            let mut response = ExchangeResponse::Unmatched;
            for credential in set.matching(&target.as_destination()) {
                let edits = credential.on_request(&req, RequestMode::Paired).unwrap();
                response.capture(edits.redactor);
            }
            response
        }

        #[test]
        fn redactors_preserve_the_whole_body_capability_order() {
            for reverse in [false, true] {
                let mut credentials = vec![
                    advisory_header_capability("*.example.com", "red").0,
                    advisory_header_capability("api.example.com", "[REDACTED]-blue").0,
                ];
                if reverse {
                    credentials.reverse();
                }
                let set = CapabilitySet::new(credentials);
                set.validate().unwrap();
                let target = Target::new("api.example.com", 443);
                let mut baseline =
                    InterceptedResponse::http(200, HeaderMap::new(), b"red-blue".to_vec());
                set.apply_to_response(&mut baseline, &target).unwrap();

                let controls = overlapping_response(&set, &target)
                    .controls(&mut HeaderMap::new())
                    .unwrap();
                let mut body = b"red-blue".to_vec();
                for mut redactor in controls.redactors {
                    let mut scrubbed = redactor.push(&body);
                    scrubbed.extend(redactor.finish());
                    body = scrubbed;
                }
                assert_eq!(body, baseline.body);
                assert_eq!(
                    body.as_slice(),
                    if reverse {
                        b"[REDACTED]-blue".as_slice()
                    } else {
                        b"[REDACTED]".as_slice()
                    }
                );
            }
        }

        #[test]
        fn header_collisions_use_original_values_and_apply_no_edits() {
            let set = CapabilitySet::new(vec![
                advisory_header_capability("*.example.com", "red").0,
                advisory_header_capability("api.example.com", "red-blue").0,
            ]);
            let target = Target::new("api.example.com", 443);
            let mut headers = HeaderMap::new();
            headers.append("X-Echo", "red-blue");
            let original = headers.clone();
            let mut baseline = InterceptedResponse::http(200, original.clone(), Vec::new());
            let expected = set.apply_to_response(&mut baseline, &target).unwrap_err();
            let actual = overlapping_response(&set, &target)
                .controls(&mut headers)
                .unwrap_err();
            assert_eq!(actual, expected);
            assert!(actual.starts_with("mutation collision:"));
            assert_eq!(headers, original);
        }

        #[test]
        fn only_matching_capabilities_produce_response_controls() {
            let (credentials, phantoms) =
                shared_vault(&["api.github.com", "api.stripe.com"], "real-secret");
            let target = Target::new("api.github.com", 443);
            let mut headers = HeaderMap::new();
            headers.append("X-Echo", "real-secret");
            headers.append("Content-Encoding", "gzip");

            let set = CapabilitySet::new(credentials);
            let mut outside = request("unmatched.example.com", HeaderMap::new());
            let mut original = headers.clone();
            let off_route = set
                .apply_exchange_request(&mut outside)
                .unwrap()
                .controls(&mut original)
                .unwrap();
            assert_eq!(original, headers);
            assert!(off_route.redactors.is_empty());
            assert!(!off_route.requires_empty_body);

            let mut outbound = HeaderMap::new();
            outbound.append("Authorization", format!("Bearer {}", phantoms[0]));
            let mut req = request(&target.host, outbound);
            let mut baseline = InterceptedResponse::http(200, headers.clone(), Vec::new());
            set.apply_to_response(&mut baseline, &target).unwrap();
            let controls = set
                .apply_exchange_request(&mut req)
                .unwrap()
                .controls(&mut headers)
                .unwrap();
            assert_eq!(controls.redactors.len(), 1);
            assert!(controls.requires_empty_body);
            assert_eq!(headers, baseline.headers);
        }

        #[test]
        fn encoded_body_refusal_does_not_depend_on_an_opaque_binding() {
            let vault = Vault::open(VaultConfig::new(Backend::local(), "tenant"))
                .unwrap()
                .into_vault();
            let set = CapabilitySet::new(vec![CredentialCapability::new(
                DestinationPattern::parse("api.example.com").unwrap(),
                Arc::new(vault),
            )]);
            let target = Target::new("api.example.com", 443);
            for (encoding, must_be_empty) in
                [("gzip", true), ("identity, br", true), ("IDENTITY", false)]
            {
                let mut headers = HeaderMap::new();
                headers.append("Content-Encoding", encoding);
                let mut baseline = InterceptedResponse::http(200, headers.clone(), vec![1]);
                assert_eq!(
                    set.apply_to_response(&mut baseline, &target).is_err(),
                    must_be_empty
                );
                let controls = set
                    .apply_exchange_request(&mut request(&target.host, HeaderMap::new()))
                    .unwrap()
                    .controls(&mut headers)
                    .unwrap();
                assert!(controls.redactors.is_empty());
                assert_eq!(controls.requires_empty_body, must_be_empty);
            }
        }

        #[test]
        fn encoding_is_checked_before_its_header_value_is_redacted() {
            for (secret, requires_empty_body) in [("gzip", true), ("identity", false)] {
                let (capability, phantom) = header_capability("api.example.com", secret);
                let set = CapabilitySet::new(vec![capability]);
                let mut outbound = HeaderMap::new();
                outbound.append("Authorization", format!("Bearer {phantom}"));
                let mut req = request("api.example.com", outbound);
                let mut headers = HeaderMap::new();
                headers.append("Content-Encoding", secret);
                let controls = set
                    .apply_exchange_request(&mut req)
                    .unwrap()
                    .controls(&mut headers)
                    .unwrap();
                assert_eq!(headers.get("content-encoding"), Some("[REDACTED]"));
                assert_eq!(controls.requires_empty_body, requires_empty_body);
            }
        }
    }
}
