//! [`CredentialCapability`] — the phantom→real swap at the boundary, via the `credentials` vault.

use std::sync::Arc;

use credentials::{DestinationPattern, Inbound, Outbound, Vault};
use zeroize::Zeroizing;

use crate::boundary::{BodyRef, InterceptedRequest, InterceptedResponse, Mutation};
use crate::capability::traits::{CapabilityContext, CapabilityOutcome, EgressCapability};

/// The `accept-encoding` every credentialed request carries.
const IDENTITY_ENCODING: &str = "identity";

/// The credential-injection capability.
pub struct CredentialCapability {
    pattern: DestinationPattern,
    store: Arc<Vault>,
}

impl CredentialCapability {
    /// Build a `CredentialCapability` scoped to `pattern`, resolving against the vault `store`.
    pub fn new(pattern: DestinationPattern, store: Arc<Vault>) -> Self {
        Self { pattern, store }
    }
}

impl EgressCapability for CredentialCapability {
    fn pattern(&self) -> &DestinationPattern {
        &self.pattern
    }

    fn on_request(
        &self,
        req: &mut InterceptedRequest,
        _cx: &CapabilityContext,
    ) -> CapabilityOutcome {
        // Not applicable to this request → no edits. A mutation capability simply does not act
        // off-route.
        if !self.pattern.matches(&req.target.as_destination()) {
            return CapabilityOutcome::none();
        }

        // The vault owns the whole decision: which binding, where the phantom is, whether it matches,
        // and — for a signed route — the signature. There is no partial answer to mishandle here.
        // The vault signs these headers, so each one must already hold the value that goes on the
        // wire, including the `accept-encoding` this capability forces below.
        let mut headers: Vec<(String, String)> = req
            .headers
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("accept-encoding"))
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        headers.push(("accept-encoding".to_string(), IDENTITY_ENCODING.to_string()));
        let url = req.target.url();
        let outbound = Outbound {
            destination: req.target.as_destination(),
            method: req.method.as_deref().unwrap_or("GET"),
            url: &url,
            query: &req.target.query,
            headers: &headers,
            body: req.body.as_bytes(),
        };

        match self.store.attach_for(outbound) {
            // The vault governs no credential for this destination.
            Ok(None) => CapabilityOutcome::none(),
            Ok(Some(attachment)) => {
                // An advisory injection (secret attached without a matching placeholder) is a
                // noteworthy allow. Carry the vault's non-secret reason to the driver, which journals
                // it on the allow decision with the destination and requester correlation. Set only
                // when present, so a second matching control's normal swap cannot clobber the note.
                if let Some(reason) = attachment.advisory_reason() {
                    req.advisory_note = Some(reason.to_string());
                }
                let mut mutations = Vec::new();
                // Strips first: the phantom must be gone before the real secret is set, and for a
                // signed route every inbound signing artifact must be gone before the signature lands.
                for name in attachment.strip_headers() {
                    mutations.push(Mutation::StripHeader {
                        name: name.to_string(),
                    });
                }
                for name in attachment.strip_query() {
                    mutations.push(Mutation::StripQueryParam {
                        name: name.to_string(),
                    });
                }
                // The vault vends each secret-bearing value as `&Zeroizing<String>`, and the mutation
                // holds the same type — so this clones the wrapper, not the bare bytes, and the copy
                // is wiped when the mutation drops. `value.to_string()` also compiles here (the
                // wrapper derefs) and would produce a plain `String` freed without scrubbing.
                for (name, value) in attachment.set_headers() {
                    mutations.push(Mutation::SetHeader {
                        name: name.to_string(),
                        value: value.clone(),
                    });
                }
                if let Some(path) = attachment.rewrite_path_to() {
                    mutations.push(Mutation::RewritePath { path: path.clone() });
                }
                for (name, value) in attachment.set_query() {
                    mutations.push(Mutation::AddQueryParam {
                        name: name.to_string(),
                        value: value.clone(),
                    });
                }
                // The leak-back scrub reads the response as plain bytes, so the origin must not encode it.
                mutations.push(Mutation::SetHeader {
                    name: "accept-encoding".to_string(),
                    value: Zeroizing::new(IDENTITY_ENCODING.to_string()),
                });
                CapabilityOutcome::applied(mutations)
            }
            // An ambiguous binding, a missing or mismatched phantom, an underivable signing scope, or a
            // signer error. Every one of them means the request must not go out carrying this
            // credential. The vault's messages are non-secret by construction.
            Err(err) => CapabilityOutcome::unavailable(err.to_string()),
        }
    }

    fn on_response(
        &self,
        res: &mut InterceptedResponse,
        cx: &CapabilityContext,
    ) -> CapabilityOutcome {
        // The request's destination (carried on the context) resolves the same binding whose secret to
        // scan for — an upstream must not be able to echo the injected secret back to the workload.
        let headers: Vec<(String, String)> = res
            .headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        let body = res.body.as_bytes().to_vec();
        if !body.is_empty()
            && let Some(encoding) = content_encoding(&res.headers)
        {
            return CapabilityOutcome::unavailable(format!(
                "the response to a credentialed request arrived with Content-Encoding {encoding}, \
                 which the leak-back scrub cannot read; it is refused rather than delivered unscanned"
            ));
        }
        let inbound = Inbound {
            destination: cx.target.as_destination(),
            headers: &headers,
            body: &body,
        };

        let Some(redactions) = self.store.redact_leaks(inbound) else {
            return CapabilityOutcome::none();
        };

        // The body is rewritten in place (the interceptor owns the response bytes); header redactions
        // ride on mutations, as they always have.
        if let Some(scrubbed) = redactions.body() {
            res.body = BodyRef::Bytes(scrubbed.to_vec());
        }
        // These values are non-secret by construction — a redaction is what remains *after* the
        // secret was removed. The wrap is to satisfy `SetHeader`'s type, not to protect these bytes.
        let mutations: Vec<Mutation> = redactions
            .set_headers()
            .map(|(name, value)| Mutation::SetHeader {
                name: name.to_string(),
                value: Zeroizing::new(value.to_string()),
            })
            .collect();
        CapabilityOutcome::applied(mutations)
    }
}

/// The response's `Content-Encoding` when it names any coding other than `identity`.
fn content_encoding(headers: &crate::boundary::HeaderMap) -> Option<String> {
    let value = headers.get("content-encoding")?;
    value
        .split(',')
        .map(str::trim)
        .any(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity"))
        .then(|| value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use credentials::{Backend, InjectMode, Locator, PhantomCheck, RouteSpec, VaultConfig};

    use super::*;
    use crate::boundary::{HeaderMap, Target};

    /// Place `secret` in a uniquely-named environment variable and return its `env://` locator.
    fn env_locator(secret: &str) -> Locator {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "CREDENTIAL_CAPABILITY_TEST_{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        // SAFETY: the name is unique to this call, so no other test reads or writes it.
        unsafe { std::env::set_var(&name, secret) };
        Locator::parse_uri(&format!("env://{name}")).unwrap()
    }

    fn pattern(dest: &str) -> DestinationPattern {
        DestinationPattern::parse(dest).unwrap()
    }

    /// A capability over one opaque header route; returns it with the minted phantom.
    fn header_capability(dest: &str, secret: &str) -> (CredentialCapability, String) {
        let opened = Vault::open(
            VaultConfig::new(Backend::local(), "tenant").route(RouteSpec::opaque(
                pattern(dest),
                env_locator(secret),
                InjectMode::header("Bearer {}".to_string(), None)
                    .expect("a valid header placement"),
            )),
        )
        .unwrap();
        let phantom = opened.phantoms()[0].token().to_string();
        (
            CredentialCapability::new(pattern(dest), Arc::new(opened.into_vault())),
            phantom,
        )
    }

    /// A capability over one opaque header route in `advisory` mode; returns it with the phantom.
    fn advisory_header_capability(dest: &str, secret: &str) -> (CredentialCapability, String) {
        let opened = Vault::open(
            VaultConfig::new(Backend::local(), "tenant").route(
                RouteSpec::opaque(
                    pattern(dest),
                    env_locator(secret),
                    InjectMode::header("Bearer {}".to_string(), None)
                        .expect("a valid header placement"),
                )
                .phantom_check(PhantomCheck::Advisory),
            ),
        )
        .unwrap();
        let phantom = opened.phantoms()[0].token().to_string();
        (
            CredentialCapability::new(pattern(dest), Arc::new(opened.into_vault())),
            phantom,
        )
    }

    /// Assert that `outcome` swaps in the real secret and strips the placeholder location.
    fn assert_swapped_to_real_secret(outcome: &CapabilityOutcome) {
        assert!(
            !outcome.is_unavailable(),
            "advisory must inject, not refuse"
        );
        let edits = outcome.edits();
        assert!(
            edits.iter().any(|m| matches!(
                m,
                Mutation::SetHeader { name, value }
                    if name == "Authorization" && value.as_str() == "Bearer real-secret"
            )),
            "the real secret must be attached: {edits:?}"
        );
        assert!(
            edits
                .iter()
                .any(|m| matches!(m, Mutation::StripHeader { name } if name == "Authorization")),
            "the placeholder location must be stripped: {edits:?}"
        );
    }

    fn request(host: &str, headers: HeaderMap) -> InterceptedRequest {
        InterceptedRequest {
            target: Target::new(host, 443),
            method: Some("GET".to_string()),
            headers,
            body: BodyRef::Empty,
            advisory_note: None,
        }
    }

    fn context(host: &str) -> CapabilityContext {
        CapabilityContext::new(crate::RequestId::new("turn-1"), 0, Target::new(host, 443))
    }

    /// The happy path: a request presenting the phantom gets the real secret, and the phantom is
    /// stripped rather than left beside it.
    #[test]
    fn a_matching_phantom_is_swapped_for_the_real_secret() {
        let (capability, phantom) = header_capability("api.github.com", "real-secret");
        let mut headers = HeaderMap::new();
        headers.append("Authorization", format!("Bearer {phantom}"));
        let mut req = request("api.github.com", headers);

        let outcome = capability.on_request(&mut req, &context("api.github.com"));

        assert!(!outcome.is_unavailable(), "the happy path produces edits");
        let edits = outcome.edits();
        assert!(
            edits.iter().any(|m| matches!(
                m,
                Mutation::SetHeader { name, value }
                    if name == "Authorization" && value.as_str() == "Bearer real-secret"
            )),
            "the real secret must be attached: {edits:?}"
        );
        assert!(
            edits
                .iter()
                .any(|m| matches!(m, Mutation::StripHeader { name } if name == "Authorization")),
            "the phantom must be stripped, not left beside the secret: {edits:?}"
        );
        // Strips precede sets, or the strip would remove the secret just attached.
        let strip = edits
            .iter()
            .position(|m| matches!(m, Mutation::StripHeader { .. }))
            .expect("a strip is present");
        let set = edits
            .iter()
            .position(|m| matches!(m, Mutation::SetHeader { .. }))
            .expect("a set is present");
        assert!(strip < set, "strip must precede set: {edits:?}");
    }

    /// A phantom that does not match the binding stops the exchange.
    #[test]
    fn a_mismatched_phantom_is_unavailable() {
        let (capability, _phantom) = header_capability("api.github.com", "real-secret");
        let mut headers = HeaderMap::new();
        headers.append("Authorization", "Bearer strands_box_not-the-right-phantom");
        let mut req = request("api.github.com", headers);

        let outcome = capability.on_request(&mut req, &context("api.github.com"));

        assert!(
            outcome.is_unavailable(),
            "an unrecognised placeholder must stop the exchange, not attach a secret"
        );
        assert!(outcome.edits().is_empty(), "nothing may egress");
    }

    /// A request presenting **no** phantom is refused too: there is nothing to recognise, so attaching
    /// a secret would credential a request the harness never marked.
    #[test]
    fn a_missing_phantom_is_unavailable() {
        let (capability, _) = header_capability("api.github.com", "real-secret");
        let mut req = request("api.github.com", HeaderMap::new());

        assert!(
            capability
                .on_request(&mut req, &context("api.github.com"))
                .is_unavailable()
        );
    }

    /// An advisory route injects the real secret when the request presents no placeholder.
    #[test]
    fn advisory_injects_when_the_placeholder_is_absent() {
        let (capability, _) = advisory_header_capability("api.github.com", "real-secret");
        let mut req = request("api.github.com", HeaderMap::new());

        let outcome = capability.on_request(&mut req, &context("api.github.com"));
        assert_swapped_to_real_secret(&outcome);
    }

    /// An advisory route injects the real secret even when the presented placeholder does not match.
    #[test]
    fn advisory_injects_when_the_placeholder_mismatches() {
        let (capability, _phantom) = advisory_header_capability("api.github.com", "real-secret");
        let mut headers = HeaderMap::new();
        headers.append("Authorization", "Bearer strands_box_not-the-right-phantom");
        let mut req = request("api.github.com", headers);

        let outcome = capability.on_request(&mut req, &context("api.github.com"));
        assert_swapped_to_real_secret(&outcome);
    }

    /// A matching placeholder on an advisory route still swaps normally.
    #[test]
    fn advisory_swaps_a_matching_placeholder() {
        let (capability, phantom) = advisory_header_capability("api.github.com", "real-secret");
        let mut headers = HeaderMap::new();
        headers.append("Authorization", format!("Bearer {phantom}"));
        let mut req = request("api.github.com", headers);

        let outcome = capability.on_request(&mut req, &context("api.github.com"));
        assert_swapped_to_real_secret(&outcome);
        assert!(
            req.advisory_note.is_none(),
            "a matching placeholder is not an advisory override"
        );
    }

    /// An advisory injection annotates the request with a non-secret reason for the audit journal.
    #[test]
    fn advisory_injection_annotates_the_request_for_the_journal() {
        let (capability, _) = advisory_header_capability("api.github.com", "real-secret");
        let mut req = request("api.github.com", HeaderMap::new());

        let _ = capability.on_request(&mut req, &context("api.github.com"));
        let note = req
            .advisory_note
            .as_deref()
            .expect("an advisory injection annotates the request for the journal");
        assert!(
            note.contains("inject = always"),
            "the note names the always-inject decision: {note}"
        );
        assert!(
            !note.contains("real-secret"),
            "the note carries no secret: {note}"
        );
    }

    /// A later normal swap on the same request does not clobber an advisory note already recorded —
    /// so the allow decision keeps the reason even when two controls match one destination.
    #[test]
    fn a_normal_swap_does_not_clobber_an_earlier_advisory_note() {
        let (advisory_cap, _) = advisory_header_capability("api.github.com", "real-secret");
        let (strict_cap, phantom) = header_capability("api.github.com", "real-secret");
        let mut req = request("api.github.com", HeaderMap::new());

        // Advisory injection (absent placeholder) records the note.
        let _ = advisory_cap.on_request(&mut req, &context("api.github.com"));
        assert!(req.advisory_note.is_some(), "advisory records the note");

        // A second control that matches its own phantom is a normal swap and must not erase it.
        req.headers
            .append("Authorization", format!("Bearer {phantom}"));
        let _ = strict_cap.on_request(&mut req, &context("api.github.com"));
        assert!(
            req.advisory_note.is_some(),
            "a normal swap must not clobber the advisory note"
        );
    }

    /// A strict route leaves no note — it refuses rather than injecting.
    #[test]
    fn a_strict_miss_leaves_no_advisory_note() {
        let (capability, _) = header_capability("api.github.com", "real-secret");
        let mut req = request("api.github.com", HeaderMap::new());

        let outcome = capability.on_request(&mut req, &context("api.github.com"));
        assert!(outcome.is_unavailable(), "strict fails closed");
        assert!(req.advisory_note.is_none(), "a refusal is not an allow");
    }

    /// Off-route requests get no edits: a mutation capability does not act outside its pattern.
    #[test]
    fn an_off_route_request_gets_no_edits() {
        let (capability, phantom) = header_capability("api.github.com", "real-secret");
        let mut headers = HeaderMap::new();
        headers.append("Authorization", format!("Bearer {phantom}"));
        let mut req = request("api.stripe.com", headers);

        let outcome = capability.on_request(&mut req, &context("api.stripe.com"));
        assert_eq!(outcome, CapabilityOutcome::none());
    }

    /// A secret echoed back by the upstream is redacted out of the response body.
    #[test]
    fn a_leaked_secret_is_redacted_from_the_response_body() {
        let (capability, _) = header_capability("api.github.com", "real-secret");
        let mut res = InterceptedResponse::http(
            200,
            HeaderMap::new(),
            BodyRef::Bytes(b"{\"echo\":\"real-secret\"}".to_vec()),
        );

        let outcome = capability.on_response(&mut res, &context("api.github.com"));

        assert!(!outcome.is_unavailable());
        let body = String::from_utf8(res.body.as_bytes().to_vec()).unwrap();
        assert!(!body.contains("real-secret"), "the secret leaked: {body}");
        assert!(body.contains("[REDACTED]"), "got {body}");
    }

    /// A credentialed request asks the origin for an unencoded response, whatever the workload sent.
    #[test]
    fn a_credentialed_request_asks_for_an_unencoded_response() {
        let (capability, phantom) = header_capability("api.github.com", "real-secret");
        let mut headers = HeaderMap::new();
        headers.append("Authorization", format!("Bearer {phantom}"));
        headers.append("Accept-Encoding", "gzip, br");
        let mut req = request("api.github.com", headers);

        let outcome = capability.on_request(&mut req, &context("api.github.com"));

        assert!(
            outcome.edits().iter().any(|m| matches!(
                m,
                Mutation::SetHeader { name, value }
                    if name == "accept-encoding" && value.as_str() == "identity"
            )),
            "the request must ask for identity: {:?}",
            outcome.edits()
        );
    }

    /// An off-route request is not rewritten, so its encoding is left to the workload.
    #[test]
    fn an_off_route_request_keeps_its_accept_encoding() {
        let (capability, _) = header_capability("api.github.com", "real-secret");
        let mut headers = HeaderMap::new();
        headers.append("Accept-Encoding", "gzip");
        let mut req = request("example.com", headers);

        let outcome = capability.on_request(&mut req, &context("example.com"));

        assert!(outcome.edits().is_empty(), "{:?}", outcome.edits());
    }

    /// A compressed body on a credentialed route is refused, because the scrub cannot read it.
    #[test]
    fn an_encoded_response_body_is_refused() {
        let (capability, _) = header_capability("api.github.com", "real-secret");
        for coding in ["gzip", "GZIP", "br", "deflate", "identity, gzip"] {
            let mut headers = HeaderMap::new();
            headers.append("Content-Encoding", coding);
            let mut res = InterceptedResponse::http(
                200,
                headers,
                BodyRef::Bytes(vec![0x1f, 0x8b, 0x08, 0x00]),
            );

            let outcome = capability.on_response(&mut res, &context("api.github.com"));

            assert!(
                outcome.is_unavailable(),
                "Content-Encoding {coding} must be refused"
            );
        }
    }

    /// An `identity` coding, or an empty body, carries nothing the scrub cannot read.
    #[test]
    fn an_identity_or_empty_encoded_response_is_delivered() {
        let (capability, _) = header_capability("api.github.com", "real-secret");
        let mut headers = HeaderMap::new();
        headers.append("Content-Encoding", "identity");
        let mut plain = InterceptedResponse::http(
            200,
            headers,
            BodyRef::Bytes(b"{\"echo\":\"real-secret\"}".to_vec()),
        );
        let outcome = capability.on_response(&mut plain, &context("api.github.com"));
        assert!(!outcome.is_unavailable());
        let body = String::from_utf8(plain.body.as_bytes().to_vec()).unwrap();
        assert!(
            !body.contains("real-secret"),
            "the identity body is still scrubbed: {body}"
        );

        let mut headers = HeaderMap::new();
        headers.append("Content-Encoding", "gzip");
        let mut empty = InterceptedResponse::http(304, headers, BodyRef::Empty);
        assert!(
            !capability
                .on_response(&mut empty, &context("api.github.com"))
                .is_unavailable()
        );
    }

    /// A leaked secret in a header value is redacted through a mutation.
    #[test]
    fn a_leaked_secret_is_redacted_from_a_response_header() {
        let (capability, _) = header_capability("api.github.com", "real-secret");
        let mut headers = HeaderMap::new();
        headers.append("X-Echo", "real-secret");
        let mut res = InterceptedResponse::http(200, headers, BodyRef::Empty);

        let outcome = capability.on_response(&mut res, &context("api.github.com"));

        assert!(outcome.edits().iter().any(|m| matches!(
            m,
            Mutation::SetHeader { name, value }
                if name == "X-Echo" && value.contains("[REDACTED]")
        )));
    }

    /// A clean response is left alone.
    #[test]
    fn a_clean_response_gets_no_edits() {
        let (capability, _) = header_capability("api.github.com", "real-secret");
        let mut res = InterceptedResponse::http(
            200,
            HeaderMap::new(),
            BodyRef::Bytes(b"{\"ok\":true}".to_vec()),
        );

        let outcome = capability.on_response(&mut res, &context("api.github.com"));
        assert_eq!(outcome, CapabilityOutcome::none());
        assert_eq!(res.body.as_bytes(), b"{\"ok\":true}");
    }
}
