//! The two request-leg implementations behind [`Vault::attach_for`].
//!
//! [`Vault::attach_for`]: crate::Vault::attach_for

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::Zeroizing;

use crate::attach::{Attachment, Outbound, extract_slot, header_value, query_value};
use crate::sources::{
    AwsAcquisition, AwsResolution, AwsSource, CREDSD_SCHEME, CredsdClient,
    credsd_session_credentials,
};
use crate::vault::OpaqueBinding;
use crate::{
    CredentialError, InjectMode, Locator, PhantomCheck, RequestId, Result, Vault, sign_request,
};

/// The header the `Header` / `BasicAuth` inject modes use when the mode carries no explicit name.
/// `InjectMode::Header { header_name: None }` (and every `BasicAuth`) means the standard
/// `Authorization` header; `Some(name)` names a non-`Authorization` header such as `x-api-key`.
const DEFAULT_CRED_HEADER: &str = "Authorization";

/// The correlation id a per-request signing resolve audits under.
const SIGN_CORRELATION: &str = "credential-store-sign";

/// The inbound signing artifacts stripped unconditionally before signing.
const STRIP_SIGNING_HEADERS: &[&str] = &[
    "authorization",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
    "x-amz-signature",
];

impl Vault {
    /// Check the phantom on `req` per the binding's mode, then produce the strip + attach-real edits.
    pub(crate) fn swap_phantom(
        &self,
        binding: &OpaqueBinding,
        req: &Outbound<'_>,
    ) -> Result<Attachment> {
        // Read the phantom the harness placed, wherever it placed it. A `Strict` route fails closed
        // on an absent or mismatched placeholder; an `Advisory` route warns and attaches anyway,
        // for a workload the box cannot seed the placeholder into.
        let observed = observe_phantom(req, binding.harness());
        let matches = observed
            .as_deref()
            .is_some_and(|token| token == binding.phantom());

        // `Some` only for an advisory override, carrying the non-secret reason to journal.
        let mut advisory: Option<&'static str> = None;
        if !matches {
            let against = if observed.is_none() {
                "no placeholder token"
            } else {
                "an unrecognised placeholder token"
            };
            match binding.phantom_check() {
                PhantomCheck::Strict if observed.is_none() => {
                    return Err(CredentialError::UnsupportedInjectType(
                        "no phantom token found at the harness credential location; refusing to \
                         attach a secret to a request that presents no placeholder"
                            .to_string(),
                    ));
                }
                PhantomCheck::Strict => {
                    return Err(CredentialError::UnsupportedInjectType(
                        "observed phantom token does not match the destination's bound credential; \
                         refusing to attach a secret against an unrecognised placeholder"
                            .to_string(),
                    ));
                }
                PhantomCheck::Advisory => {
                    self.warn(&format!(
                        "attaching the real credential to {host} against {against}: the route sets \
                         secret.inject = \"always\", so the box injects without a matching placeholder",
                        host = req.destination.host,
                    ));
                    advisory = Some(against);
                }
            }
        }

        let mut attachment = attach_secret(binding);
        if let Some(against) = advisory {
            // Journalled on the gateway's allow decision (with the destination and requester
            // correlation the vault does not hold), so an advisory injection is reconstructable.
            attachment.note_advisory(format!("inject = always, against {against}"));
        }

        // The harness may have placed the phantom at a *different* location than the one the secret
        // attaches to. `attach_secret` clears the attach location; when the harness location differs,
        // clear that one too so the phantom never rides upstream.
        match binding.harness() {
            InjectMode::Header { header_name, .. } => {
                attachment.strip_header(header_name.as_deref().unwrap_or(DEFAULT_CRED_HEADER));
            }
            InjectMode::BasicAuth => attachment.strip_header(DEFAULT_CRED_HEADER),
            InjectMode::QueryParam { name, .. } => attachment.strip_query_param(name.clone()),
            // A `UrlPath` harness location has no standalone strip: clearing a phantom spliced into the
            // path means rewriting the whole path, which only a `UrlPath` *attach* does. When the attach
            // rewrites the path the phantom is overwritten and there is nothing to do; when it does not,
            // the phantom would ride upstream beside the real secret, so refuse the exchange.
            InjectMode::UrlPath { .. } if !attachment.rewrites_path() => {
                return Err(CredentialError::UnsupportedInjectType(
                    "the phantom is spliced into the request path but the credential attaches \
                     elsewhere, so the path phantom cannot be cleared; pair a url_path harness \
                     location with a url_path inject mode"
                        .to_string(),
                ));
            }
            InjectMode::UrlPath { .. } => {}
        }

        Ok(attachment)
    }

    /// SigV4-sign `req` in-boundary against the AWS `config` bound to its destination.
    pub(crate) fn sign_aws(&self, config: &Locator, req: &Outbound<'_>) -> Result<Attachment> {
        // Derive the signing scope from the request host, never from the credential (whose region is a
        // non-secret hint). An underivable host fails closed rather than signing under a guessed scope.
        let (service, region) = derive_service_region(req.destination.host).ok_or_else(|| {
            CredentialError::Credential(format!(
                "cannot derive an AWS service/region from host {host:?}; refusing to sign with a \
                 guessed scope",
                host = req.destination.host,
            ))
        })?;

        // Session credentials expire, so this resolve happens per request — and therefore gets its own
        // audit record, exactly like a load-time one. A signed route resolves nothing at open,
        // so without this an AWS credential acquisition would never be audited at all.
        let resolution = self.audit_aws_resolve(config)?;
        if let Some(warning) = resolution.acquisition.warning() {
            // An ambient fallback is allowed but not silent: it means the request is being signed with
            // whatever identity the host happens to carry rather than a declared scoped one.
            self.warn(warning);
        }
        // The source's return type is the credentials themselves, so there is no "wrong material kind"
        // branch left to get wrong here.
        let credentials = &*resolution.credentials;

        // Strip-then-sign: assemble the cleaned header set, then sign over exactly those headers.
        let clean_headers: Vec<(String, String)> = req
            .headers
            .iter()
            .filter(|(name, _)| {
                !STRIP_SIGNING_HEADERS
                    .iter()
                    .any(|stripped| name.eq_ignore_ascii_case(stripped))
            })
            .cloned()
            .collect();

        let signed = sign_request(
            credentials,
            &service,
            &region,
            req.method,
            req.url,
            &clean_headers,
            req.body,
        )?;

        let mut attachment = Attachment::new();
        for name in STRIP_SIGNING_HEADERS {
            attachment.strip_header(*name);
        }
        // Already `Zeroizing` from the signer, so this moves the wrapper rather than re-wrapping a
        // plaintext copy.
        for (name, value) in signed {
            attachment.set_header(name, value);
        }
        Ok(attachment)
    }
}

impl Vault {
    /// Resolve a signed route's AWS credentials, auditing the attempt.
    ///
    /// A `credsd://` locator routes to the credsd client and the AWS delivery adapter; every other
    /// signed locator is the ambient/scoped AWS source. The audit reference names the credsd
    /// environment; a structured aws route has no such non-secret label, so it keeps the
    /// `scheme://structured` form.
    fn audit_aws_resolve(&self, config: &Locator) -> Result<AwsResolution> {
        let request_id = RequestId::new(SIGN_CORRELATION);
        let reference = match config {
            Locator::Uri(uri) if config.scheme() == CREDSD_SCHEME => uri.clone(),
            _ => format!("{}://structured", config.scheme()),
        };
        crate::audit_resolve(
            self.emitter(),
            self.tenant_label(),
            config.scheme(),
            &reference,
            &request_id,
            || self.resolve_signed(config),
        )
    }

    /// Resolve one signed route's credentials, dispatching on the locator scheme.
    fn resolve_signed(&self, config: &Locator) -> Result<AwsResolution> {
        if config.scheme() == CREDSD_SCHEME {
            return self.resolve_credsd(config);
        }
        AwsSource::with_policy(self.ambient_policy()).resolve(config)
    }

    /// Resolve a `credsd://<environment>` locator to AWS session credentials.
    ///
    /// A `credsd` route always names an environment, so there is no unscoped case and no ambient
    /// fallback — the acquisition carries no warning.
    fn resolve_credsd(&self, config: &Locator) -> Result<AwsResolution> {
        let environment = credsd_environment(config)?;
        let socket = self.credsd_socket().ok_or_else(|| {
            CredentialError::KeystoreAccess(format!(
                "no credsd socket was resolved for environment {environment:?}"
            ))
        })?;
        let client = CredsdClient::new(socket.to_path_buf());
        let credentials = credsd_session_credentials(&client, environment)?;
        Ok(AwsResolution {
            credentials: zeroize::Zeroizing::new(credentials),
            acquisition: AwsAcquisition::Credsd(environment.to_string()),
        })
    }
}

/// The environment a `credsd://<environment>` locator names.
fn credsd_environment(config: &Locator) -> Result<&str> {
    match config {
        Locator::Uri(uri) => {
            let (scheme, environment) = uri.split_once("://").ok_or_else(|| {
                CredentialError::Credential(format!(
                    "malformed credsd credential reference {uri:?} (expected `credsd://<environment>`)"
                ))
            })?;
            if scheme != CREDSD_SCHEME {
                return Err(CredentialError::Credential(format!(
                    "a credsd route needs a credsd:// reference, not {scheme:?}"
                )));
            }
            if environment.is_empty() {
                return Err(CredentialError::Credential(
                    "a credsd:// reference names no environment".to_string(),
                ));
            }
            Ok(environment)
        }
        Locator::Structured(_) => Err(CredentialError::Credential(
            "a credsd route needs a credsd:// reference, not a structured block".to_string(),
        )),
    }
}

/// Build the strip-phantom + attach-real edits for a validated binding, honoring its inject mode.
fn attach_secret(binding: &OpaqueBinding) -> Attachment {
    let secret = binding.secret();
    let mut attachment = Attachment::new();

    match binding.inject() {
        InjectMode::Header {
            format,
            header_name,
            ..
        } => {
            let name = header_name.as_deref().unwrap_or(DEFAULT_CRED_HEADER);
            attachment.strip_header(name);
            attachment.set_header(name, Zeroizing::new(format.replacen("{}", secret, 1)));
        }
        InjectMode::BasicAuth => {
            // The raw credential is the `user:pass` pair; encode it as HTTP Basic.
            //
            // `encoded` is wrapped even though only the `format!` result was before: base64 is an
            // encoding, not a protection, so the encoded form is the credential and left an unwiped
            // copy in freed heap on every Basic-auth request.
            let encoded = Zeroizing::new(BASE64.encode(secret.as_bytes()));
            attachment.strip_header(DEFAULT_CRED_HEADER);
            attachment.set_header(
                DEFAULT_CRED_HEADER,
                Zeroizing::new(format!("Basic {}", *encoded)),
            );
        }
        InjectMode::UrlPath { pattern, .. } => {
            // Rewriting the path with the secret spliced in subsumes any phantom already there.
            attachment.rewrite_path(Zeroizing::new(pattern.replacen("{}", secret, 1)));
        }
        InjectMode::QueryParam { name, .. } => {
            // The set appends, so the swap must strip first: without the strip the phantom and the real
            // secret both egress as duplicate parameters, and which one the upstream honors is
            // server-dependent.
            attachment.strip_query_param(name.clone());
            attachment.set_query_param(name.clone(), Zeroizing::new(secret.to_string()));
        }
    }
    attachment
}

/// Read the phantom the harness placed at `location`.
fn observe_phantom(req: &Outbound<'_>, location: &InjectMode) -> Option<Zeroizing<String>> {
    let observed = match location {
        InjectMode::Header {
            format,
            header_name,
            ..
        } => {
            let name = header_name.as_deref().unwrap_or(DEFAULT_CRED_HEADER);
            let value = header_value(req.headers, name)?;
            extract_slot(format, value)?.to_string()
        }
        InjectMode::BasicAuth => {
            let value = header_value(req.headers, DEFAULT_CRED_HEADER)?;
            let b64 = value.strip_prefix("Basic ").unwrap_or(value);
            let decoded = BASE64.decode(b64.trim()).ok()?;
            let pair = String::from_utf8(decoded).ok()?;
            // The phantom is the password half of `user:pass`.
            pair.split_once(':').map(|(_, pw)| pw.to_string())?
        }
        InjectMode::UrlPath { pattern, .. } => {
            extract_slot(pattern, req.destination.path)?.to_string()
        }
        InjectMode::QueryParam { name, .. } => query_value(req.query, name)?.to_string(),
    };
    // A phantom is non-secret, but it is read out of a request that may carry a real credential at the
    // same location, so the extracted value is wiped on drop regardless.
    Some(Zeroizing::new(observed))
}

/// The suffixes an AWS endpoint host may carry.
///
/// **`.api.aws` is not decoration, and omitting it made a whole product unreachable.** AWS's newer
/// endpoints use it — Bedrock's OpenAI-compatible surface is `bedrock-mantle.<region>.api.aws` —
/// and this function returned `None` for every one of them. `None` means "cannot derive a signing
/// scope", so the signed leg refused to sign, and the gateway answered the workload
/// `403 blocked by egress control`.
///
/// That failure names nothing useful. Measured with Codex against Bedrock: five reconnect attempts
/// and then `error sending request for url`, which reads as a network fault rather than as an
/// endpoint shape this signer does not know.
///
/// The two suffixes are disjoint — no host ends with both — so the order here carries no meaning.
const AWS_HOST_SUFFIXES: [&str; 2] = [".amazonaws.com", ".api.aws"];

/// Derive `(service, region)` from an AWS endpoint host.
pub(crate) fn derive_service_region(host: &str) -> Option<(String, String)> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let rest = AWS_HOST_SUFFIXES
        .iter()
        .find_map(|suffix| host.strip_suffix(suffix))?;
    if rest.is_empty() {
        return None;
    }
    let labels: Vec<&str> = rest.split('.').collect();

    match labels.as_slice() {
        // {service}.amazonaws.com — a global service signs under us-east-1.
        [service] => Some((signing_name(service), "us-east-1".to_string())),
        // {service}.{region}.amazonaws.com — the regional form.
        [service, region] => Some((signing_name(service), (*region).to_string())),
        // {api-id}.execute-api.{region}.amazonaws.com — API Gateway; the service is always execute-api.
        [_, service, region] if *service == "execute-api" => {
            Some(("execute-api".to_string(), (*region).to_string()))
        }
        // Any other multi-label form is non-standard → fail closed.
        _ => None,
    }
}

/// Map an AWS endpoint prefix to its SigV4 signing name.
fn signing_name(endpoint_prefix: &str) -> String {
    match endpoint_prefix {
        // Bedrock's data-plane endpoints are `bedrock-runtime.*` / `bedrock-agent-runtime.*` but both
        // sign as `bedrock`.
        //
        // **`bedrock-mantle` is deliberately NOT mapped, and it was mapped twice wrongly.** First it
        // was refused outright, on the reasoning that the surface reads a Bearer token rather than a
        // signature. Then it was mapped to `bedrock`. Both came from watching one client instead of
        // reading the reference implementation.
        //
        // `openai/codex` signs Mantle with the service name `bedrock-mantle` unchanged
        // (`codex-rs/model-provider/src/amazon_bedrock/mantle.rs`,
        // `aws_auth_config_uses_profile_and_mantle_service`). Measured against production
        // 2026-08-19, `bedrock` and `bedrock-mantle` both return `200`, so the service accepts
        // either — which is exactly why a probe was the wrong evidence. The default arm passes the
        // prefix through, so matching the reference costs no code at all.
        "bedrock-runtime" | "bedrock-agent-runtime" => "bedrock".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regional_and_global_hosts_derive_their_scope() {
        assert_eq!(
            derive_service_region("s3.us-east-1.amazonaws.com"),
            Some(("s3".to_string(), "us-east-1".to_string()))
        );
        // A global service signs under us-east-1.
        assert_eq!(
            derive_service_region("iam.amazonaws.com"),
            Some(("iam".to_string(), "us-east-1".to_string()))
        );
        // API Gateway's four-label form.
        assert_eq!(
            derive_service_region("abc123.execute-api.eu-west-1.amazonaws.com"),
            Some(("execute-api".to_string(), "eu-west-1".to_string()))
        );
    }

    /// A `.api.aws` host derives its scope, and `bedrock-mantle` signs as `bedrock`.
    ///
    /// **Both halves are required and each failed on its own.** Without the suffix the host derived
    /// nothing and the gateway refused to sign it, answering `403 blocked by egress control`. With
    /// the suffix and no signing-name entry the request would be signed as service `bedrock-mantle`,
    /// which Bedrock rejects — a wrong signature rather than a missing one.
    #[test]
    fn a_dot_api_dot_aws_host_derives_its_scope() {
        // A `.api.aws` service that really does take SigV4 derives its scope.
        assert_eq!(
            derive_service_region("s3.us-east-2.api.aws"),
            Some(("s3".to_string(), "us-east-2".to_string()))
        );
        // The `.amazonaws.com` form still derives, so the added suffix widened nothing.
        assert_eq!(
            derive_service_region("bedrock-runtime.us-east-2.amazonaws.com"),
            Some(("bedrock".to_string(), "us-east-2".to_string()))
        );
        // A host carrying neither suffix is still refused, so this is not "any host signs".
        assert_eq!(derive_service_region("s3.us-east-2.api.example"), None);
        assert_eq!(derive_service_region("evil.com"), None);
    }

    /// **A Mantle host signs as `bedrock-mantle`, which is the prefix unchanged.**
    ///
    /// This got two wrong answers before the right one, and both came from probing instead of
    /// reading the reference. It was refused outright — "the surface reads a Bearer token, not a
    /// signature" — and then mapped to `bedrock`. `openai/codex` signs it with `bedrock-mantle`
    /// (`aws_auth_config_uses_profile_and_mantle_service`), and measured against production
    /// 2026-08-19 both service names return `200`. So a probe could not distinguish them and the
    /// reference implementation could.
    #[test]
    fn a_mantle_host_signs_as_its_own_prefix() {
        assert_eq!(
            derive_service_region("bedrock-mantle.us-east-2.api.aws"),
            Some(("bedrock-mantle".to_string(), "us-east-2".to_string()))
        );
        // Its sibling data-plane endpoints do map, so the pass-through is specific rather than a
        // decision to stop mapping anything.
        assert_eq!(
            derive_service_region("bedrock-runtime.us-east-2.api.aws"),
            Some(("bedrock".to_string(), "us-east-2".to_string()))
        );
    }

    /// The endpoint prefix is mapped to the signing name, or the signature would not validate.
    #[test]
    fn bedrock_runtime_signs_as_bedrock() {
        assert_eq!(
            derive_service_region("bedrock-runtime.us-west-2.amazonaws.com"),
            Some(("bedrock".to_string(), "us-west-2".to_string()))
        );
        assert_eq!(
            derive_service_region("bedrock-agent-runtime.us-west-2.amazonaws.com"),
            Some(("bedrock".to_string(), "us-west-2".to_string()))
        );
    }

    /// A host the mapping does not recognise yields `None`, so the caller refuses to sign rather than
    /// guessing a scope.
    #[test]
    fn unrecognised_hosts_fail_closed() {
        assert!(derive_service_region("api.github.com").is_none());
        assert!(derive_service_region("amazonaws.com").is_none());
        assert!(derive_service_region("vpce-1234.s3.us-east-1.vpce.amazonaws.com").is_none());
        // A trailing dot (a fully-qualified name) still resolves, so it cannot be used to dodge the
        // mapping and reach the `None` branch with a real AWS host.
        assert_eq!(
            derive_service_region("s3.us-east-1.amazonaws.com."),
            Some(("s3".to_string(), "us-east-1".to_string()))
        );
    }
}
