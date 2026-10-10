//! AWS SigV4 signing and the AWS credential source.

use std::env;

use zeroize::Zeroizing;

use crate::{AwsSessionCredentials, CredentialError, Locator, Result};

// ===================================================================================================
// SigV4 signer
// ===================================================================================================

/// The SigV4 algorithm identifier.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The fixed terminator string for the credential scope and signing-key derivation.
const REQUEST_TYPE: &str = "aws4_request";

/// Sign an outbound request with AWS Signature Version 4, returning the headers to attach.
pub(crate) fn sign_request(
    credentials: &AwsSessionCredentials,
    service: &str,
    region: &str,
    method: &str,
    url: &str,
    clean_headers: &[(String, String)],
    body: &[u8],
) -> Result<Vec<(String, Zeroizing<String>)>> {
    sign_request_at(
        credentials,
        service,
        region,
        method,
        url,
        clean_headers,
        body,
        &SigningTime::now()?,
    )
}

/// [`sign_request`] with the signing timestamp supplied explicitly (the deterministic test seam).
#[allow(clippy::too_many_arguments)]
fn sign_request_at(
    credentials: &AwsSessionCredentials,
    service: &str,
    region: &str,
    method: &str,
    url: &str,
    clean_headers: &[(String, String)],
    body: &[u8],
    time: &SigningTime,
) -> Result<Vec<(String, Zeroizing<String>)>> {
    if service.is_empty() {
        return Err(CredentialError::Credential(
            "SigV4 signing requires a non-empty service (from the route binding)".to_string(),
        ));
    }
    if region.is_empty() {
        return Err(CredentialError::Credential(
            "SigV4 signing requires a non-empty region (from the route binding)".to_string(),
        ));
    }

    let (authority, path, query) = split_url(url)?;
    // A session token is signed iff it is present and non-empty (`Option` replaces the old
    // empty-string sentinel; `Some("")` is still treated as "no token"). `session_token` names it
    // once so the `Some(token)` branches below reuse the borrow.
    let session_token = credentials
        .session_token
        .as_deref()
        .filter(|t| !t.is_empty());

    // --- Canonical headers -----------------------------------------------------------------------
    // Collect the headers we sign: the caller's clean headers, plus the amz headers we add. Keyed by
    // lowercased name (BTreeMap → sorted); duplicate names have their values comma-joined per the
    // SigV4 spec.
    use std::collections::BTreeMap;
    fn add(signed: &mut BTreeMap<String, Vec<String>>, name: &str, value: String) {
        signed
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(value);
    }
    let mut signed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in clean_headers {
        add(&mut signed, name, canonical_header_value(value));
    }
    // A host header is mandatory in the signature; derive it from the URL when absent.
    if !signed.contains_key("host") {
        add(&mut signed, "host", authority.clone());
    }
    add(&mut signed, "x-amz-date", time.amz_date.clone());
    if let Some(token) = session_token {
        add(
            &mut signed,
            "x-amz-security-token",
            canonical_header_value(token),
        );
    }
    // The payload hash over the body this boundary is actually forwarding.
    //
    // S3 *requires* `x-amz-content-sha256` on every request (without it the
    // service answers `400 InvalidRequest: Missing required header`), and the
    // caller strips any inbound one so a workload cannot have a value of its own
    // choosing signed — which leaves the signer as its only author. It is added
    // to the signed set, not merely attached, so the signature vouches for the
    // hash rather than leaving it unattested.
    //
    // S3 only: the header is scoped the way the AWS SDKs scope it, in an
    // S3-specific signer (botocore adds it in `S3SigV4Auth`, not in the base
    // `SigV4Auth`). Signing it for every service would also break conformance
    // with the published SigV4 `get-vanilla` vector, whose signed set is
    // `host;x-amz-date`.
    let hashed_payload = sha256_hex(body);
    let signs_payload_header = service.eq_ignore_ascii_case("s3");
    if signs_payload_header {
        add(&mut signed, "x-amz-content-sha256", hashed_payload.clone());
    }

    // `canonical_headers` and, through it, `canonical_request` embed the **session token** when the
    // credentials carry one, so both are wiped on drop. Without the wrapper each was a plain `String`
    // the allocator freed unscrubbed — one copy of the token per signed request, for every request the
    // daemon signs. `signed_headers` is only the *names*, so it stays plain.
    let canonical_headers: Zeroizing<String> = Zeroizing::new(
        signed
            .iter()
            .map(|(name, values)| format!("{name}:{}\n", values.join(",")))
            .collect(),
    );
    let signed_headers: String = signed.keys().cloned().collect::<Vec<_>>().join(";");

    // --- Canonical request -----------------------------------------------------------------------
    let canonical_request = Zeroizing::new(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        uri_encode(&path, false),
        canonical_query(&query),
        *canonical_headers,
        signed_headers,
        hashed_payload,
    ));

    // --- String to sign --------------------------------------------------------------------------
    // The string-to-sign holds only a *hash* of the canonical request, so it carries no secret and
    // needs no wrapper: the scope, the date, and a SHA-256 digest.
    let credential_scope = format!("{}/{region}/{service}/{REQUEST_TYPE}", time.date_stamp);
    let string_to_sign = format!(
        "{ALGORITHM}\n{}\n{credential_scope}\n{}",
        time.amz_date,
        sha256_hex(canonical_request.as_bytes()),
    );

    // --- Signing key + signature -----------------------------------------------------------------
    let signature = to_hex(&signing_signature(
        &credentials.secret_access_key,
        &time.date_stamp,
        region,
        service,
        string_to_sign.as_bytes(),
    ));

    // Carries the access key id, which is credential material even though it is not the secret half.
    let authorization = Zeroizing::new(format!(
        "{ALGORITHM} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        credentials.access_key_id,
    ));

    // Headers the caller attaches to the outbound request, in a stable order.
    // When the payload hash is in the signed set it has to go on the wire too —
    // a signature naming a header the request omits does not verify.
    //
    // Every value is `Zeroizing`: the security token and the `Authorization` value are credential
    // material, and the date and payload hash are not — but the vector is one type, and wrapping a
    // non-secret costs a wipe of bytes nobody minds losing. The alternative, a per-entry "is this
    // secret" flag, is a decision every future caller could get wrong.
    let mut out = vec![(
        "X-Amz-Date".to_string(),
        Zeroizing::new(time.amz_date.clone()),
    )];
    if signs_payload_header {
        out.push((
            "X-Amz-Content-Sha256".to_string(),
            Zeroizing::new(hashed_payload),
        ));
    }
    if let Some(token) = session_token {
        out.push((
            "X-Amz-Security-Token".to_string(),
            Zeroizing::new(token.to_string()),
        ));
    }
    out.push(("Authorization".to_string(), authorization));
    Ok(out)
}

/// Derive the SigV4 signing key and return the final signature bytes (HMAC-SHA256 of the
/// string-to-sign under the derived key).
fn signing_signature(
    secret_access_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
    string_to_sign: &[u8],
) -> Zeroizing<Vec<u8>> {
    // `AWS4` ‖ secret, wrapped so the seed is wiped on drop.
    //
    // One honest limit: `format!` grows its own buffer internally, so if its final capacity was
    // reached by growing, an intermediate allocation held a prefix of the secret and was freed
    // un-scrubbed. `Zeroizing` covers the buffer it receives, not `format!`'s history. Bounding that
    // would mean building this by hand into a pre-sized `Zeroizing<String>`; it is left as-is because
    // the daemon's memory protection
    // (docs/design/decisions.md#the-trusted-processs-memory-is-a-defended-asset) is what defends
    // this class, and the same limit applies to every `format!` on the path.
    let seed = Zeroizing::new(format!("AWS4{secret_access_key}"));
    let k_date = Zeroizing::new(hmac_sha256(seed.as_bytes(), date_stamp.as_bytes()));
    let k_region = Zeroizing::new(hmac_sha256(&k_date, region.as_bytes()));
    let k_service = Zeroizing::new(hmac_sha256(&k_region, service.as_bytes()));
    let k_signing = Zeroizing::new(hmac_sha256(&k_service, REQUEST_TYPE.as_bytes()));
    Zeroizing::new(hmac_sha256(&k_signing, string_to_sign))
}

/// The signing timestamp in the two forms SigV4 needs: the full ISO-8601 basic `amz_date`
/// (`YYYYMMDDTHHMMSSZ`) used in the string-to-sign and the `X-Amz-Date` header, and the
/// `date_stamp` (`YYYYMMDD`) used in the credential scope and signing-key derivation.
struct SigningTime {
    amz_date: String,
    date_stamp: String,
}

impl SigningTime {
    /// The current UTC wall-clock time. A clock set before the Unix epoch is a hard error rather
    /// than a wrong (fail-open) signature.
    fn now() -> Result<Self> {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                CredentialError::Credential(
                    "system clock is before the Unix epoch; cannot form a SigV4 timestamp"
                        .to_string(),
                )
            })?
            .as_secs();
        Ok(Self::from_unix_secs(secs as i64))
    }

    /// Build the timestamp from a Unix epoch second count (UTC). Pure integer date math — no
    /// dependency on a calendar crate — so the signer stays `std`-only.
    fn from_unix_secs(secs: i64) -> Self {
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
        let (year, month, day) = civil_from_days(days);
        Self {
            amz_date: format!("{year:04}{month:02}{day:02}T{hour:02}{min:02}{sec:02}Z"),
            date_stamp: format!("{year:04}{month:02}{day:02}"),
        }
    }
}

/// Convert a day count since 1970-01-01 to a `(year, month, day)` civil date (Howard Hinnant's
/// `civil_from_days`, valid for the proleptic Gregorian calendar).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

/// URI-encode per RFC 3986 (SigV4 rules): the unreserved set (`A-Z a-z 0-9 - _ . ~`) passes
/// through, `/` is preserved when `encode_slash` is false (canonical path), and everything else is
/// percent-encoded with uppercase hex.
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Sort the URL's encoded query pairs by key and value.
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k.to_string(), v.to_string())
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Trim a header value and collapse each whitespace run to one space.
fn canonical_header_value(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

/// Split a URL into `(authority, path, query)`. `authority` is the host (with port if present) used
/// for the `host` header; `path` keeps its leading `/` (defaulting to `/`); `query` excludes the
/// `?`. A URL with no authority is a hard, fail-closed error.
fn split_url(url: &str) -> Result<(String, String, String)> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let (authority, rest) = match after_scheme.split_once('/') {
        Some((a, r)) => (a, format!("/{r}")),
        None => (after_scheme, "/".to_string()),
    };
    // An authority may carry `user@` or a trailing `#fragment`; strip a fragment from the path.
    let (path_part, query) = match rest.split_once('?') {
        Some((p, q)) => (
            p.to_string(),
            q.split_once('#').map_or(q, |(q, _)| q).to_string(),
        ),
        None => (
            rest.split_once('#')
                .map_or(rest.as_str(), |(p, _)| p)
                .to_string(),
            String::new(),
        ),
    };
    if authority.is_empty() {
        return Err(CredentialError::Credential(
            "SigV4 signing requires a URL with a host".to_string(),
        ));
    }
    Ok((authority.to_string(), path_part, query))
}

/// HMAC-SHA256 of `data` under `key`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Lowercase hex of the SHA-256 digest of `data`.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    to_hex(&hasher.finalize())
}

/// Lowercase hex encoding (hand-rolled so the crate takes no `hex` dependency).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ===================================================================================================
// AWS source
// ===================================================================================================

/// The structured-config `source` tag the AWS source claims.
const AWS_SOURCE_TAG: &str = "aws";

/// How the ambient AWS credential chain may be used when no scoped `profile` is declared.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AmbientFallbackPolicy {
    /// Ambient fallback is allowed; the source resolves the ambient chain and reports the fallback
    /// through the returned [`AwsAcquisition`] with a warning (the default).
    #[default]
    AllowWithWarning,
    /// Ambient fallback is refused: a config with no scoped `profile` is a **hard**, fail-closed
    /// [`CredentialError::Credential`], so a deployment can require a declared scoped identity.
    Deny,
}

/// How a set of AWS credentials was acquired — the *outcome* the acquisition audit records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AwsAcquisition {
    /// Credentials came from the declared scoped `profile`.
    Profile(String),
    /// Credentials came from the named `credsd` environment. Never an ambient fallback, so it
    /// carries no warning.
    Credsd(String),
    /// No scoped `profile` was declared; the ambient provider chain was used (allowed-with-warning).
    AmbientFallback,
}

impl AwsAcquisition {
    /// The operator-facing warning for this acquisition, if any. Present only for
    /// [`AmbientFallback`](Self::AmbientFallback) — a scoped profile or a `credsd` environment names
    /// its identity, so neither needs a warning.
    pub(crate) fn warning(&self) -> Option<&'static str> {
        match self {
            AwsAcquisition::Profile(_) | AwsAcquisition::Credsd(_) => None,
            AwsAcquisition::AmbientFallback => Some(
                "AWS ambient credential chain used (no scoped profile declared); \
                 prefer a declared scoped identity to shrink blast radius",
            ),
        }
    }
}

/// The result of resolving an AWS credential reference: the [`AwsSessionCredentials`]
/// material plus how it was [acquired](AwsAcquisition).
pub(crate) struct AwsResolution {
    /// The resolved credentials, wiped on drop.
    pub credentials: Zeroizing<AwsSessionCredentials>,
    /// How the credentials were acquired — recorded by the caller's acquisition audit.
    pub acquisition: AwsAcquisition,
}

impl std::fmt::Debug for AwsResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The credentials redact themselves, but keep the field explicitly redacted so a change to
        // their Debug can never make this leak.
        f.debug_struct("AwsResolution")
            .field("credentials", &"[REDACTED]")
            .field("acquisition", &self.acquisition)
            .finish()
    }
}

/// Materializes AWS session credentials — the seam a real SDK-backed provider chain plugs into.
trait AwsCredentialProvider: Send + Sync {
    /// Resolve credentials for `profile` (or the ambient chain when `None`).
    fn provide(&self, profile: Option<&str>) -> Result<AwsSessionCredentials>;
}

/// The default provider: the ambient `AWS_*` environment, or the operator's named profile.
///
/// **It delegates rather than replacing, so ambient behaviour is unchanged.** With no profile it is
/// `EnvAwsProvider` exactly. With one it resolves the operator's AWS configuration, which
/// `EnvAwsProvider` refuses to do — correctly, since it cannot honour a named identity and must not
/// substitute another. That refusal left `aws://<profile>` with no provider at all, so every such
/// route failed at its first request.
struct DefaultAwsProvider;

impl AwsCredentialProvider for DefaultAwsProvider {
    fn provide(&self, profile: Option<&str>) -> Result<AwsSessionCredentials> {
        match profile {
            None => EnvAwsProvider.provide(None),
            Some(profile) => crate::sources::aws_profile::resolve_profile(profile),
        }
    }
}

/// The v1 default provider: reads the ambient `AWS_*` environment credentials **synchronously**.
struct EnvAwsProvider;

impl AwsCredentialProvider for EnvAwsProvider {
    fn provide(&self, profile: Option<&str>) -> Result<AwsSessionCredentials> {
        // Refuse rather than substitute. This provider reads the ambient `AWS_*` environment and has
        // no way to honour a named profile, so accepting one would sign with whatever identity the
        // host carries while `AwsAcquisition::Profile(..)` attests the opposite — and `warning()`
        // returns `None` when a profile was declared, so that substitution reaches neither stderr nor
        // the audit record. An operator who names an identity gets that identity or an error.
        if let Some(profile) = profile {
            return Err(CredentialError::Credential(format!(
                "the ambient AWS provider cannot sign as the declared profile {profile:?}: it reads \
                 AWS_* from the environment. Remove the profile to sign with the ambient identity, \
                 or supply a provider that can resolve it"
            )));
        }

        let non_empty = |name: &str| env::var(name).ok().filter(|v| !v.is_empty());
        match (
            non_empty("AWS_ACCESS_KEY_ID"),
            non_empty("AWS_SECRET_ACCESS_KEY"),
        ) {
            (Some(access_key_id), Some(secret_access_key)) => Ok(AwsSessionCredentials {
                access_key_id,
                secret_access_key,
                // `Some` only when AWS_SESSION_TOKEN is set and non-empty (STS/assumed-role); a
                // long-lived IAM user key has none, so `None` — never an empty-string sentinel.
                session_token: non_empty("AWS_SESSION_TOKEN"),
                region: non_empty("AWS_REGION").or_else(|| non_empty("AWS_DEFAULT_REGION")),
            }),
            // No ambient credentials means the provider chain is unreachable → KeystoreAccess.
            _ => Err(CredentialError::KeystoreAccess(
                "AWS provider chain unreachable: no credentials found in the environment"
                    .to_string(),
            )),
        }
    }
}

/// The AWS credential source: selected by structured config (`source = "aws"`, optional `profile`),
/// returns [`AwsSessionCredentials`] material.
pub(crate) struct AwsSource {
    provider: Box<dyn AwsCredentialProvider>,
    ambient_policy: AmbientFallbackPolicy,
}

impl AwsSource {
    /// Construct the source backed by the v1 ambient environment provider, with the default
    /// allowed-with-warning ambient-fallback policy.
    pub(crate) fn new() -> Self {
        Self::with_policy(AmbientFallbackPolicy::default())
    }

    /// Construct the source backed by the v1 ambient environment provider, with an explicit
    /// ambient-fallback `policy`.
    pub(crate) fn with_policy(policy: AmbientFallbackPolicy) -> Self {
        Self {
            provider: Box::new(DefaultAwsProvider),
            ambient_policy: policy,
        }
    }

    /// Construct the source backed by a custom provider — the test seam for exercising the
    /// config-parse, ambient-fallback, and error-mapping paths without a real AWS environment.
    #[cfg(test)]
    fn with_provider(
        provider: Box<dyn AwsCredentialProvider>,
        policy: AmbientFallbackPolicy,
    ) -> Self {
        Self {
            provider,
            ambient_policy: policy,
        }
    }

    /// Resolve an AWS credential reference to [`AwsSessionCredentials`] material.
    pub(crate) fn resolve(&self, loc: &Locator) -> Result<AwsResolution> {
        let profile = Self::parse_profile(loc)?;

        let (acquisition, provider_profile) = match &profile {
            Some(p) => (AwsAcquisition::Profile(p.clone()), Some(p.as_str())),
            None => {
                if self.ambient_policy == AmbientFallbackPolicy::Deny {
                    return Err(CredentialError::Credential(
                        "no scoped AWS profile declared and ambient fallback is disabled"
                            .to_string(),
                    ));
                }
                (AwsAcquisition::AmbientFallback, None)
            }
        };

        let credentials = self.provider.provide(provider_profile)?;
        Ok(AwsResolution {
            credentials: Zeroizing::new(credentials),
            acquisition,
        })
    }

    /// Extract the optional scoped `profile` from either locator form.
    fn parse_profile(loc: &Locator) -> Result<Option<String>> {
        match loc {
            Locator::Uri(uri) => {
                // The scheme is checked, not discarded. Without this, `split_once("://")` handed back
                // whatever followed *any* scheme and recorded the whole body as the scoped profile:
                // `env://AWS_THING` and `file:///etc/passwd` both became AWS signing routes signed
                // with the ambient identity, while the acquisition record attested a profile. It also
                // made `AmbientFallbackPolicy::Deny` unreachable, since this arm always yielded
                // `Some`. Mirrors the `Structured` arm's own `source` check below.
                let (scheme, body) = uri.split_once("://").ok_or_else(|| {
                    CredentialError::Credential(format!(
                        "malformed aws credential reference {uri:?} (expected `aws://<profile>`)"
                    ))
                })?;
                if scheme != AWS_SOURCE_TAG {
                    // The scheme is a non-secret source *kind*, so it may appear; the body may not.
                    return Err(CredentialError::Credential(format!(
                        "an aws route needs an aws:// reference, not {scheme:?}"
                    )));
                }
                Ok(Some(body.to_string()).filter(|profile| !profile.is_empty()))
            }
            Locator::Structured(fields) => {
                match fields.get("source").map(String::as_str) {
                    Some(AWS_SOURCE_TAG) => {}
                    _ => {
                        return Err(CredentialError::Credential(
                            "the aws source config must set source = \"aws\"".to_string(),
                        ));
                    }
                }
                Ok(fields.get("profile").filter(|p| !p.is_empty()).cloned())
            }
        }
    }
}

impl Default for AwsSource {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AwsSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The provider holds no secret material; keep the output a stable audit line naming only the
        // (non-secret) ambient-fallback policy.
        f.debug_struct("AwsSource")
            .field("ambient_policy", &self.ambient_policy)
            .finish_non_exhaustive()
    }
}

// ===================================================================================================
// credsd AWS delivery adapter
// ===================================================================================================

use super::credsd::{CredentialResult, CredsdClient, SESSION_CREDENTIALS_TYPE};

/// Turn one `credsd` `credential/get` result into [`AwsSessionCredentials`] for the signed-AWS
/// route. The one AWS-aware piece of the credsd path — the client itself names no type.
pub(crate) fn credsd_session_credentials(
    client: &CredsdClient,
    environment: &str,
) -> Result<AwsSessionCredentials> {
    session_credentials_from(client.get(environment)?, environment)
}

/// Map a `credsd` result onto [`AwsSessionCredentials`], asserting the material tag.
///
/// A material tag other than `session_credentials`, or a `session_credentials` payload with any empty
/// field, is a hard credential failure that surfaces no credentials. The token is `Some` and
/// the region is `None` — the signing region comes from the route host, never from credsd.
fn session_credentials_from(
    result: CredentialResult,
    environment: &str,
) -> Result<AwsSessionCredentials> {
    let mut material = result.material;
    if material.kind != SESSION_CREDENTIALS_TYPE {
        return Err(CredentialError::Credential(format!(
            "credsd environment {environment:?} returned {kind:?} material, but an AWS route needs \
             {SESSION_CREDENTIALS_TYPE}",
            kind = material.kind
        )));
    }
    // A daemon that returns session_credentials with an empty field would have the box sign a
    // malformed SigV4 request (an empty access key id, or an empty X-Amz-Security-Token), which AWS
    // rejects as its own error — so refuse here and keep every credsd failure a hard, credsd-named
    // one. Session credentials always carry all three fields.
    if material.access_key_id.is_empty()
        || material.secret_access_key.is_empty()
        || material.session_token.is_empty()
    {
        return Err(CredentialError::Credential(format!(
            "credsd environment {environment:?} returned session_credentials with an empty access \
             key id, secret access key, or session token"
        )));
    }
    // Move each field out rather than clone, so no transient second plaintext copy exists. `Material`
    // implements `Drop`, so a direct field move will not compile; `mem::take` transfers the
    // allocation and leaves an empty `String` its `Drop` still zeroizes (a no-op).
    Ok(AwsSessionCredentials {
        access_key_id: std::mem::take(&mut material.access_key_id),
        secret_access_key: std::mem::take(&mut material.secret_access_key),
        session_token: Some(std::mem::take(&mut material.session_token)),
        region: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // --- SigV4 signer --------------------------------------------------------

    fn fixed_creds() -> AwsSessionCredentials {
        // The canonical AWS SigV4 test-suite credentials (get-vanilla), with no session token.
        AwsSessionCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
            region: None,
        }
    }

    /// The signing-time integer date math reproduces the canonical `get-vanilla` timestamp.
    #[test]
    fn signing_time_formats_utc() {
        // 2015-08-30T12:36:00Z == 1440938160 Unix seconds.
        let t = SigningTime::from_unix_secs(1_440_938_160);
        assert_eq!(t.amz_date, "20150830T123600Z");
        assert_eq!(t.date_stamp, "20150830");
    }

    /// Signing with fixed credentials reproduces the published AWS `get-vanilla` SigV4
    /// test vector exactly, proving the canonical-request / string-to-sign / signing-key pipeline.
    #[test]
    fn sign_request_matches_get_vanilla_vector() {
        let time = SigningTime::from_unix_secs(1_440_938_160);
        let headers = [("Host".to_string(), "example.amazonaws.com".to_string())];
        let signed = sign_request_at(
            &fixed_creds(),
            "service",
            "us-east-1",
            "GET",
            "https://example.amazonaws.com/",
            &headers,
            b"",
            &time,
        )
        .unwrap();

        let authorization = signed
            .iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.as_str())
            .expect("Authorization header present");

        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        );
        // The signer also returns the date header it signed; no security-token header without one.
        assert!(
            signed
                .iter()
                .any(|(k, v)| k == "X-Amz-Date" && v.as_str() == "20150830T123600Z")
        );
        assert!(!signed.iter().any(|(k, _)| k == "X-Amz-Security-Token"));
    }

    /// A session token is signed (appears in `SignedHeaders`) and returned as an `X-Amz-Security-Token`
    /// header. Signing is deterministic for fixed inputs.
    #[test]
    fn sign_request_signs_and_returns_session_token() {
        let creds = AwsSessionCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: Some("SESSIONTOKEN123".to_string()),
            region: None,
        };
        let time = SigningTime::from_unix_secs(1_440_938_160);
        let headers = [("Host".to_string(), "example.amazonaws.com".to_string())];
        let signed = sign_request_at(
            &creds,
            "service",
            "us-east-1",
            "GET",
            "https://example.amazonaws.com/",
            &headers,
            b"",
            &time,
        )
        .unwrap();

        let authorization = signed
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap()
            .1
            .to_string();
        assert!(
            authorization.contains("SignedHeaders=host;x-amz-date;x-amz-security-token"),
            "session token must be in the signed headers: {authorization}"
        );
        assert!(
            signed
                .iter()
                .any(|(k, v)| k == "X-Amz-Security-Token" && v.as_str() == "SESSIONTOKEN123"),
            "the session token must be returned as a header"
        );
        // The secret access key never appears in any returned header.
        for (_, v) in &signed {
            assert!(
                !v.contains("wJalrXUtnFEMI"),
                "secret key leaked: {}",
                v.as_str()
            );
        }
    }

    /// A `None` session token signs with no `X-Amz-Security-Token`, byte-for-byte identical
    /// to the get-vanilla vector — the `Option` shape preserves the empty-string sentinel's behavior.
    #[test]
    fn sign_request_omits_security_token_when_none() {
        let time = SigningTime::from_unix_secs(1_440_938_160);
        let headers = [("Host".to_string(), "example.amazonaws.com".to_string())];
        // fixed_creds() carries session_token: None.
        let signed = sign_request_at(
            &fixed_creds(),
            "service",
            "us-east-1",
            "GET",
            "https://example.amazonaws.com/",
            &headers,
            b"",
            &time,
        )
        .unwrap();
        assert!(!signed.iter().any(|(k, _)| k == "X-Amz-Security-Token"));
        let authorization = signed.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert!(authorization.1.contains("SignedHeaders=host;x-amz-date,"));
    }

    /// S3 rejects a request without `x-amz-content-sha256` (`400 InvalidRequest:
    /// Missing required header`), and the egress boundary strips any inbound one
    /// so a workload cannot choose the value. The signer therefore authors it for
    /// S3: attached to the outbound request, carrying the hash of the body being
    /// forwarded, and inside `SignedHeaders` so the signature covers it.
    #[test]
    fn sign_request_signs_and_attaches_payload_hash_for_s3() {
        let time = SigningTime::from_unix_secs(1_440_938_160);
        let headers = [("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];
        let body = b"payload-bytes";
        let signed = sign_request_at(
            &fixed_creds(),
            "s3",
            "us-east-1",
            "PUT",
            "https://s3.us-east-1.amazonaws.com/bucket/key",
            &headers,
            body,
            &time,
        )
        .unwrap();

        let attached = signed
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-content-sha256"))
            .expect("S3 request carries the payload-hash header");
        assert_eq!(
            attached.1.as_str(),
            sha256_hex(body),
            "the attached hash covers the forwarded body"
        );

        let authorization = signed
            .iter()
            .find(|(k, _)| k == "Authorization")
            .expect("Authorization present");
        assert!(
            authorization.1.contains("x-amz-content-sha256"),
            "the payload hash must be signed, not merely attached: {}",
            authorization.1.as_str()
        );
    }

    #[test]
    fn encoded_query_and_header_whitespace_match_sigv4_canonicalization() {
        assert_eq!(
            canonical_query("prefix=a%20b&marker=x%2Fy&prefix=c%2Bd"),
            "marker=x%2Fy&prefix=a%20b&prefix=c%2Bd"
        );
        assert_eq!(canonical_query("b=1&a=/+&a=%2f"), "a=%2f&a=/+&b=1");
        assert_eq!(canonical_query("b=1&&a=2"), "=&a=2&b=1");
        assert_eq!(canonical_header_value(" a\t  b \t c "), "a b c");
        let time = SigningTime::from_unix_secs(1_440_938_160);
        let headers = [("Host".to_string(), "example.amazonaws.com".to_string())];
        let signed = sign_request_at(
            &fixed_creds(),
            "service",
            "us-east-1",
            "GET",
            "https://example.amazonaws.com/?prefix=a%20b&marker=x%2Fy&prefix=c%2Bd",
            &headers,
            b"",
            &time,
        )
        .unwrap();
        let authorization = signed
            .iter()
            .find(|(name, _)| name == "Authorization")
            .unwrap();
        assert!(authorization.1.ends_with(
            "Signature=106b05d0ddfbf90249ce1f30ee3da7bd20f2a898dc1dc08de2c801e2433027a8"
        ));
        let mut tabbed = headers.to_vec();
        tabbed.push(("X-Test".into(), " a\t  b \t c ".into()));
        let mut normalized = headers.to_vec();
        normalized.push(("X-Test".into(), "a b c".into()));
        let sign = |headers: &[(String, String)]| {
            sign_request_at(
                &fixed_creds(),
                "service",
                "us-east-1",
                "GET",
                "https://example.amazonaws.com/",
                headers,
                b"",
                &time,
            )
            .unwrap()
        };
        assert_eq!(sign(&tabbed), sign(&normalized));
    }

    /// ...and only for S3. The AWS SDKs scope the header to an S3-specific signer
    /// (botocore's `S3SigV4Auth`, not the base `SigV4Auth`), and signing it
    /// everywhere would diverge from the published `get-vanilla` vector.
    #[test]
    fn sign_request_omits_payload_hash_for_non_s3_services() {
        let time = SigningTime::from_unix_secs(1_440_938_160);
        let headers = [(
            "Host".to_string(),
            "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
        )];
        let signed = sign_request_at(
            &fixed_creds(),
            "bedrock",
            "us-east-1",
            "POST",
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/invoke",
            &headers,
            b"{}",
            &time,
        )
        .unwrap();

        assert!(
            !signed
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-content-sha256")),
            "non-S3 services must not carry the payload-hash header"
        );
        let authorization = signed
            .iter()
            .find(|(k, _)| k == "Authorization")
            .expect("Authorization present");
        assert!(!authorization.1.contains("x-amz-content-sha256"));
    }

    /// An empty-string `Some("")` session token is still treated as "no token" — the `Option` shape
    /// keeps the old empty-string sentinel's behavior for a defensively-constructed value.
    #[test]
    fn sign_request_treats_empty_session_token_as_absent() {
        let creds = AwsSessionCredentials {
            session_token: Some(String::new()),
            ..fixed_creds()
        };
        let time = SigningTime::from_unix_secs(1_440_938_160);
        let headers = [("Host".to_string(), "example.amazonaws.com".to_string())];
        let signed = sign_request_at(
            &creds,
            "service",
            "us-east-1",
            "GET",
            "https://example.amazonaws.com/",
            &headers,
            b"",
            &time,
        )
        .unwrap();
        assert!(!signed.iter().any(|(k, _)| k == "X-Amz-Security-Token"));
    }

    /// The signer derives a `host` header from the URL when the caller did not supply one, so the
    /// signature always covers the host.
    #[test]
    fn sign_request_derives_host_from_url() {
        let time = SigningTime::from_unix_secs(1_440_938_160);
        let signed = sign_request_at(
            &fixed_creds(),
            "service",
            "us-east-1",
            "GET",
            "https://example.amazonaws.com/",
            &[], // no host header supplied
            b"",
            &time,
        )
        .unwrap();
        let authorization = signed
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap()
            .1
            .to_string();
        // Same vector as get-vanilla: deriving the host reproduces the identical signature.
        assert!(
            authorization.contains("SignedHeaders=host;x-amz-date"),
            "{authorization}"
        );
        assert!(
            authorization.ends_with(
                "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
            ),
            "{authorization}"
        );
    }

    /// Empty service or region, or a URL with no host, is a hard, fail-closed error.
    #[test]
    fn sign_request_rejects_missing_scope_or_host() {
        let time = SigningTime::from_unix_secs(1_440_938_160);
        let creds = fixed_creds();
        let url = "https://example.amazonaws.com/";
        let host = [("Host".to_string(), "example.amazonaws.com".to_string())];

        for (service, region, url) in [
            ("", "us-east-1", url),
            ("service", "", url),
            ("service", "us-east-1", "https:///"),
        ] {
            let err = sign_request_at(&creds, service, region, "GET", url, &host, b"", &time)
                .unwrap_err();
            assert!(
                !err.is_soft(),
                "must fail closed for {service:?}/{region:?}/{url:?}"
            );
        }
    }

    // --- AWS source: config parse + acquisition ------------------------------

    /// A provider that records the profile it was handed and returns fixed credentials.
    struct RecordingProvider(std::sync::Mutex<Vec<Option<String>>>);
    impl AwsCredentialProvider for RecordingProvider {
        fn provide(&self, profile: Option<&str>) -> Result<AwsSessionCredentials> {
            self.0.lock().unwrap().push(profile.map(str::to_string));
            Ok(AwsSessionCredentials {
                access_key_id: "AKIA".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: Some("token".to_string()),
                region: Some("us-west-2".to_string()),
            })
        }
    }

    /// A provider that always reports the chain unreachable.
    struct UnreachableProvider;
    impl AwsCredentialProvider for UnreachableProvider {
        fn provide(&self, _profile: Option<&str>) -> Result<AwsSessionCredentials> {
            Err(CredentialError::KeystoreAccess("chain down".to_string()))
        }
    }

    fn structured(pairs: &[(&str, &str)]) -> Locator {
        let fields: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Locator::structured(fields).unwrap()
    }

    /// `aws://<profile>` names the same profile as the structured form: both spellings reach
    /// the provider with the same scope, so config can carry a plain string.
    #[test]
    fn uri_and_structured_forms_name_the_same_profile() {
        for locator in [
            Locator::parse_uri("aws://prod").unwrap(),
            structured(&[("source", "aws"), ("profile", "prod")]),
        ] {
            assert_eq!(
                AwsSource::parse_profile(&locator).unwrap(),
                Some("prod".to_string()),
                "locator={locator:?}"
            );
            // Both dispatch to this source by the same routing key.
            assert_eq!(locator.scheme(), AWS_SOURCE_TAG);
        }
    }

    /// Bare `aws://` cannot be written: `parse_uri` rejects an empty body, so the URI form has no
    /// spelling for "use whatever credentials are ambient". Ambient stays reachable only
    /// through the structured form, and only when the policy permits it.
    #[test]
    fn the_uri_form_cannot_request_ambient_credentials() {
        assert!(
            Locator::parse_uri("aws://").is_err(),
            "an empty profile body must not parse"
        );
        // The structured form can omit the profile, which is what ambient fallback means.
        assert_eq!(
            AwsSource::parse_profile(&structured(&[("source", "aws")])).unwrap(),
            None
        );
    }

    /// `source = "aws"` with a `profile` resolves to `Aws` material, forwards the profile to
    /// the provider, and records a scoped acquisition.
    #[test]
    fn resolve_structured_profile_returns_aws_material() {
        let recorder = std::sync::Arc::new(RecordingProvider(std::sync::Mutex::new(Vec::new())));
        struct Forward(std::sync::Arc<RecordingProvider>);
        impl AwsCredentialProvider for Forward {
            fn provide(&self, p: Option<&str>) -> Result<AwsSessionCredentials> {
                self.0.provide(p)
            }
        }
        let src = AwsSource::with_provider(
            Box::new(Forward(recorder.clone())),
            AmbientFallbackPolicy::AllowWithWarning,
        );

        let resolution = src
            .resolve(&structured(&[("source", "aws"), ("profile", "prod")]))
            .unwrap();

        assert!(!resolution.credentials.access_key_id.is_empty());
        assert_eq!(
            resolution.acquisition,
            AwsAcquisition::Profile("prod".to_string())
        );
        assert!(resolution.acquisition.warning().is_none());
        assert_eq!(
            recorder.0.lock().unwrap().as_slice(),
            [Some("prod".to_string())]
        );
    }

    /// No `profile` → ambient fallback, allowed-with-warning, still returns `Aws` (never a None
    /// sentinel), and the provider is called with `None`.
    #[test]
    fn resolve_without_profile_falls_back_to_ambient_with_warning() {
        let recorder = std::sync::Arc::new(RecordingProvider(std::sync::Mutex::new(Vec::new())));
        struct Forward(std::sync::Arc<RecordingProvider>);
        impl AwsCredentialProvider for Forward {
            fn provide(&self, p: Option<&str>) -> Result<AwsSessionCredentials> {
                self.0.provide(p)
            }
        }
        let src = AwsSource::with_provider(
            Box::new(Forward(recorder.clone())),
            AmbientFallbackPolicy::AllowWithWarning,
        );

        let resolution = src.resolve(&structured(&[("source", "aws")])).unwrap();

        assert!(!resolution.credentials.access_key_id.is_empty());
        assert_eq!(resolution.acquisition, AwsAcquisition::AmbientFallback);
        assert!(
            resolution.acquisition.warning().is_some(),
            "ambient fallback must warn"
        );
        assert_eq!(recorder.0.lock().unwrap().as_slice(), [None]);
    }

    /// A provider that panics if it is ever reached.
    struct PanicProvider;

    impl AwsCredentialProvider for PanicProvider {
        fn provide(&self, _p: Option<&str>) -> Result<AwsSessionCredentials> {
            panic!("the provider must not be reached when the config is refused");
        }
    }

    /// With the tightened `Deny` policy, a config with no scoped profile is a hard refusal —
    /// the provider is never consulted.
    #[test]
    fn resolve_without_profile_is_refused_under_deny_policy() {
        let src = AwsSource::with_provider(Box::new(PanicProvider), AmbientFallbackPolicy::Deny);
        let err = src.resolve(&structured(&[("source", "aws")])).unwrap_err();
        assert!(!err.is_soft(), "denied ambient fallback must fail closed");
    }

    /// A non-`aws` URI scheme or source tag is a hard config error.
    #[test]
    fn resolve_rejects_wrong_form_or_source() {
        let src = AwsSource::with_provider(
            Box::new(PanicProvider),
            AmbientFallbackPolicy::AllowWithWarning,
        );

        for locator in [
            Locator::parse_uri("env://AWS_THING").unwrap(),
            Locator::parse_uri("file:///etc/passwd").unwrap(),
            Locator::parse_uri("garbage://x").unwrap(),
        ] {
            let err = src
                .resolve(&locator)
                .expect_err("a non-aws scheme is not an aws route");
            assert!(!err.is_soft(), "a wrong scheme fails closed");
            assert!(
                !err.to_string().contains("passwd"),
                "the locator body must not leak: {err}"
            );
        }

        let wrong = structured(&[("source", "gcp"), ("profile", "prod")]);
        let err = src
            .resolve(&wrong)
            .expect_err("a non-aws source tag is refused");
        assert!(!err.is_soft());
    }

    /// The shipped provider refuses a profile it cannot honour.
    #[test]
    fn the_ambient_provider_refuses_a_declared_profile() {
        let err = EnvAwsProvider
            .provide(Some("prod"))
            .expect_err("the ambient provider cannot sign as a named profile");
        assert!(!err.is_soft(), "an unhonourable profile fails closed");
        assert!(
            err.to_string().contains("prod"),
            "the refusal names the profile: {err}"
        );
    }

    /// A provider-chain reachability failure propagates as `KeystoreAccess`, unchanged.
    #[test]
    fn resolve_maps_unreachable_chain_to_keystore_access() {
        let src = AwsSource::with_provider(
            Box::new(UnreachableProvider),
            AmbientFallbackPolicy::AllowWithWarning,
        );
        let err = src.resolve(&structured(&[("source", "aws")])).unwrap_err();
        assert!(!err.is_soft());
        assert!(
            matches!(err, CredentialError::KeystoreAccess(_)),
            "got {err:?}"
        );
    }

    /// The resolution's `Debug` redacts the material and shows only the non-secret acquisition.
    #[test]
    fn resolution_debug_redacts_material() {
        let src = AwsSource::with_provider(
            Box::new(RecordingProvider(std::sync::Mutex::new(Vec::new()))),
            AmbientFallbackPolicy::AllowWithWarning,
        );
        let resolution = src
            .resolve(&structured(&[("source", "aws"), ("profile", "prod")]))
            .unwrap();
        let rendered = format!("{resolution:?}");
        assert!(rendered.contains("[REDACTED]"), "got {rendered}");
        assert!(!rendered.contains("secret"), "material leaked: {rendered}");
        assert!(
            rendered.contains("prod"),
            "acquisition should be visible: {rendered}"
        );
    }

    // --- credsd AWS delivery adapter -----------------------------------------

    use super::super::credsd::Material;

    /// One `credsd` result carrying `kind` and a session token.
    fn credsd_result(kind: &str, session_token: &str) -> CredentialResult {
        CredentialResult {
            material: Material {
                kind: kind.to_string(),
                access_key_id: "ASIACREDSDEXAMPLE".to_string(),
                secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
                session_token: session_token.to_string(),
            },
        }
    }

    /// `session_credentials` maps onto the three fields, token `Some`, region `None`.
    #[test]
    fn session_credentials_map_onto_aws_credentials() {
        let creds = session_credentials_from(credsd_result(SESSION_CREDENTIALS_TYPE, "tok"), "dev")
            .expect("session_credentials material maps");
        assert_eq!(creds.access_key_id, "ASIACREDSDEXAMPLE");
        assert_eq!(
            creds.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(
            creds.session_token.as_deref(),
            Some("tok"),
            "the token is Some"
        );
        assert_eq!(
            creds.region, None,
            "the signing region comes from the route host"
        );
    }

    /// Any other material type is a hard credential failure that surfaces no credentials.
    #[test]
    fn a_non_session_credentials_type_is_refused() {
        let error = session_credentials_from(credsd_result("api_key", ""), "prod-inference")
            .expect_err("a non-session_credentials type must fail");
        assert!(
            matches!(error, CredentialError::Credential(_)),
            "a hard credential failure"
        );
        assert!(
            error.to_string().contains("prod-inference"),
            "the error names the environment"
        );
        assert!(
            !error.to_string().contains("wJalr"),
            "no material in the message"
        );
    }

    /// A session_credentials payload with any empty field — key id, secret, or session token — is
    /// refused, so the box never signs a malformed SigV4 request with empty credentials.
    #[test]
    fn empty_aws_fields_are_refused() {
        for (access_key_id, secret_access_key, session_token) in [
            ("", "wJalrSecret", "tok"),
            ("ASIA", "", "tok"),
            ("ASIA", "wJalrSecret", ""),
        ] {
            let result = CredentialResult {
                material: Material {
                    kind: SESSION_CREDENTIALS_TYPE.to_string(),
                    access_key_id: access_key_id.to_string(),
                    secret_access_key: secret_access_key.to_string(),
                    session_token: session_token.to_string(),
                },
            };
            let error = session_credentials_from(result, "prod-inference")
                .expect_err("empty AWS fields must fail closed");
            assert!(matches!(error, CredentialError::Credential(_)));
            assert!(
                error.to_string().contains("prod-inference"),
                "names the environment: {error}"
            );
        }
    }

    /// A credsd-vended credential signs to the same bytes an aws:// route would, at a fixed
    /// time — the credsd path feeds the identical signer, so only the credential source differs.
    #[test]
    fn credsd_credentials_sign_identically_to_an_aws_route() {
        let material_token = "FQoGZXIvYXdzEXAMPLETOKEN";
        // The same credentials, reached two ways: the AWS provider seam and the credsd adapter.
        let via_aws = AwsSessionCredentials {
            access_key_id: "ASIACREDSDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: Some(material_token.to_string()),
            // An aws:// route may carry a region hint; the signer ignores it, deriving from the host.
            region: Some("us-west-2".to_string()),
        };
        let via_credsd = session_credentials_from(
            credsd_result(SESSION_CREDENTIALS_TYPE, material_token),
            "prod",
        )
        .expect("session_credentials map");

        let time = SigningTime::from_unix_secs(1_440_938_160);
        let headers = [(
            "Host".to_string(),
            "bedrock-runtime.us-west-2.amazonaws.com".to_string(),
        )];
        let sign = |creds: &AwsSessionCredentials| {
            sign_request_at(
                creds,
                "bedrock",
                "us-west-2",
                "POST",
                "https://bedrock-runtime.us-west-2.amazonaws.com/model/invoke",
                &headers,
                b"{}",
                &time,
            )
            .expect("signing succeeds")
        };
        assert_eq!(
            sign(&via_aws),
            sign(&via_credsd),
            "identical credentials must sign to identical bytes regardless of source"
        );
    }
}
