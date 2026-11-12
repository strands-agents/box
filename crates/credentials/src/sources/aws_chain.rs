//! The SDK-backed AWS credential provider, driven on a dedicated worker thread.
//!
//! Both `aws://` forms resolve through the AWS SDK
//! (docs/design/decisions.md#a-provider-refuses-an-identity-it-cannot-honour): a bare `aws://`
//! resolves the default credential provider chain, and `aws://PROFILE` pins that same chain to the
//! named profile. See the crate AGENTS.md for the worker, cache, region, and timeout design.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use zeroize::Zeroizing;

use crate::{AwsSessionCredentials, CredentialError, Result};

/// When the cached credentials stop being valid. `None` is a credential the SDK gave no expiry for.
type Expiry = Option<SystemTime>;

/// A resolved credential and its expiry.
type Resolved = (AwsSessionCredentials, Expiry);

/// The cache key: the scoped profile name, or `None` for the bare default chain. One slot per
/// identity, so a bare route and a named profile (or two named profiles) never evict each other.
type ProfileKey = Option<String>;

/// How long before expiry a resolve is retried, so a request never signs with an expired token.
const EXPIRY_BUFFER: Duration = Duration::from_secs(5 * 60);

/// How long a caller waits for the worker before the resolve is a hard error.
const CALLER_DEADLINE: Duration = Duration::from_secs(10);

/// How long one resolve may run on the worker before it is a hard error, shorter than
/// [`CALLER_DEADLINE`] so the worker thread recovers. A `credential_process` helper the AWS SDK
/// does not time out cannot wedge the chain for the life of the box past this bound.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

// ===================================================================================================
// The refresh cache
// ===================================================================================================

/// Holds the resolved credentials and their expiry, and refreshes near expiry.
///
/// `resolve` resolves the chain, and `now` is injectable so the refresh logic tests with a fake
/// clock. The cached credential is wiped on drop.
struct RefreshCache<R, N> {
    resolve: R,
    now: N,
    cached: HashMap<ProfileKey, (Zeroizing<AwsSessionCredentials>, Expiry)>,
}

impl<R, N> RefreshCache<R, N>
where
    R: FnMut(Option<&str>) -> Result<Resolved>,
    N: Fn() -> SystemTime,
{
    /// A cache that resolves through `resolve` and reads the clock through `now`.
    fn new(resolve: R, now: N) -> Self {
        Self {
            resolve,
            now,
            cached: HashMap::new(),
        }
    }

    /// Serve the cached credentials for `profile` while valid; refresh inside the expiry buffer; on
    /// a failed refresh serve still-valid cached, else return the hard error. Each `profile` key has
    /// its own slot.
    fn provide(&mut self, profile: Option<&str>) -> Result<AwsSessionCredentials> {
        let key: ProfileKey = profile.map(str::to_string);
        if let Some((credentials, expiry)) = self.cached.get(&key)
            && !should_refresh((self.now)(), *expiry)
        {
            return Ok((**credentials).clone());
        }
        match (self.resolve)(profile) {
            // A resolve can take real time (a `credential_process` helper, an STS round trip), so
            // read the clock again rather than reusing the pre-resolve instant. A freshly resolved
            // credential that is already expired must not displace a still-valid cached one.
            Ok((credentials, expiry)) if still_valid((self.now)(), expiry) => {
                self.cached
                    .insert(key, (Zeroizing::new(credentials.clone()), expiry));
                Ok(credentials)
            }
            Ok((credentials, _expired)) => match self.cached.get(&key) {
                Some((cached, expiry)) if still_valid((self.now)(), *expiry) => {
                    Ok((**cached).clone())
                }
                // No valid cache to prefer: serve the resolved credential and let the upstream
                // reject it, rather than inventing a failure from a successful resolve.
                _ => Ok(credentials),
            },
            // On a failed refresh, serve the cached credential only if it is still valid *now* — one
            // that expired while the refresh ran is no longer a safe fallback.
            Err(error) => match self.cached.get(&key) {
                Some((credentials, expiry)) if still_valid((self.now)(), *expiry) => {
                    Ok((**credentials).clone())
                }
                _ => Err(error),
            },
        }
    }
}

/// Whether a cached credential is still valid at `now`. A non-expiring credential is always valid.
fn still_valid(now: SystemTime, expiry: Expiry) -> bool {
    match expiry {
        None => true,
        Some(expiry) => now < expiry,
    }
}

/// Whether a resolve is due at `now`: a credential inside its expiry buffer or expired, or any
/// non-expiring credential (which re-resolves every call so a rotated one is not pinned).
fn should_refresh(now: SystemTime, expiry: Expiry) -> bool {
    match expiry {
        None => true,
        Some(expiry) => now
            .checked_add(EXPIRY_BUFFER)
            .is_none_or(|deadline| deadline >= expiry),
    }
}

// ===================================================================================================
// The SDK-backed provider
// ===================================================================================================

/// One resolve request to the worker: the profile to resolve (`None` is the bare default chain), the
/// channel the worker replies on, and the instant the caller stops waiting, so the worker can skip a
/// resolve for a caller that already left.
struct Request {
    profile: ProfileKey,
    reply: Sender<Result<AwsSessionCredentials>>,
    deadline: Instant,
}

/// Resolves AWS credentials through the SDK on a dedicated worker thread, bare or named-profile.
pub(in crate::sources) struct SdkChainProvider {
    sender: Sender<Request>,
}

impl SdkChainProvider {
    /// The process-wide provider, started on first use.
    pub(in crate::sources) fn shared() -> &'static SdkChainProvider {
        static PROVIDER: OnceLock<SdkChainProvider> = OnceLock::new();
        PROVIDER.get_or_init(|| SdkChainProvider::spawn(Box::new(real_setup)))
    }

    /// Resolve `profile` (or the bare default chain when `None`), waiting up to [`CALLER_DEADLINE`]
    /// for the worker.
    pub(in crate::sources) fn provide(
        &self,
        profile: Option<&str>,
    ) -> Result<AwsSessionCredentials> {
        self.provide_within(profile, CALLER_DEADLINE)
    }

    /// Spawn the worker.
    ///
    /// A thread that cannot start drops the closure with `receiver`, so every send then fails and
    /// `provide` returns a hard error rather than panicking in the trusted process.
    fn spawn(setup: SetupFn) -> Self {
        let (sender, receiver) = mpsc::channel::<Request>();
        let _ = thread::Builder::new()
            .name("aws-default-chain".to_string())
            .spawn(move || worker(receiver, setup));
        Self { sender }
    }

    /// Send a request for `profile` and wait up to `deadline` for the worker's reply.
    fn provide_within(
        &self,
        profile: Option<&str>,
        deadline: Duration,
    ) -> Result<AwsSessionCredentials> {
        let (reply, reply_rx) = mpsc::channel();
        self.sender
            .send(Request {
                profile: profile.map(str::to_string),
                reply,
                deadline: Instant::now() + deadline,
            })
            .map_err(|_| {
                CredentialError::Credential(
                    "the AWS default-chain worker is not running".to_string(),
                )
            })?;
        match reply_rx.recv_timeout(deadline) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(CredentialError::Credential(
                "the AWS default credential chain did not resolve within the deadline".to_string(),
            )),
            Err(RecvTimeoutError::Disconnected) => Err(CredentialError::Credential(
                "the AWS default-chain worker stopped before replying".to_string(),
            )),
        }
    }

    /// A provider whose worker resolves through `resolve` rather than the real SDK chain — the test
    /// seam that exercises the worker, the runtime bridge, and the cache offline. `resolve` receives
    /// the requested profile.
    #[cfg(test)]
    fn with_resolver(
        resolve: impl FnMut(Option<&str>) -> Result<Resolved> + Send + 'static,
    ) -> Self {
        Self::spawn(Box::new(move || Ok(Box::new(resolve) as ResolveFn)))
    }
}

/// The resolve closure the worker drives each request, given the requested profile.
type ResolveFn = Box<dyn FnMut(Option<&str>) -> Result<Resolved> + Send>;

/// Runs once on the worker thread to build the resolve closure, or fails if the runtime cannot
/// start.
type SetupFn = Box<dyn FnOnce() -> Result<ResolveFn> + Send>;

/// The worker loop: set up once, then serve each request from the cache. A setup failure replies a
/// hard error to every request, so the failure surfaces on the first resolve and stays fail-closed.
fn worker(receiver: Receiver<Request>, setup: SetupFn) {
    match setup() {
        Err(error) => {
            let message = error.to_string();
            for request in receiver {
                let _ = request
                    .reply
                    .send(Err(CredentialError::Credential(message.clone())));
            }
        }
        Ok(resolve) => {
            let mut cache = RefreshCache::new(resolve, SystemTime::now);
            for request in receiver {
                // Skip a resolve for a caller that already timed out, so a slow or failing chain
                // does not run work for callers that have left and stack behind them.
                if Instant::now() >= request.deadline {
                    continue;
                }
                let _ = request
                    .reply
                    .send(cache.provide(request.profile.as_deref()));
            }
        }
    }
}

/// Build the runtime, the shared HTTP client, and the region once, and return a closure that
/// rebuilds the chain on each resolve. See the crate AGENTS.md for why the chain is rebuilt.
fn real_setup() -> Result<ResolveFn> {
    use aws_smithy_http_client::{Builder, tls};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CredentialError::Credential(format!(
                "could not start the AWS default-chain runtime: {error}"
            ))
        })?;
    let http_client = Builder::new()
        .tls_provider(tls::Provider::Rustls(
            tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https();
    // The region is read once from the environment, then the profile, then `us-east-1`. Both
    // providers read only variables and files, so the per-resolve rebuild never reaches instance
    // metadata. See the crate AGENTS.md.
    let region = runtime
        .block_on(
            aws_config::meta::region::RegionProviderChain::first_try(
                aws_config::environment::EnvironmentVariableRegionProvider::new(),
            )
            .or_else(aws_config::profile::ProfileFileRegionProvider::new())
            .region(),
        )
        .unwrap_or_else(|| aws_config::Region::from_static("us-east-1"));
    Ok(Box::new(move |profile: Option<&str>| {
        let http_client = http_client.clone();
        match profile {
            // A bare `aws://` resolves the SDK default chain: env keys, then the default profile,
            // then web identity, ECS, and IMDS. `without_region` carries the Tokio sleep
            // implementation (rt-tokio); a fresh config re-reads the profile files each resolve; and
            // `.region` pins the region so the rebuild never re-runs the region chain, which reaches
            // instance metadata.
            None => {
                let region = region.clone();
                resolve_once(&runtime, || {
                    let config = aws_config::provider_config::ProviderConfig::without_region()
                        .with_http_client(http_client.clone());
                    aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
                        .region(region.clone())
                        .configure(config)
                        .build()
                })
            }
            // `aws://PROFILE` resolves only that profile through a `ProfileFileCredentialsProvider`:
            // static keys, `credential_process`, assume-role, or web identity. It never reads the
            // ambient `AWS_*` keys or instance metadata, and a missing profile is a hard error, so a
            // named route signs as the profile it names or refuses, and the audit's `Profile(_)` is
            // true. The region is the profile's own (env first, then the named profile, then the
            // shared fallback), so an assume-role or web-identity STS call for a GovCloud, China, or
            // VPC-endpoint profile reaches the right endpoint. Both region providers read only env
            // and files, so this never reaches IMDS.
            Some(profile) => {
                let named_region = runtime
                    .block_on(
                        aws_config::meta::region::RegionProviderChain::first_try(
                            aws_config::environment::EnvironmentVariableRegionProvider::new(),
                        )
                        .or_else(
                            aws_config::profile::ProfileFileRegionProvider::builder()
                                .profile_name(profile)
                                .build(),
                        )
                        .region(),
                    )
                    .unwrap_or_else(|| region.clone());
                resolve_once(&runtime, || {
                    let config = aws_config::provider_config::ProviderConfig::without_region()
                        .with_region(Some(named_region))
                        .with_http_client(http_client.clone());
                    let provider = aws_config::profile::ProfileFileCredentialsProvider::builder()
                        .configure(&config)
                        .profile_name(profile)
                        .build();
                    async move { provider }
                })
            }
        }
    }))
}

/// Build a provider with `build_provider` and resolve it once under [`RESOLVE_TIMEOUT`], mapping an
/// unreachable, empty, or timed-out provider to [`CredentialError::KeystoreAccess`]. The timeout
/// keeps a stuck `credential_process` helper (which the SDK does not time out) from wedging the
/// worker past this bound; the worker thread is then free to serve the next request. The provider is
/// generic over `ProvideCredentials`, so a bare `aws://` resolves a `DefaultCredentialsChain` and a
/// named `aws://PROFILE` resolves a profile-only `ProfileFileCredentialsProvider`.
fn resolve_once<F, C, P>(runtime: &tokio::runtime::Runtime, build_provider: F) -> Result<Resolved>
where
    F: FnOnce() -> C,
    C: std::future::Future<Output = P>,
    P: aws_credential_types::provider::ProvideCredentials,
{
    resolve_within(runtime, RESOLVE_TIMEOUT, async move {
        let provider = build_provider().await;
        provider.provide_credentials().await
    })
}

/// Drive `resolve` on `runtime`, bounded by `timeout`. An elapsed timeout, or a provider error,
/// maps to a hard [`CredentialError::KeystoreAccess`]. The timeout is what frees the single worker
/// thread: the AWS SDK sets none on a `credential_process` helper, so without this a helper that
/// never returns would wedge the chain for the life of the box. Split from [`resolve_once`] so a
/// test drives the bound with a never-completing future, without the SDK or a real chain.
fn resolve_within(
    runtime: &tokio::runtime::Runtime,
    timeout: Duration,
    resolve: impl std::future::Future<
        Output = std::result::Result<
            aws_credential_types::Credentials,
            aws_credential_types::provider::error::CredentialsError,
        >,
    >,
) -> Result<Resolved> {
    let credentials = runtime
        .block_on(async { tokio::time::timeout(timeout, resolve).await })
        .map_err(|_elapsed| {
            CredentialError::KeystoreAccess(format!(
                "AWS credential resolution did not complete within {}s (a credential_process \
                 helper may be stuck)",
                timeout.as_secs().max(1)
            ))
        })?
        .map_err(|error| {
            CredentialError::KeystoreAccess(format!(
                "AWS default credential chain resolved no credentials: {}",
                // Walk the error's source chain, because the top-level `CredentialsError` message
                // hides the real cause. An SSO default profile, which this build does not resolve,
                // reads only as "not properly configured" at the top; the source names the missing
                // provider.
                error_chain(&error)
            ))
        })?;
    let expiry = credentials.expiry();
    Ok((
        AwsSessionCredentials {
            access_key_id: credentials.access_key_id().to_string(),
            secret_access_key: credentials.secret_access_key().to_string(),
            session_token: credentials.session_token().map(str::to_string),
            // The signing region comes from the route host, never from the chain.
            region: None,
        },
        expiry,
    ))
}

/// The full `: `-joined message chain of `error`, so a wrapped cause is not lost.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        message.push_str(": ");
        message.push_str(&inner.to_string());
        source = inner.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn creds(id: &str) -> AwsSessionCredentials {
        AwsSessionCredentials {
            access_key_id: id.to_string(),
            secret_access_key: "secret".to_string(),
            session_token: Some("token".to_string()),
            region: None,
        }
    }

    // --- RefreshCache (fake clock, fake resolve; no SDK, no network) ---------

    /// While the cached credentials are valid and outside the buffer, `provide` serves the cache
    /// without resolving again.
    #[test]
    fn cache_serves_valid_without_resolving() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0u32);
        let clock = Cell::new(base);
        let expiry = Some(base + Duration::from_secs(3600));
        let mut cache = RefreshCache::new(
            |_profile| {
                calls.set(calls.get() + 1);
                Ok((creds("AKIA1"), expiry))
            },
            || clock.get(),
        );

        assert_eq!(cache.provide(None).unwrap().access_key_id, "AKIA1");
        // A second call, still well before expiry, is served from the cache.
        assert_eq!(cache.provide(None).unwrap().access_key_id, "AKIA1");
        assert_eq!(calls.get(), 1, "the chain was resolved only once");
    }

    /// Inside the expiry buffer, `provide` resolves the chain again.
    #[test]
    fn cache_refreshes_within_expiry_buffer() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0u32);
        let clock = Cell::new(base);
        // The first resolve expires one hour out; the second returns a fresh id.
        let mut cache = RefreshCache::new(
            |_profile| {
                calls.set(calls.get() + 1);
                let id = format!("AKIA{}", calls.get());
                Ok((creds(&id), Some(clock.get() + Duration::from_secs(3600))))
            },
            || clock.get(),
        );

        assert_eq!(cache.provide(None).unwrap().access_key_id, "AKIA1");
        // Advance to within the buffer of the first expiry (3600 - 60 < 3600 - 300 window).
        clock.set(base + Duration::from_secs(3600) - Duration::from_secs(60));
        assert_eq!(
            cache.provide(None).unwrap().access_key_id,
            "AKIA2",
            "a provide inside the buffer resolves again"
        );
        assert_eq!(calls.get(), 2);
    }

    /// A non-expiring credential (no `Expiration`) re-resolves on every call, so a rotated file or
    /// environment credential is picked up rather than pinned for the life of the run.
    #[test]
    fn cache_reresolves_when_expiry_is_none() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0u32);
        let clock = Cell::new(base);
        let mut cache = RefreshCache::new(
            |_profile| {
                calls.set(calls.get() + 1);
                let id = format!("AKIA{}", calls.get());
                // No expiry, as a rotated static/session key in `~/.aws/credentials` carries.
                Ok((creds(&id), None))
            },
            || clock.get(),
        );

        assert_eq!(cache.provide(None).unwrap().access_key_id, "AKIA1");
        // The clock does not move, yet the next provide resolves again and sees the rotated value.
        assert_eq!(
            cache.provide(None).unwrap().access_key_id,
            "AKIA2",
            "a non-expiring credential is re-resolved, not served forever"
        );
        assert_eq!(calls.get(), 2);
    }

    /// Each profile key has its own cache slot: a bare resolve and a named profile do not evict
    /// each other, so one is served from cache while the other keeps its own value.
    #[test]
    fn cache_keys_by_profile() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0u32);
        let clock = Cell::new(base);
        let expiry = Some(base + Duration::from_secs(3600));
        // The resolved id echoes the requested profile, so the slot it lands in is visible.
        let mut cache = RefreshCache::new(
            |profile: Option<&str>| {
                calls.set(calls.get() + 1);
                Ok((creds(profile.unwrap_or("bare")), expiry))
            },
            || clock.get(),
        );

        assert_eq!(cache.provide(None).unwrap().access_key_id, "bare");
        assert_eq!(cache.provide(Some("prod")).unwrap().access_key_id, "prod");
        assert_eq!(calls.get(), 2, "two distinct profiles resolved once each");
        // Both are now cached independently; neither re-resolves and neither evicted the other.
        assert_eq!(cache.provide(None).unwrap().access_key_id, "bare");
        assert_eq!(cache.provide(Some("prod")).unwrap().access_key_id, "prod");
        assert_eq!(calls.get(), 2, "both served from their own slot");
    }

    /// A failed refresh while the cache is still valid serves the still-valid cached credentials.
    #[test]
    fn cache_serves_stale_valid_on_refresh_failure() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0u32);
        let clock = Cell::new(base);
        let expiry = Some(base + Duration::from_secs(3600));
        let mut cache = RefreshCache::new(
            |_profile| {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    Ok((creds("AKIA1"), expiry))
                } else {
                    Err(CredentialError::KeystoreAccess("metadata blip".to_string()))
                }
            },
            || clock.get(),
        );

        assert_eq!(cache.provide(None).unwrap().access_key_id, "AKIA1");
        // Move into the buffer but before expiry, so the refresh is attempted and fails.
        clock.set(base + Duration::from_secs(3600) - Duration::from_secs(60));
        assert_eq!(
            cache.provide(None).unwrap().access_key_id,
            "AKIA1",
            "a failed refresh serves the still-valid cached credentials"
        );
        assert_eq!(calls.get(), 2, "the refresh was attempted");
    }

    /// A failed refresh with an expired cache is a hard error.
    #[test]
    fn cache_errors_hard_when_expired_and_refresh_fails() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0u32);
        let clock = Cell::new(base);
        let expiry = Some(base + Duration::from_secs(3600));
        let mut cache = RefreshCache::new(
            |_profile| {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    Ok((creds("AKIA1"), expiry))
                } else {
                    Err(CredentialError::KeystoreAccess("chain down".to_string()))
                }
            },
            || clock.get(),
        );

        assert_eq!(cache.provide(None).unwrap().access_key_id, "AKIA1");
        // Past expiry: the cached credential is no longer valid, so a failed refresh is hard.
        clock.set(base + Duration::from_secs(7200));
        let error = cache.provide(None).unwrap_err();
        assert!(
            !error.is_soft(),
            "an expired cache with a failed refresh is hard"
        );
    }

    /// A refresh that fails *after* the cached credential expired during the resolve is a hard
    /// error, not a stale serve. The validity of the fallback is judged on the clock read after the
    /// resolve, not before it, so a resolve that runs past the expiry cannot revive the old value.
    #[test]
    fn cache_does_not_serve_a_cached_credential_that_expired_during_a_failed_refresh() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0u32);
        let clock = Cell::new(base);
        // The first resolve expires three seconds out; the second advances the clock four seconds
        // (the resolve "took" that long) and then fails.
        let mut cache = RefreshCache::new(
            |_profile| {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    Ok((creds("AKIA1"), Some(base + Duration::from_secs(3))))
                } else {
                    clock.set(clock.get() + Duration::from_secs(4));
                    Err(CredentialError::KeystoreAccess(
                        "refresh failed".to_string(),
                    ))
                }
            },
            || clock.get(),
        );

        assert_eq!(cache.provide(None).unwrap().access_key_id, "AKIA1");
        // The cached credential is still valid now (base), so the refresh is attempted; it fails
        // after moving the clock past the expiry, so the fallback must refuse rather than serve it.
        let error = cache.provide(None).unwrap_err();
        assert!(
            !error.is_soft(),
            "a credential that expired during the failed refresh is not a valid fallback: {error:?}"
        );
    }

    /// A freshly resolved credential that is already expired does not displace a still-valid cached
    /// one: the cache keeps serving the valid value rather than caching the expired resolve.
    #[test]
    fn cache_keeps_a_valid_credential_over_an_expired_fresh_resolve() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0u32);
        let clock = Cell::new(base);
        let mut cache = RefreshCache::new(
            |_profile| {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    // Valid for a long time, so it stays a valid fallback.
                    Ok((creds("AKIA1"), Some(base + Duration::from_secs(3600))))
                } else {
                    // A fresh resolve that is already expired.
                    Ok((creds("STALE"), Some(base - Duration::from_secs(1))))
                }
            },
            || clock.get(),
        );

        assert_eq!(cache.provide(None).unwrap().access_key_id, "AKIA1");
        // Inside the buffer, so a refresh is attempted; it returns an already-expired credential,
        // which must not replace the still-valid cached one.
        clock.set(base + Duration::from_secs(3600) - Duration::from_secs(60));
        assert_eq!(
            cache.provide(None).unwrap().access_key_id,
            "AKIA1",
            "an expired fresh resolve does not displace the valid cached credential"
        );
    }

    // --- SdkChainProvider (worker + channel; fake resolver, no SDK) ----------

    /// A resolve closure that blocks past the caller deadline yields a hard error rather than an
    /// unsigned request.
    #[test]
    fn sdk_provider_deadline_is_hard() {
        let provider = SdkChainProvider::with_resolver(|_profile| {
            // Block past the caller's (short, injected) deadline so the caller times out first.
            thread::sleep(Duration::from_secs(2));
            Ok((creds("AKIA"), None))
        });
        let error = provider
            .provide_within(None, Duration::from_millis(100))
            .unwrap_err();
        assert!(!error.is_soft(), "a deadline overrun is a hard error");
        assert!(
            error.to_string().contains("deadline"),
            "the error names the deadline: {error}"
        );
    }

    /// The worker skips the resolve for a caller whose deadline has already passed, so a slow or
    /// failing chain does not run work for callers that have left.
    #[test]
    fn sdk_provider_skips_a_caller_that_already_timed_out() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let resolves = Arc::new(AtomicUsize::new(0));
        let counter = resolves.clone();
        let provider = SdkChainProvider::with_resolver(move |_profile| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((creds("AKIA"), None))
        });
        // A zero deadline is already in the past when the worker dequeues the request.
        let error = provider
            .provide_within(None, Duration::ZERO)
            .expect_err("a timed-out caller gets a hard error, not credentials");
        assert!(!error.is_soft());
        // Give the worker a moment; it must not have run the resolve for the departed caller.
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            resolves.load(Ordering::SeqCst),
            0,
            "the resolve is skipped for a caller that already timed out"
        );
    }

    /// An empty chain result maps to `KeystoreAccess`, through the worker and the cache.
    #[test]
    fn sdk_provider_maps_empty_chain_to_keystore_access() {
        let provider = SdkChainProvider::with_resolver(|_profile| {
            Err(CredentialError::KeystoreAccess(
                "no credentials found".to_string(),
            ))
        });
        let error = provider.provide(None).unwrap_err();
        assert!(
            matches!(error, CredentialError::KeystoreAccess(_)),
            "an empty chain is KeystoreAccess: {error:?}"
        );
    }

    /// A named profile reaches the resolver as `Some(name)`, so `aws://PROFILE` resolves that
    /// profile rather than the bare chain.
    #[test]
    fn sdk_provider_resolves_the_requested_profile() {
        let provider = SdkChainProvider::with_resolver(|profile: Option<&str>| {
            Ok((creds(profile.unwrap_or("bare")), None))
        });
        assert_eq!(provider.provide(None).unwrap().access_key_id, "bare");
        assert_eq!(
            provider.provide(Some("prod")).unwrap().access_key_id,
            "prod",
            "a named profile is resolved as itself"
        );
    }

    /// After one resolve outlasts its caller's deadline, the worker thread recovers and serves the
    /// next request — a resolve that overran one caller does not wedge the chain for the box's life.
    /// This exercises `CALLER_DEADLINE` and worker reuse, not the per-resolve `RESOLVE_TIMEOUT`,
    /// which `resolve_within_cuts_off_a_resolve_that_never_completes` pins.
    #[test]
    fn sdk_provider_worker_recovers_when_a_resolve_outlasts_its_caller() {
        // The resolver blocks on the first call until the test releases it, then returns fast.
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let calls = std::cell::Cell::new(0u32);
        let provider = SdkChainProvider::with_resolver(move |_profile| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                // Hold the worker until the test has observed the first caller time out.
                let _ = release_rx.recv();
            }
            Ok((creds("AKIA"), None))
        });

        // First caller gives up quickly while the worker is still blocked inside the resolve.
        let error = provider
            .provide_within(None, Duration::from_millis(50))
            .expect_err("the first caller times out while the resolve is stuck");
        assert!(!error.is_soft());

        // Release the stuck resolve, then a fresh request must succeed on the recovered worker.
        release_tx.send(()).expect("release the worker");
        let resolved = provider
            .provide_within(None, Duration::from_secs(5))
            .expect("the worker recovered and served the next request");
        assert_eq!(resolved.access_key_id, "AKIA");
    }

    /// The per-resolve timeout bounds the wait even when the resolve never completes. A
    /// never-completing future stands in for a `credential_process` helper the SDK does not time
    /// out; `resolve_within` must return a hard error near its timeout rather than block forever.
    /// Run on a worker thread so deleting the `tokio::time::timeout` wrapper hangs that thread and
    /// trips `recv_timeout` here, rather than wedging the whole test binary.
    #[test]
    fn resolve_within_cuts_off_a_resolve_that_never_completes() {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a current-thread runtime");
            // A future that never resolves, of the chain's own output type.
            let never = std::future::pending::<
                std::result::Result<
                    aws_credential_types::Credentials,
                    aws_credential_types::provider::error::CredentialsError,
                >,
            >();
            let outcome = match resolve_within(&runtime, Duration::from_millis(50), never) {
                Err(error)
                    if !error.is_soft() && error.to_string().contains("did not complete") =>
                {
                    Ok(())
                }
                other => Err(format!("{other:?}")),
            };
            let _ = tx.send(outcome);
        });
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(())) => {}
            Ok(Err(unexpected)) => {
                panic!("resolve_within returned an unexpected result: {unexpected}")
            }
            Err(_) => panic!(
                "resolve_within did not return within 2s — RESOLVE_TIMEOUT did not bound the wait"
            ),
        }
    }

    /// `provide` is callable from a thread already running a runtime, with no "runtime within a
    /// runtime" panic, because the worker owns the runtime and the caller only waits on a channel.
    #[test]
    fn sdk_provider_is_callable_from_a_runtime_thread() {
        let provider = SdkChainProvider::with_resolver(|_profile| Ok((creds("AKIA"), None)));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        let resolved = runtime.block_on(async { provider.provide(None) });
        assert_eq!(resolved.unwrap().access_key_id, "AKIA");
    }

    // --- real SDK resolver against a temp profile file (no network) -----------
    //
    // These tests mutate the process environment, which is global, so `test_env` serializes them
    // and restores the snapshot even on a panic.

    use crate::sources::test_env::{EnvRestore, lock_env};

    /// A named `aws://PROFILE` resolves only that profile, through the real SDK resolver: the
    /// profile's static key wins over an exported `AWS_ACCESS_KEY_ID`, and a missing profile is a
    /// hard error rather than a fall-through to the ambient identity. A `DefaultCredentialsChain`
    /// with `.profile_name` would fail both halves — env keys sit in front of the profile, and a
    /// missing profile falls through to web identity, ECS, and IMDS — so this pins the profile-only
    /// `ProfileFileCredentialsProvider` path. Static keys need no network, so the test is hermetic.
    #[test]
    fn named_profile_ignores_ambient_env_and_refuses_a_missing_profile() {
        let _guard = lock_env();
        // Restore the captured environment on every exit, including a panicking assertion.
        let _restore = EnvRestore::capture(&[
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONFIG_FILE",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
        ]);

        let dir = std::env::temp_dir().join(format!("box-aws-profile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let creds_path = dir.join("credentials");
        std::fs::write(
            &creds_path,
            "[prod]\naws_access_key_id = PROFILEKEY\naws_secret_access_key = profilesecret\n",
        )
        .expect("write the profile file");

        // Set an ambient key that must NOT win for a named profile.
        // SAFETY: `_guard` holds `ENV_LOCK` and `_restore` restores the snapshot on drop, so no
        // other thread observes a torn environment.
        unsafe {
            std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &creds_path);
            std::env::set_var("AWS_CONFIG_FILE", dir.join("config-does-not-exist"));
            std::env::set_var("AWS_ACCESS_KEY_ID", "ENVKEY");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "envsecret");
            for n in [
                "AWS_SESSION_TOKEN",
                "AWS_PROFILE",
                "AWS_REGION",
                "AWS_DEFAULT_REGION",
            ] {
                std::env::remove_var(n);
            }
        }

        let mut resolve = real_setup().expect("the resolver builds");

        // The named profile's static key wins; the exported ENVKEY is never consulted.
        let named = resolve(Some("prod")).expect("the named profile resolves");
        assert_eq!(
            named.0.access_key_id, "PROFILEKEY",
            "aws://prod signs as the profile, not the ambient AWS_ACCESS_KEY_ID"
        );

        // A missing profile refuses, rather than falling through to env, web identity, or IMDS.
        let missing = resolve(Some("nosuchprofile"));
        assert!(
            missing.is_err(),
            "a missing profile refuses rather than signing as the ambient identity: {missing:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
