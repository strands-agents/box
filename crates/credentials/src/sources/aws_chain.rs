//! The SDK-backed AWS default credential provider chain, driven on a dedicated worker thread.
//!
//! A bare `aws://` resolves the AWS SDK default credential provider chain
//! (docs/design/decisions.md#a-bare-aws-resolves-the-default-credential-chain). The chain is async
//! and the signing path is synchronous, so a dedicated worker thread owns a current-thread runtime
//! and the [`RefreshCache`]; the synchronous [`AwsCredentialProvider::provide`] seam sends a request
//! and waits on a channel with a bounded deadline.

use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

use super::aws::AwsCredentialProvider;
use crate::{AwsSessionCredentials, CredentialError, Result};

/// When the cached credentials stop being valid. `None` is a non-expiring credential (a long-lived
/// static key), which the cache serves forever and never refreshes.
type Expiry = Option<SystemTime>;

/// A resolved credential and its expiry.
type Resolved = (AwsSessionCredentials, Expiry);

/// How long before expiry a resolve is retried, so a request never signs with an expired token.
const EXPIRY_BUFFER: Duration = Duration::from_secs(5 * 60);

/// How long a caller waits for the worker before the resolve is a hard error.
const CALLER_DEADLINE: Duration = Duration::from_secs(10);

// ===================================================================================================
// The refresh cache
// ===================================================================================================

/// Holds the resolved credentials and their expiry, and refreshes near expiry.
///
/// `resolve` resolves the chain, and `now` is injectable so the refresh logic tests with a fake
/// clock. The cached credential is wiped on drop.
pub(in crate::sources) struct RefreshCache<R, N> {
    resolve: R,
    now: N,
    cached: Option<(Zeroizing<AwsSessionCredentials>, Expiry)>,
}

impl<R, N> RefreshCache<R, N>
where
    R: FnMut() -> Result<Resolved>,
    N: Fn() -> SystemTime,
{
    /// A cache that resolves through `resolve` and reads the clock through `now`.
    pub(in crate::sources) fn new(resolve: R, now: N) -> Self {
        Self {
            resolve,
            now,
            cached: None,
        }
    }

    /// Serve the cached credentials while valid; refresh inside the expiry buffer; on a failed
    /// refresh serve still-valid cached, else return the hard error.
    pub(in crate::sources) fn provide(&mut self) -> Result<AwsSessionCredentials> {
        let now = (self.now)();
        if let Some((credentials, expiry)) = &self.cached
            && !should_refresh(now, *expiry)
        {
            return Ok((**credentials).clone());
        }
        match (self.resolve)() {
            Ok((credentials, expiry)) => {
                self.cached = Some((Zeroizing::new(credentials.clone()), expiry));
                Ok(credentials)
            }
            Err(error) => match &self.cached {
                Some((credentials, expiry)) if still_valid(now, *expiry) => {
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

/// Whether a resolve is due at `now`: the credential is within the expiry buffer, or expired. A
/// non-expiring credential is never due.
fn should_refresh(now: SystemTime, expiry: Expiry) -> bool {
    match expiry {
        None => false,
        Some(expiry) => now
            .checked_add(EXPIRY_BUFFER)
            .is_none_or(|deadline| deadline >= expiry),
    }
}

// ===================================================================================================
// The SDK-backed provider
// ===================================================================================================

/// One resolve request to the worker: whether a scoped profile was asked for (which this provider
/// cannot honour), and the channel the worker replies on.
struct Request {
    profile_present: bool,
    reply: Sender<Result<AwsSessionCredentials>>,
}

/// Resolves the AWS SDK default credential provider chain on a dedicated worker thread.
///
/// The worker owns a current-thread runtime and the [`RefreshCache`]. `provide(None)` sends a
/// request and waits on a channel bounded by [`CALLER_DEADLINE`]; `provide(Some(_))` is a hard
/// error, because this provider is wired only on the no-profile branch.
pub(in crate::sources) struct SdkChainProvider {
    sender: Mutex<Sender<Request>>,
}

impl SdkChainProvider {
    /// The process-wide provider, started on first use. One worker and one cache serve every bare
    /// `aws://` request, so the metadata endpoint is reached at most once per credential lifetime.
    pub(in crate::sources) fn shared() -> &'static SdkChainProvider {
        static PROVIDER: OnceLock<SdkChainProvider> = OnceLock::new();
        PROVIDER.get_or_init(|| SdkChainProvider::spawn(Box::new(real_setup)))
    }

    /// Spawn the worker. `setup` runs once on the worker thread and produces the resolve closure;
    /// its failure (a runtime that cannot start) is reported as a hard error on the first resolve.
    fn spawn(setup: SetupFn) -> Self {
        let (sender, receiver) = mpsc::channel::<Request>();
        // A thread that cannot start drops the closure with `receiver`, so every send then fails and
        // `provide` returns a hard error. The trusted process never panics here.
        let _ = thread::Builder::new()
            .name("aws-default-chain".to_string())
            .spawn(move || worker(receiver, setup));
        Self {
            sender: Mutex::new(sender),
        }
    }

    /// A provider whose worker resolves through `resolve` rather than the real SDK chain — the test
    /// seam that exercises the worker, the runtime bridge, and the cache offline.
    #[cfg(test)]
    fn with_resolver(resolve: impl FnMut() -> Result<Resolved> + Send + 'static) -> Self {
        Self::spawn(Box::new(move || Ok(Box::new(resolve) as ResolveFn)))
    }
}

impl SdkChainProvider {
    /// Send a request and wait up to `deadline` for the worker's reply.
    fn provide_within(
        &self,
        profile: Option<&str>,
        deadline: Duration,
    ) -> Result<AwsSessionCredentials> {
        let (reply, reply_rx) = mpsc::channel();
        let request = Request {
            profile_present: profile.is_some(),
            reply,
        };
        self.sender
            .lock()
            .map_err(|_| {
                CredentialError::Credential(
                    "the AWS default-chain worker is unavailable (poisoned)".to_string(),
                )
            })?
            .send(request)
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
}

impl AwsCredentialProvider for SdkChainProvider {
    fn provide(&self, profile: Option<&str>) -> Result<AwsSessionCredentials> {
        self.provide_within(profile, CALLER_DEADLINE)
    }
}

/// The resolve closure the worker drives each request.
type ResolveFn = Box<dyn FnMut() -> Result<Resolved> + Send>;

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
                let result = if request.profile_present {
                    Err(CredentialError::Credential(
                        "the AWS default-chain provider resolves no scoped profile".to_string(),
                    ))
                } else {
                    cache.provide()
                };
                let _ = request.reply.send(result);
            }
        }
    }
}

/// Build the current-thread runtime and the default chain, returning a closure that resolves it.
fn real_setup() -> Result<ResolveFn> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CredentialError::Credential(format!(
                "could not start the AWS default-chain runtime: {error}"
            ))
        })?;
    let chain = runtime.block_on(build_chain());
    Ok(Box::new(move || resolve_once(&runtime, &chain)))
}

/// Resolve the chain once, mapping an unreachable or empty chain to [`CredentialError::KeystoreAccess`].
fn resolve_once(
    runtime: &tokio::runtime::Runtime,
    chain: &aws_config::default_provider::credentials::DefaultCredentialsChain,
) -> Result<Resolved> {
    use aws_credential_types::provider::ProvideCredentials;

    let credentials = runtime
        .block_on(chain.provide_credentials())
        .map_err(|error| {
            CredentialError::KeystoreAccess(format!(
                "AWS default credential chain resolved no credentials: {error}"
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

/// Build the AWS SDK default credential provider chain over the rustls/ring HTTP client. The
/// `ring` crypto provider keeps rustls unambiguous, matching the rest of the workspace.
async fn build_chain() -> aws_config::default_provider::credentials::DefaultCredentialsChain {
    use aws_smithy_http_client::{Builder, tls};

    let http_client = Builder::new()
        .tls_provider(tls::Provider::Rustls(
            tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https();
    // `without_region` carries the Tokio sleep implementation (rt-tokio); the region resolves from
    // the chain's own region chain.
    let config =
        aws_config::provider_config::ProviderConfig::without_region().with_http_client(http_client);
    aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
        .configure(config)
        .build()
        .await
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
            || {
                calls.set(calls.get() + 1);
                Ok((creds("AKIA1"), expiry))
            },
            || clock.get(),
        );

        assert_eq!(cache.provide().unwrap().access_key_id, "AKIA1");
        // A second call, still well before expiry, is served from the cache.
        assert_eq!(cache.provide().unwrap().access_key_id, "AKIA1");
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
            || {
                calls.set(calls.get() + 1);
                let id = format!("AKIA{}", calls.get());
                Ok((creds(&id), Some(clock.get() + Duration::from_secs(3600))))
            },
            || clock.get(),
        );

        assert_eq!(cache.provide().unwrap().access_key_id, "AKIA1");
        // Advance to within the buffer of the first expiry (3600 - 60 < 3600 - 300 window).
        clock.set(base + Duration::from_secs(3600) - Duration::from_secs(60));
        assert_eq!(
            cache.provide().unwrap().access_key_id,
            "AKIA2",
            "a provide inside the buffer resolves again"
        );
        assert_eq!(calls.get(), 2);
    }

    /// A failed refresh while the cache is still valid serves the still-valid cached credentials.
    #[test]
    fn cache_serves_stale_valid_on_refresh_failure() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0u32);
        let clock = Cell::new(base);
        let expiry = Some(base + Duration::from_secs(3600));
        let mut cache = RefreshCache::new(
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    Ok((creds("AKIA1"), expiry))
                } else {
                    Err(CredentialError::KeystoreAccess("metadata blip".to_string()))
                }
            },
            || clock.get(),
        );

        assert_eq!(cache.provide().unwrap().access_key_id, "AKIA1");
        // Move into the buffer but before expiry, so the refresh is attempted and fails.
        clock.set(base + Duration::from_secs(3600) - Duration::from_secs(60));
        assert_eq!(
            cache.provide().unwrap().access_key_id,
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
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    Ok((creds("AKIA1"), expiry))
                } else {
                    Err(CredentialError::KeystoreAccess("chain down".to_string()))
                }
            },
            || clock.get(),
        );

        assert_eq!(cache.provide().unwrap().access_key_id, "AKIA1");
        // Past expiry: the cached credential is no longer valid, so a failed refresh is hard.
        clock.set(base + Duration::from_secs(7200));
        let error = cache.provide().unwrap_err();
        assert!(
            !error.is_soft(),
            "an expired cache with a failed refresh is hard"
        );
    }

    // --- SdkChainProvider (worker + channel; fake resolver, no SDK) ----------

    /// A resolve closure that blocks past the caller deadline yields a hard error rather than an
    /// unsigned request.
    #[test]
    fn sdk_provider_deadline_is_hard() {
        let provider = SdkChainProvider::with_resolver(|| {
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

    /// An empty chain result maps to `KeystoreAccess`, through the worker and the cache.
    #[test]
    fn sdk_provider_maps_empty_chain_to_keystore_access() {
        let provider = SdkChainProvider::with_resolver(|| {
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

    /// A scoped profile reaches this provider only by mistake, and it refuses rather than resolving
    /// the chain under a profile it cannot honour.
    #[test]
    fn sdk_provider_refuses_a_scoped_profile() {
        let provider = SdkChainProvider::with_resolver(|| Ok((creds("AKIA"), None)));
        let error = provider.provide(Some("prod")).unwrap_err();
        assert!(!error.is_soft(), "a scoped profile here is a hard error");
    }

    /// `provide` is callable from a thread already running a runtime, with no "runtime within a
    /// runtime" panic, because the worker owns the runtime and the caller only waits on a channel.
    #[test]
    fn sdk_provider_is_callable_from_a_runtime_thread() {
        let provider = SdkChainProvider::with_resolver(|| Ok((creds("AKIA"), None)));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        let resolved = runtime.block_on(async { provider.provide(None) });
        assert_eq!(resolved.unwrap().access_key_id, "AKIA");
    }
}
