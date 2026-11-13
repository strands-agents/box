//! The SDK-backed AWS default credential provider chain, driven on a dedicated worker thread.
//!
//! A bare `aws://` resolves the AWS SDK default credential provider chain
//! (docs/design/decisions.md#a-bare-aws-resolves-the-default-credential-chain). See the crate
//! AGENTS.md for the worker, cache, and region design.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use zeroize::Zeroizing;

use crate::{AwsSessionCredentials, CredentialError, Result};

/// When the cached credentials stop being valid. `None` is a credential the SDK gave no expiry for.
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
struct RefreshCache<R, N> {
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
    fn new(resolve: R, now: N) -> Self {
        Self {
            resolve,
            now,
            cached: None,
        }
    }

    /// Serve the cached credentials while valid; refresh inside the expiry buffer; on a failed
    /// refresh serve still-valid cached, else return the hard error.
    fn provide(&mut self) -> Result<AwsSessionCredentials> {
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

/// One resolve request to the worker: the channel the worker replies on, and the instant the caller
/// stops waiting, so the worker can skip a resolve for a caller that already left.
struct Request {
    reply: Sender<Result<AwsSessionCredentials>>,
    deadline: Instant,
}

/// One SDK call to run on the worker, and the instant the caller stops waiting.
struct Call {
    work: CallFn,
    deadline: Instant,
}

/// What the worker serves: a resolve of the chain, or an SDK call signed by it.
enum Job {
    Resolve(Request),
    Call(Call),
}

/// What an SDK call runs with on the worker: its one `ring` HTTPS client, and the chain's credentials.
pub(in crate::sources) struct CallContext {
    pub(in crate::sources) http_client: aws_smithy_runtime_api::client::http::SharedHttpClient,
    pub(in crate::sources) credentials: Zeroizing<AwsSessionCredentials>,
}

/// An SDK call, given the worker's runtime and context, or the reason there is none.
type CallFn = Box<dyn FnOnce(Result<(&tokio::runtime::Runtime, CallContext)>) + Send>;

/// How long a caller waits past its deadline, so the worker's own timeout answer arrives first.
const CALL_GRACE: Duration = Duration::from_secs(1);

/// The runtime and HTTPS client an SDK call runs with. A worker built over a test resolver has none.
struct Io {
    runtime: Arc<tokio::runtime::Runtime>,
    http_client: aws_smithy_runtime_api::client::http::SharedHttpClient,
}

/// Resolves the AWS SDK default credential provider chain on a dedicated worker thread.
pub(in crate::sources) struct SdkChainProvider {
    sender: Sender<Job>,
}

impl SdkChainProvider {
    /// The process-wide provider, started on first use.
    pub(in crate::sources) fn shared() -> &'static SdkChainProvider {
        static PROVIDER: OnceLock<SdkChainProvider> = OnceLock::new();
        PROVIDER.get_or_init(|| SdkChainProvider::spawn(Box::new(real_setup)))
    }

    /// Resolve the default chain, waiting up to [`CALLER_DEADLINE`] for the worker.
    pub(in crate::sources) fn provide(&self) -> Result<AwsSessionCredentials> {
        self.provide_within(CALLER_DEADLINE)
    }

    /// Drive the future `work` builds on the worker, with its runtime, its HTTPS client and the
    /// chain's credentials. The worker drops the future at `deadline`, so a call holds the worker,
    /// and every bare `aws://` signer behind it, no longer than that. A chain that resolves no
    /// credentials, or a worker that has no runtime, is the answer's error and `work` does not run.
    pub(in crate::sources) fn call<T, F, Fut>(&self, deadline: Duration, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(CallContext) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let (reply, reply_rx) = mpsc::channel();
        let until = Instant::now() + deadline;
        let late = move || {
            CredentialError::Credential(format!(
                "the AWS call did not finish within {} s",
                deadline.as_secs()
            ))
        };
        self.sender
            .send(Job::Call(Call {
                work: Box::new(move |ready| {
                    let answer = ready.and_then(|(runtime, context)| {
                        let remaining = until.saturating_duration_since(Instant::now());
                        runtime.block_on(async move {
                            tokio::time::timeout(remaining, work(context))
                                .await
                                .unwrap_or_else(|_| Err(late()))
                        })
                    });
                    let _ = reply.send(answer);
                }),
                deadline: until,
            }))
            .map_err(|_| {
                CredentialError::Credential(
                    "the AWS default-chain worker is not running".to_string(),
                )
            })?;
        match reply_rx.recv_timeout(deadline + CALL_GRACE) {
            Ok(answer) => answer,
            Err(RecvTimeoutError::Timeout) => Err(late()),
            Err(RecvTimeoutError::Disconnected) => Err(CredentialError::Credential(
                "the AWS call stopped on the worker before it answered".to_string(),
            )),
        }
    }

    /// Spawn the worker.
    ///
    /// A thread that cannot start drops the closure with `receiver`, so every send then fails and
    /// `provide` returns a hard error rather than panicking in the trusted process.
    fn spawn(setup: SetupFn) -> Self {
        let (sender, receiver) = mpsc::channel::<Job>();
        let _ = thread::Builder::new()
            .name("aws-default-chain".to_string())
            .spawn(move || worker(receiver, setup));
        Self { sender }
    }

    /// Send a request and wait up to `deadline` for the worker's reply.
    fn provide_within(&self, deadline: Duration) -> Result<AwsSessionCredentials> {
        let (reply, reply_rx) = mpsc::channel();
        self.sender
            .send(Job::Resolve(Request {
                reply,
                deadline: Instant::now() + deadline,
            }))
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
    /// seam that exercises the worker, the runtime bridge, and the cache offline.
    #[cfg(test)]
    fn with_resolver(resolve: impl FnMut() -> Result<Resolved> + Send + 'static) -> Self {
        Self::spawn(Box::new(move || Ok((Box::new(resolve) as ResolveFn, None))))
    }

    /// A provider over `resolve` whose worker also holds a real runtime and HTTPS client, so a
    /// test runs an SDK call against a local stand-in with fixed credentials.
    #[cfg(test)]
    pub(in crate::sources) fn with_resolver_and_io(
        resolve: impl FnMut() -> Result<Resolved> + Send + 'static,
    ) -> Self {
        Self::spawn(Box::new(move || {
            let (runtime, http_client) = runtime_and_client()?;
            Ok((
                Box::new(resolve) as ResolveFn,
                Some(Io {
                    runtime: Arc::new(runtime),
                    http_client,
                }),
            ))
        }))
    }
}

/// The resolve closure the worker drives each request.
type ResolveFn = Box<dyn FnMut() -> Result<Resolved> + Send>;

/// Runs once on the worker thread to build the resolve closure and the runtime an SDK call runs
/// with, or fails if the runtime cannot start.
type SetupFn = Box<dyn FnOnce() -> Result<(ResolveFn, Option<Io>)> + Send>;

/// The worker loop: set up once, then serve each request from the cache. A setup failure replies a
/// hard error to every request, so the failure surfaces on the first resolve and stays fail-closed.
fn worker(receiver: Receiver<Job>, setup: SetupFn) {
    match setup() {
        Err(error) => {
            let message = error.to_string();
            for job in receiver {
                let refused = CredentialError::Credential(message.clone());
                match job {
                    Job::Resolve(request) => {
                        let _ = request.reply.send(Err(refused));
                    }
                    Job::Call(call) => (call.work)(Err(refused)),
                }
            }
        }
        Ok((resolve, io)) => {
            let mut cache = RefreshCache::new(resolve, SystemTime::now);
            for job in receiver {
                match job {
                    // Skip work for a caller that already timed out, so a slow or failing chain
                    // does not run work for callers that have left and stack behind them.
                    Job::Resolve(request) if Instant::now() < request.deadline => {
                        let _ = request.reply.send(cache.provide());
                    }
                    Job::Call(call) if Instant::now() < call.deadline => {
                        let ready = match &io {
                            None => Err(CredentialError::Credential(
                                "this AWS default-chain worker runs no SDK calls".to_string(),
                            )),
                            Some(io) => cache.provide().map(|credentials| {
                                (
                                    &*io.runtime,
                                    CallContext {
                                        http_client: io.http_client.clone(),
                                        credentials: Zeroizing::new(credentials),
                                    },
                                )
                            }),
                        };
                        // A call that panics drops its reply, so its caller gets an error, and the
                        // worker stays up for every bare `aws://` signer behind it.
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            (call.work)(ready);
                        }));
                    }
                    Job::Resolve(_) | Job::Call(_) => {}
                }
            }
        }
    }
}

/// The current-thread runtime and the `ring` HTTPS client the worker holds.
fn runtime_and_client() -> Result<(
    tokio::runtime::Runtime,
    aws_smithy_runtime_api::client::http::SharedHttpClient,
)> {
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
    Ok((runtime, http_client))
}

/// Build the runtime, the shared HTTP client, and the region once, and return a closure that
/// rebuilds the chain on each resolve. See the crate AGENTS.md for why the chain is rebuilt.
fn real_setup() -> Result<(ResolveFn, Option<Io>)> {
    let (runtime, http_client) = runtime_and_client()?;
    let runtime = Arc::new(runtime);
    let io = Io {
        runtime: Arc::clone(&runtime),
        http_client: http_client.clone(),
    };
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
    let resolve: ResolveFn = Box::new(move || {
        // `without_region` carries the Tokio sleep implementation (rt-tokio). A fresh config
        // re-reads the profile files; `.region` pins the region so the rebuild does not re-run the
        // region chain (which reaches instance metadata).
        let http_client = http_client.clone();
        let region = region.clone();
        let chain = runtime.block_on(async {
            let config = aws_config::provider_config::ProviderConfig::without_region()
                .with_http_client(http_client);
            aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
                .region(region)
                .configure(config)
                .build()
                .await
        });
        resolve_once(&runtime, &chain)
    });
    Ok((resolve, Some(io)))
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

    /// A non-expiring credential (no `Expiration`) re-resolves on every call, so a rotated file or
    /// environment credential is picked up rather than pinned for the life of the run.
    #[test]
    fn cache_reresolves_when_expiry_is_none() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0u32);
        let clock = Cell::new(base);
        let mut cache = RefreshCache::new(
            || {
                calls.set(calls.get() + 1);
                let id = format!("AKIA{}", calls.get());
                // No expiry, as a rotated static/session key in `~/.aws/credentials` carries.
                Ok((creds(&id), None))
            },
            || clock.get(),
        );

        assert_eq!(cache.provide().unwrap().access_key_id, "AKIA1");
        // The clock does not move, yet the next provide resolves again and sees the rotated value.
        assert_eq!(
            cache.provide().unwrap().access_key_id,
            "AKIA2",
            "a non-expiring credential is re-resolved, not served forever"
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
            .provide_within(Duration::from_millis(100))
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
        let provider = SdkChainProvider::with_resolver(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((creds("AKIA"), None))
        });
        // A zero deadline is already in the past when the worker dequeues the request.
        let error = provider
            .provide_within(Duration::ZERO)
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
        let provider = SdkChainProvider::with_resolver(|| {
            Err(CredentialError::KeystoreAccess(
                "no credentials found".to_string(),
            ))
        });
        let error = provider.provide().unwrap_err();
        assert!(
            matches!(error, CredentialError::KeystoreAccess(_)),
            "an empty chain is KeystoreAccess: {error:?}"
        );
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
        let resolved = runtime.block_on(async { provider.provide() });
        assert_eq!(resolved.unwrap().access_key_id, "AKIA");
    }
    /// **A call runs on the worker with the chain's cached credentials**, so an SDK operation signs
    /// as the identity a bare `aws://` signs with.
    #[test]
    fn a_call_runs_with_the_chains_credentials() {
        let provider = SdkChainProvider::with_resolver_and_io(|| Ok((creds("AKIA-CALL"), None)));
        let seen = provider
            .call(Duration::from_secs(5), |context| async move {
                Ok(context.credentials.access_key_id.clone())
            })
            .expect("the call runs");
        assert_eq!(seen, "AKIA-CALL");
    }

    /// **A call fails without running when the chain resolves nothing, or the worker has no
    /// runtime**, so no SDK operation goes out unsigned.
    #[test]
    fn a_call_without_credentials_or_a_runtime_does_not_run() {
        let empty = SdkChainProvider::with_resolver_and_io(|| {
            Err(CredentialError::KeystoreAccess(
                "no credentials".to_string(),
            ))
        });
        let error = empty
            .call(Duration::from_secs(5), |_| async {
                panic!("the call ran without credentials");
                #[allow(unreachable_code)]
                Ok(())
            })
            .expect_err("no credentials");
        assert!(error.to_string().contains("no credentials"), "{error}");

        let no_runtime = SdkChainProvider::with_resolver(|| Ok((creds("AKIA"), None)));
        let error = no_runtime
            .call(Duration::from_secs(5), |_| async {
                panic!("the call ran without a runtime");
                #[allow(unreachable_code)]
                Ok(())
            })
            .expect_err("no runtime");
        assert!(error.to_string().contains("runs no SDK calls"), "{error}");
    }

    /// **A call holds the worker no longer than its deadline**, so a bare `aws://` signer behind a
    /// stuck call is answered as soon as the deadline passes.
    #[test]
    fn a_stuck_call_releases_the_worker_at_its_deadline() {
        let provider = SdkChainProvider::with_resolver_and_io(|| Ok((creds("AKIA"), None)));
        let started = Instant::now();
        let error = provider
            .call(Duration::from_millis(300), |_| {
                std::future::pending::<Result<()>>()
            })
            .expect_err("the call never finishes");
        assert!(error.to_string().contains("did not finish"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );

        let resolved = Instant::now();
        provider
            .provide()
            .expect("the worker answers after the call");
        assert!(
            resolved.elapsed() < Duration::from_secs(1),
            "{:?}",
            resolved.elapsed()
        );
    }

    /// **A call that panics fails its caller and leaves the worker running.**
    #[test]
    fn a_panicking_call_leaves_the_worker_running() {
        let provider = SdkChainProvider::with_resolver_and_io(|| Ok((creds("AKIA"), None)));
        let error = provider
            .call(Duration::from_secs(5), |_| async {
                panic!("a defect in the call");
                #[allow(unreachable_code)]
                Ok(())
            })
            .expect_err("the call panicked");
        assert!(
            error.to_string().contains("stopped on the worker"),
            "{error}"
        );
        assert_eq!(
            provider.provide().expect("still running").access_key_id,
            "AKIA"
        );
    }
}
