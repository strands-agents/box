//! The AWS default-credential-chain resolver for a bare `aws://` route, injected into the vault.
//!
//! The box builds the AWS SDK default credential provider chain and hands the `credentials` crate
//! a resolver for a bare `aws://` reference, so that crate links no HTTP client of its own. The
//! chain runs on a dedicated thread with its own current-thread runtime: the `credentials` resolve
//! is synchronous and is reached from inside the box's async request path, so a runtime of its own
//! on a separate thread keeps `block_on` off a runtime worker. Each injected resolver spawns its
//! own worker thread on first use (the box injects one resolver per vault, so a box with several
//! bare `aws://` routes runs one worker per route), and a box with no bare `aws://` route starts
//! none. The chain does not cache when called directly, so each worker holds the last credentials
//! and refreshes them near expiry.

use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::{Duration, SystemTime};

use aws_credential_types::provider::ProvideCredentials;
use credentials::{AwsChainCredentials, AwsChainResolver, CredentialError};

/// One resolve request: where to send the answer.
struct Request {
    reply: mpsc::Sender<Result<AwsChainCredentials, CredentialError>>,
}

/// Build a resolver for a bare `aws://` route (the AWS default credential chain).
///
/// The returned resolver spawns its worker thread on first use and shares it across every later
/// resolve *through this resolver*. A box that never resolves a bare `aws://` route spawns none.
pub(crate) fn resolver() -> AwsChainResolver {
    let worker: OnceLock<mpsc::Sender<Request>> = OnceLock::new();
    AwsChainResolver::new(move || {
        let sender = worker.get_or_init(spawn_worker);
        let (reply, answer) = mpsc::channel();
        sender.send(Request { reply }).map_err(|_| {
            CredentialError::KeystoreAccess(
                "the AWS credential resolver thread is gone".to_string(),
            )
        })?;
        answer.recv().map_err(|_| {
            CredentialError::KeystoreAccess(
                "the AWS credential resolver dropped the reply".to_string(),
            )
        })?
    })
}

/// Spawn the worker thread and return the channel that feeds it.
fn spawn_worker() -> mpsc::Sender<Request> {
    let (sender, receiver) = mpsc::channel::<Request>();
    std::thread::Builder::new()
        .name("aws-credential-resolver".to_string())
        .spawn(move || worker_loop(&receiver))
        .expect("the AWS credential resolver thread must spawn");
    sender
}

/// The wall-clock bound on one chain resolve, so a hung endpoint cannot stall box startup or a
/// request without limit.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Refresh when within this window of expiry, so a request never races an expiring credential.
const EXPIRY_BUFFER: Duration = Duration::from_secs(300);

/// Serve resolve requests until every sender is gone.
fn worker_loop(receiver: &mpsc::Receiver<Request>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(source) => {
            // No runtime means no resolve can succeed; answer every request with a hard failure
            // rather than leave a caller blocked on a reply that never comes.
            for request in receiver {
                let _ = request
                    .reply
                    .send(Err(CredentialError::KeystoreAccess(format!(
                        "the AWS credential resolver could not start a runtime: {source}"
                    ))));
            }
            return;
        }
    };
    // The SDK's HTTP client, built on `ring` to match the workspace so rustls has one unambiguous
    // crypto provider. The chain uses it for IMDS, ECS, STS, and any web-identity call.
    let http_client = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https();
    let provider_config =
        aws_config::provider_config::ProviderConfig::default().with_http_client(http_client);
    let chain = runtime.block_on(
        aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
            .configure(provider_config)
            .build(),
    );

    // The chain does not cache when `provide_credentials` is called directly (the SDK's cache lives
    // in a service client's runtime components), so the worker caches the last credentials and
    // their expiry, and refreshes only when missing or near expiry. This keeps a steady request
    // stream off the metadata and STS endpoints.
    let mut cached: Option<(AwsChainCredentials, Option<SystemTime>)> = None;
    for request in receiver {
        let answer = serve(&runtime, &chain, &mut cached);
        let _ = request.reply.send(answer);
    }
}

/// Serve one request from the cache, refreshing through the chain when missing or near expiry.
fn serve(
    runtime: &tokio::runtime::Runtime,
    chain: &aws_config::default_provider::credentials::DefaultCredentialsChain,
    cached: &mut Option<(AwsChainCredentials, Option<SystemTime>)>,
) -> Result<AwsChainCredentials, CredentialError> {
    cached_or(cached, SystemTime::now(), || {
        runtime.block_on(resolve(chain))
    })
}

/// The cache decision, pure and injectable for tests: serve the cached credentials while valid,
/// otherwise call `fetch`, store its result, and serve a copy. A cached credential with no expiry
/// (a long-lived key the chain found) serves forever.
fn cached_or(
    cached: &mut Option<(AwsChainCredentials, Option<SystemTime>)>,
    now: SystemTime,
    fetch: impl FnOnce() -> Result<(AwsChainCredentials, Option<SystemTime>), CredentialError>,
) -> Result<AwsChainCredentials, CredentialError> {
    if let Some((creds, expiry)) = cached.as_ref()
        && !near_expiry(*expiry, now)
    {
        return Ok(copy_of(creds));
    }
    let (fresh, expiry) = fetch()?;
    let answer = copy_of(&fresh);
    *cached = Some((fresh, expiry));
    Ok(answer)
}

/// Whether a credential is within the refresh buffer of its expiry, measured against `now`. A
/// credential with no expiry (a long-lived key the chain found) never counts as near expiry.
fn near_expiry(expiry: Option<SystemTime>, now: SystemTime) -> bool {
    match expiry {
        None => false,
        Some(at) => now + EXPIRY_BUFFER >= at,
    }
}

/// Resolve the chain once, mapping every SDK failure to a hard keystore error.
async fn resolve(
    chain: &aws_config::default_provider::credentials::DefaultCredentialsChain,
) -> Result<(AwsChainCredentials, Option<SystemTime>), CredentialError> {
    let credentials = within_timeout(RESOLVE_TIMEOUT, chain.provide_credentials())
        .await?
        .map_err(|source| {
            CredentialError::KeystoreAccess(format!(
                "the AWS SDK default credential chain could not resolve: {source}"
            ))
        })?;
    let mapped = AwsChainCredentials {
        access_key_id: credentials.access_key_id().to_string(),
        secret_access_key: credentials.secret_access_key().to_string(),
        session_token: credentials.session_token().unwrap_or_default().to_string(),
    };
    Ok((mapped, credentials.expiry()))
}

/// Bound a resolve future in wall-clock time, mapping an overrun to a hard keystore error so a hung
/// endpoint cannot stall box startup or a request. Returns the future's own output when it finishes
/// in time.
async fn within_timeout<T>(
    limit: Duration,
    fut: impl std::future::Future<Output = T>,
) -> Result<T, CredentialError> {
    tokio::time::timeout(limit, fut).await.map_err(|_elapsed| {
        CredentialError::KeystoreAccess(format!(
            "the AWS default credential chain did not answer within {}s",
            limit.as_secs()
        ))
    })
}

/// A copy of the cached credentials to hand to one caller, leaving the cache intact.
fn copy_of(creds: &AwsChainCredentials) -> AwsChainCredentials {
    AwsChainCredentials {
        access_key_id: creds.access_key_id.clone(),
        secret_access_key: creds.secret_access_key.clone(),
        session_token: creds.session_token.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> AwsChainCredentials {
        AwsChainCredentials {
            access_key_id: "ASIAEXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: "token".to_string(),
        }
    }

    /// No expiry never counts as near expiry; an expiry past `now + buffer` does not; one within the
    /// buffer, or already past, does.
    #[test]
    fn near_expiry_reads_the_buffer() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert!(
            !near_expiry(None, now),
            "a long-lived key never nears expiry"
        );
        assert!(
            !near_expiry(Some(now + EXPIRY_BUFFER + Duration::from_secs(60)), now),
            "well before expiry is not near"
        );
        assert!(
            near_expiry(Some(now + Duration::from_secs(60)), now),
            "inside the buffer is near"
        );
        assert!(
            near_expiry(Some(now - Duration::from_secs(1)), now),
            "already expired is near"
        );
    }

    /// The cache fetches once, then serves the cached copy while valid, then refetches past expiry.
    #[test]
    fn the_cache_fetches_once_then_serves_until_expiry() {
        use std::cell::Cell;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let calls = Cell::new(0);
        let mut cached = None;

        // An expiry an hour out: first call fetches and stores it.
        let fetch = || {
            calls.set(calls.get() + 1);
            Ok((creds(), Some(now + Duration::from_secs(3600))))
        };
        cached_or(&mut cached, now, fetch).expect("first fetch");
        assert_eq!(calls.get(), 1);

        // A later call still inside validity serves the cache: fetch must not run.
        cached_or(&mut cached, now + Duration::from_secs(60), || {
            panic!("must not refetch inside validity")
        })
        .expect("served from cache");
        assert_eq!(calls.get(), 1);

        // A call within the buffer of expiry refetches.
        let fetch2 = || {
            calls.set(calls.get() + 1);
            Ok((creds(), Some(now + Duration::from_secs(7200))))
        };
        cached_or(&mut cached, now + Duration::from_secs(3600), fetch2)
            .expect("refetch near expiry");
        assert_eq!(calls.get(), 2);
    }

    /// A credential with no expiry is cached forever: a second call never refetches.
    #[test]
    fn a_no_expiry_credential_is_cached_forever() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut cached = None;
        cached_or(&mut cached, now, || Ok((creds(), None))).expect("first fetch");
        cached_or(&mut cached, now + Duration::from_secs(10_000_000), || {
            panic!("a no-expiry key must never refetch")
        })
        .expect("served from cache");
    }

    /// A resolve that never answers is bounded and mapped to a hard keystore error.
    #[tokio::test]
    async fn a_hung_resolve_times_out() {
        let err = within_timeout(Duration::from_millis(5), std::future::pending::<()>())
            .await
            .expect_err("a pending future must time out");
        assert!(matches!(err, CredentialError::KeystoreAccess(_)));
        assert!(err.to_string().contains("did not answer"), "{err}");
    }

    /// A resolve that answers in time returns its own output unchanged.
    #[tokio::test]
    async fn a_prompt_resolve_passes_through() {
        let value = within_timeout(Duration::from_secs(5), async { 7 })
            .await
            .expect("a ready future returns in time");
        assert_eq!(value, 7);
    }
}
