//! The AWS SDK resolver for the host execution-role tokens, injected into the vault.
//!
//! The box builds the SDK's IMDS and ECS providers and hands the `credentials` crate a resolver
//! for `aws://@instance-role` and `aws://@container-role`, so that crate links no HTTP client of
//! its own. The SDK providers run on a dedicated thread with their own current-thread runtime: the
//! `credentials` resolve is synchronous and is reached from inside the box's async request path, so
//! a runtime of its own on a separate thread is what keeps `block_on` off a runtime worker. The
//! thread is spawned on first use, so a box with no token route starts none. The SDK's own caching
//! providers hold the credentials and refresh them on expiry, so a repeat resolve inside the
//! validity window makes no network call.

use std::sync::OnceLock;
use std::sync::mpsc;

use aws_credential_types::provider::ProvideCredentials;
use credentials::{
    AwsExecutionRoleCredentials, AwsExecutionRoleKind, AwsExecutionRoleResolver, CredentialError,
};

/// One resolve request: which role to resolve, and where to send the answer.
struct Request {
    kind: AwsExecutionRoleKind,
    reply: mpsc::Sender<Result<AwsExecutionRoleCredentials, CredentialError>>,
}

/// Build a resolver for the host execution-role tokens.
///
/// The returned resolver spawns its worker thread on first use and shares it across every later
/// resolve. A box that never resolves a token spawns no thread.
pub(crate) fn resolver() -> AwsExecutionRoleResolver {
    let worker: OnceLock<mpsc::Sender<Request>> = OnceLock::new();
    AwsExecutionRoleResolver::new(move |kind| {
        let sender = worker.get_or_init(spawn_worker);
        let (reply, answer) = mpsc::channel();
        sender.send(Request { kind, reply }).map_err(|_| {
            CredentialError::KeystoreAccess(
                "the AWS execution-role resolver thread is gone".to_string(),
            )
        })?;
        answer.recv().map_err(|_| {
            CredentialError::KeystoreAccess(
                "the AWS execution-role resolver dropped the reply".to_string(),
            )
        })?
    })
}

/// Spawn the worker thread and return the channel that feeds it.
fn spawn_worker() -> mpsc::Sender<Request> {
    let (sender, receiver) = mpsc::channel::<Request>();
    std::thread::Builder::new()
        .name("aws-exec-role-resolver".to_string())
        .spawn(move || worker_loop(&receiver))
        .expect("the AWS execution-role resolver thread must spawn");
    sender
}

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
                        "the AWS execution-role resolver could not start a runtime: {source}"
                    ))));
            }
            return;
        }
    };
    // The SDK's HTTP client, built on `ring` to match the workspace so rustls has one unambiguous
    // crypto provider. The metadata endpoints are plaintext HTTP, but the SDK client carries TLS
    // regardless, so the provider choice still has to be pinned.
    let http_client = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https();
    let provider_config =
        aws_config::provider_config::ProviderConfig::default().with_http_client(http_client);
    // Built once and reused, so the SDK's caching providers keep and refresh the credentials across
    // requests. The IMDS provider also answers the AgentCore MMDS endpoint, which speaks the IMDS
    // protocol.
    let imds = aws_config::imds::credentials::ImdsCredentialsProvider::builder()
        .configure(&provider_config)
        .build();
    let ecs = aws_config::ecs::EcsCredentialsProvider::builder()
        .configure(&provider_config)
        .build();
    for request in receiver {
        let answer = runtime.block_on(resolve(request.kind, &imds, &ecs));
        let _ = request.reply.send(answer);
    }
}

/// The wall-clock bound on one resolve, so a hung metadata endpoint cannot stall box startup or a
/// request without limit. The SDK carries its own connect and read timeouts; this is the outer
/// ceiling the box owns, well above a healthy link-local round trip.
const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Resolve one token through its SDK provider, mapping every SDK failure to a hard keystore error.
async fn resolve(
    kind: AwsExecutionRoleKind,
    imds: &aws_config::imds::credentials::ImdsCredentialsProvider,
    ecs: &aws_config::ecs::EcsCredentialsProvider,
) -> Result<AwsExecutionRoleCredentials, CredentialError> {
    let provide = async {
        match kind {
            AwsExecutionRoleKind::Instance => imds.provide_credentials().await,
            AwsExecutionRoleKind::Container => ecs.provide_credentials().await,
        }
    };
    let credentials = tokio::time::timeout(RESOLVE_TIMEOUT, provide)
        .await
        .map_err(|_elapsed| {
            CredentialError::KeystoreAccess(format!(
                "the AWS host execution-role endpoint did not answer within {}s",
                RESOLVE_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|source| {
            CredentialError::KeystoreAccess(format!(
                "the AWS SDK could not resolve the host execution role: {source}"
            ))
        })?;
    Ok(AwsExecutionRoleCredentials {
        access_key_id: credentials.access_key_id().to_string(),
        secret_access_key: credentials.secret_access_key().to_string(),
        session_token: credentials.session_token().unwrap_or_default().to_string(),
    })
}
