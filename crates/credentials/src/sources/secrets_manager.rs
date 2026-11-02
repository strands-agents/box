//! `aws-secretsmanager://SECRET[#FIELD]` — read a secret from AWS Secrets Manager, or one field of a
//! JSON secret, signed as the AWS identity the default credential chain finds.

use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::{OnceLock, mpsc};
use std::time::Duration;

use aws_config::ecs::EcsCredentialsProvider;
use aws_config::environment::credentials::EnvironmentVariableCredentialsProvider;
use aws_config::imds::credentials::ImdsCredentialsProvider;
use aws_config::profile::ProfileFileCredentialsProvider;
use aws_config::provider_config::ProviderConfig;
use aws_config::web_identity_token::WebIdentityTokenCredentialsProvider;
use aws_credential_types::provider::error::CredentialsError;
use aws_sdk_secretsmanager::config::timeout::TimeoutConfig;
use aws_sdk_secretsmanager::config::{
    BehaviorVersion, Credentials, ProvideCredentials, Region, SharedCredentialsProvider,
    SharedHttpClient,
};
use aws_sdk_secretsmanager::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_smithy_http_client::tls::{Provider, rustls_provider::CryptoMode};
use zeroize::Zeroizing;

use crate::sources::{SecretSource, uri_reference};
use crate::{CredentialError, Locator, Result, Secret, redact_credential_ref};

/// The scheme this source claims.
pub(crate) const SCHEME: &str = "aws-secretsmanager";

/// The variables naming the region when the secret is named without an ARN, in the order read.
const REGION_VARIABLES: [&str; 2] = ["AWS_REGION", "AWS_DEFAULT_REGION"];

/// The longest secret name or ARN the source accepts.
const MAXIMUM_SECRET_ID: usize = 2048;

/// The longest JSON field name the source accepts.
const MAXIMUM_FIELD: usize = 256;

/// The bound on one `GetSecretValue` call, retries included.
const FETCH_DEADLINE: Duration = Duration::from_secs(10);

/// The bound on opening the connection.
const CONNECT_DEADLINE: Duration = Duration::from_secs(3);

/// The longest a fetch waits for the worker, the credential chain included.
const ANSWER_DEADLINE: Duration = Duration::from_secs(30);

/// Where the signing identity comes from.
#[derive(Clone)]
enum Identity {
    /// The AWS SDK's default chain: environment, profile, web identity, container endpoint, IMDS.
    DefaultChain,
    /// Fixed credentials, so a test reads no host state.
    #[cfg(test)]
    Fixed(Credentials),
}

/// A variable lookup, so a test reads no host state.
type Lookup = Box<dyn Fn(&str) -> Option<OsString> + Send + Sync>;

/// Reads a secret from AWS Secrets Manager (`aws-secretsmanager://SECRET[#FIELD]`).
pub(crate) struct SecretsManagerSource {
    lookup: Lookup,
    identity: Identity,
    endpoint: Option<String>,
}

/// One fetch the worker serves.
struct Job {
    identity: Identity,
    endpoint: Option<String>,
    region: String,
    secret_id: String,
    answer: mpsc::Sender<std::result::Result<Fetched, String>>,
}

/// A fetched secret string, and the credential provider whose identity signed the call.
struct Fetched {
    value: Zeroizing<String>,
    signer: &'static str,
}

/// The process's one worker: a thread with one runtime, one HTTPS client and one credential chain
/// per region, so every vault's fetch reuses them.
static WORKER: OnceLock<mpsc::Sender<Job>> = OnceLock::new();

/// The worker, started on first use.
fn worker() -> Result<&'static mpsc::Sender<Job>> {
    if let Some(sender) = WORKER.get() {
        return Ok(sender);
    }
    let (sender, jobs) = mpsc::channel();
    std::thread::Builder::new()
        .name("strands-box-secrets-manager".to_string())
        .spawn(move || serve(jobs))
        .map_err(|error| {
            CredentialError::Credential(format!("cannot start the Secrets Manager worker: {error}"))
        })?;
    // A racing first caller's worker loses here, and exits when its channel closes.
    Ok(WORKER.get_or_init(|| sender))
}

/// Serve every job on one runtime, with one HTTPS client and one credential chain per region.
fn serve(jobs: mpsc::Receiver<Job>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            for job in jobs {
                let _ = job.answer.send(Err(format!(
                    "cannot start the Secrets Manager client: {error}"
                )));
            }
            return;
        }
    };
    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(Provider::Rustls(CryptoMode::Ring))
        .build_https();
    let mut chains: HashMap<String, Chain> = HashMap::new();
    for job in jobs {
        let fetched = runtime.block_on(serve_one(&http, &mut chains, &job));
        let _ = job.answer.send(fetched);
    }
}

/// The AWS SDK's default credential chain, in its order, with each provider's name.
type Chain = Vec<(&'static str, SharedCredentialsProvider)>;

/// The default chain's five providers, built over the worker's HTTPS client, for `region`.
fn default_chain(http: &SharedHttpClient, region: &Region) -> Chain {
    let config = ProviderConfig::default()
        .with_http_client(http.clone())
        .with_region(Some(region.clone()));
    vec![
        (
            "Environment",
            SharedCredentialsProvider::new(EnvironmentVariableCredentialsProvider::new()),
        ),
        (
            "Profile",
            SharedCredentialsProvider::new(
                ProfileFileCredentialsProvider::builder()
                    .configure(&config)
                    .build(),
            ),
        ),
        (
            "WebIdentityToken",
            SharedCredentialsProvider::new(
                WebIdentityTokenCredentialsProvider::builder()
                    .configure(&config)
                    .build(),
            ),
        ),
        (
            "EcsContainer",
            SharedCredentialsProvider::new(
                EcsCredentialsProvider::builder().configure(&config).build(),
            ),
        ),
        (
            "Ec2InstanceMetadata",
            SharedCredentialsProvider::new(
                ImdsCredentialsProvider::builder()
                    .configure(&config)
                    .build(),
            ),
        ),
    ]
}

/// The first provider in `chain` that holds credentials, as the SDK's chain picks it: a provider
/// with none is skipped, and any other failure stops the search.
async fn first_credentials(
    chain: &Chain,
) -> std::result::Result<(Credentials, &'static str), String> {
    for (name, provider) in chain {
        match provider.provide_credentials().await {
            Ok(credentials) => return Ok((credentials, name)),
            Err(CredentialsError::CredentialsNotLoaded(_)) => continue,
            Err(error) => {
                return Err(format!(
                    "the {name} credential provider failed: {}",
                    DisplayErrorContext(&error)
                ));
            }
        }
    }
    Err(
        "no AWS identity in the environment, a profile, web identity, the container endpoint or \
         instance metadata"
            .to_string(),
    )
}

/// One `GetSecretValue` call, signed by the identity the job names.
async fn serve_one(
    http: &SharedHttpClient,
    chains: &mut HashMap<String, Chain>,
    job: &Job,
) -> std::result::Result<Fetched, String> {
    let region = Region::new(job.region.clone());
    let (credentials, signer) = match &job.identity {
        Identity::DefaultChain => {
            let chain = chains
                .entry(job.region.clone())
                .or_insert_with(|| default_chain(http, &region));
            first_credentials(chain).await?
        }
        #[cfg(test)]
        Identity::Fixed(credentials) => (credentials.clone(), "fixed test credentials"),
    };
    let mut config = aws_sdk_secretsmanager::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(region)
        .http_client(http.clone())
        .timeout_config(
            TimeoutConfig::builder()
                .operation_timeout(FETCH_DEADLINE)
                .connect_timeout(CONNECT_DEADLINE)
                .build(),
        )
        .credentials_provider(credentials);
    if let Some(endpoint) = &job.endpoint {
        config = config.endpoint_url(endpoint);
    }
    let sent = aws_sdk_secretsmanager::Client::from_conf(config.build())
        .get_secret_value()
        .secret_id(&job.secret_id)
        .send()
        .await;
    match sent {
        Ok(mut output) => match output.secret_string.take() {
            Some(value) => Ok(Fetched {
                value: Zeroizing::new(value),
                signer,
            }),
            None => {
                Err("the secret holds binary data, and the box reads a SecretString".to_string())
            }
        },
        Err(error) => Err(refusal(&error)),
    }
}

impl SecretsManagerSource {
    /// The source over the process environment and the SDK's default credential chain.
    pub(crate) fn new() -> Self {
        Self {
            lookup: Box::new(|name: &str| std::env::var_os(name)),
            identity: Identity::DefaultChain,
            endpoint: None,
        }
    }

    /// One variable's value, when it is present, UTF-8 and not blank.
    fn variable(&self, name: &str) -> Option<String> {
        let value = (self.lookup)(name)?.into_string().ok()?;
        (!value.trim().is_empty()).then_some(value)
    }

    /// Hand one fetch to the worker, and wait for its answer.
    fn fetch_from_worker(
        &self,
        secret_id: &str,
        region: String,
    ) -> std::result::Result<Fetched, String> {
        let (answer, answered) = mpsc::channel();
        worker()
            .map_err(|error| error.to_string())?
            .send(Job {
                identity: self.identity.clone(),
                endpoint: self.endpoint.clone(),
                region,
                secret_id: secret_id.to_string(),
                answer,
            })
            .map_err(|_| "the Secrets Manager worker has stopped".to_string())?;
        answered
            .recv_timeout(ANSWER_DEADLINE)
            .map_err(|_| format!("no answer within {} s", ANSWER_DEADLINE.as_secs()))?
    }
}

impl SecretSource for SecretsManagerSource {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn fetch(&self, loc: &Locator) -> Result<Secret> {
        self.fetch_disclosed(loc).map(|(secret, _)| secret)
    }

    fn fetch_disclosed(&self, loc: &Locator) -> Result<(Secret, Option<String>)> {
        let reference = uri_reference(loc, SCHEME)?;
        let (secret_id, field) = secret_reference(reference)?;
        let region = match arn_region(secret_id) {
            Some(region) => region.to_string(),
            None => REGION_VARIABLES
                .iter()
                .find_map(|name| self.variable(name))
                .ok_or_else(|| {
                    CredentialError::Credential(format!(
                        "{} names its secret without an ARN, so it needs a region in AWS_REGION \
                         or AWS_DEFAULT_REGION, and neither is set",
                        redact_credential_ref(reference)
                    ))
                })?,
        };
        let refused = |reason: String| {
            CredentialError::Credential(format!(
                "Secrets Manager returned no secret for {}: {reason}",
                redact_credential_ref(reference)
            ))
        };
        let fetched = self.fetch_from_worker(secret_id, region).map_err(refused)?;
        let value = match field {
            None => fetched.value,
            Some(field) => json_field(&fetched.value, field).map_err(refused)?,
        };
        let disclosure = format!(
            "{} read from Secrets Manager, signed by the AWS credential chain's {} provider \
             (ambient; declare a scoped identity to shrink blast radius)",
            redact_credential_ref(reference),
            fetched.signer
        );
        Ok((Secret::new(value, reference)?, Some(disclosure)))
    }
}

/// The secret a reference names, and the JSON field after `#`, refused unless both are plain.
fn secret_reference(reference: &str) -> Result<(&str, Option<&str>)> {
    let malformed = || {
        CredentialError::Credential(format!(
            "malformed aws-secretsmanager:// reference (expected `aws-secretsmanager://SECRET` or \
             `aws-secretsmanager://SECRET#FIELD`, the secret a name or an ARN of at most \
             {MAXIMUM_SECRET_ID} letters, digits or `/_+=.@-:`): {:?}",
            redact_credential_ref(reference)
        ))
    };
    let body = reference
        .strip_prefix("aws-secretsmanager://")
        .ok_or_else(malformed)?;
    let (secret_id, field) = match body.split_once('#') {
        Some((secret_id, field)) => (secret_id, Some(field)),
        None => (body, None),
    };
    let id_is_valid = (1..=MAXIMUM_SECRET_ID).contains(&secret_id.len())
        && secret_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_+=.@-:".contains(&byte));
    let field_is_valid = field.is_none_or(|field| {
        (1..=MAXIMUM_FIELD).contains(&field.len())
            && !field
                .chars()
                .any(|character| character == '#' || character.is_control())
    });
    if id_is_valid && field_is_valid {
        Ok((secret_id, field))
    } else {
        Err(malformed())
    }
}

/// The region an ARN names, or `None` for a plain secret name.
fn arn_region(secret_id: &str) -> Option<&str> {
    secret_id
        .strip_prefix("arn:")?
        .split(':')
        .nth(2)
        .filter(|region| !region.is_empty())
}

/// One string field of a JSON secret, never echoing the secret in a refusal.
fn json_field(value: &str, field: &str) -> std::result::Result<Zeroizing<String>, String> {
    let parsed: serde_json::Map<String, serde_json::Value> = serde_json::from_str(value)
        .map_err(|_| format!("the secret is not a JSON object, so it has no field {field:?}"))?;
    match parsed.get(field) {
        Some(serde_json::Value::String(found)) => Ok(Zeroizing::new(found.clone())),
        Some(_) => Err(format!("the secret's field {field:?} is not a string")),
        None => Err(format!("the secret has no field {field:?}")),
    }
}

/// Why the call failed: the service's error code and message, or the transport's error chain.
fn refusal<E, R>(error: &SdkError<E, R>) -> String
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
    R: std::fmt::Debug,
{
    match error.as_service_error() {
        Some(service) => format!(
            "{} ({})",
            service.code().unwrap_or("unknown error"),
            service.message().unwrap_or("no message")
        ),
        None => DisplayErrorContext(error).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    use super::*;

    const SECRET: &str = "strands-box/telemetry";
    const LANGFUSE: &str = "pk-lf-test:sk-lf-test";

    fn source(
        values: &[(&'static str, &'static str)],
        endpoint: Option<String>,
    ) -> SecretsManagerSource {
        let values: HashMap<&'static str, &'static str> = values.iter().copied().collect();
        SecretsManagerSource {
            lookup: Box::new(move |name| values.get(name).map(OsString::from)),
            identity: Identity::Fixed(Credentials::new(
                "AKIDEXAMPLE",
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                None,
                None,
                "test",
            )),
            endpoint,
        }
    }

    fn locator(reference: &str) -> Locator {
        Locator::parse_uri(reference).expect("a reference")
    }

    /// The stand-in's answer to a `GetSecretValue` whose secret string is `value`.
    fn answer(value: &str) -> String {
        serde_json::json!({
            "ARN": "arn:aws:secretsmanager:us-west-2:111122223333:secret:strands-box/telemetry-AbCdEf",
            "Name": SECRET,
            "SecretString": value,
            "VersionId": "v1",
        })
        .to_string()
    }

    /// One request the stand-in received: the request line and headers, then the body.
    struct Received {
        head: String,
        body: String,
    }

    /// A loopback stand-in that answers one request with `status`, `headers` and `body`.
    fn stand_in(status: &str, headers: &str, body: &str) -> (String, mpsc::Receiver<Received>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let reply = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/x-amz-json-1.1\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                let read = stream.read(&mut chunk).expect("read");
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while buffer.len() < head_end + length {
                let read = stream.read(&mut chunk).expect("read body");
                buffer.extend_from_slice(&chunk[..read]);
            }
            let body = String::from_utf8_lossy(&buffer[head_end..head_end + length]).to_string();
            stream.write_all(reply.as_bytes()).expect("reply");
            let _ = sender.send(Received { head, body });
        });
        (format!("http://{address}"), receiver)
    }

    /// **A JSON field comes back from `GetSecretValue`, signed as the configured identity.**
    #[test]
    fn a_json_field_is_read_with_a_sigv4_signature() {
        let secret = serde_json::json!({ "LANGFUSE_AUTH": LANGFUSE, "OTHER": "x" }).to_string();
        let (endpoint, received) = stand_in("200 OK", "", &answer(&secret));
        let source = source(&[("AWS_REGION", "us-west-2")], Some(endpoint));

        let found = source
            .fetch(&locator(
                "aws-secretsmanager://strands-box/telemetry#LANGFUSE_AUTH",
            ))
            .expect("the field resolves");
        assert_eq!(found.as_str(), LANGFUSE);

        let request = received.recv().expect("the stand-in was called");
        assert!(request.head.starts_with("POST / "), "{}", request.head);
        assert!(
            request.head.lines().any(
                |line| line.eq_ignore_ascii_case("x-amz-target: secretsmanager.GetSecretValue")
            ),
            "{}",
            request.head
        );
        let authorization = request
            .head
            .lines()
            .find_map(|line| line.strip_prefix("authorization: "))
            .expect("a SigV4 authorization header");
        assert!(
            authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
                && authorization.contains("/us-west-2/secretsmanager/aws4_request"),
            "{authorization}"
        );
        let body: serde_json::Value = serde_json::from_str(&request.body).expect("a JSON body");
        assert_eq!(body["SecretId"], SECRET);
    }

    /// **A secret named without a field is read whole.**
    #[test]
    fn a_whole_secret_string_is_read() {
        let (endpoint, _received) = stand_in("200 OK", "", &answer(LANGFUSE));
        let found = source(&[("AWS_REGION", "us-west-2")], Some(endpoint))
            .fetch(&locator("aws-secretsmanager://strands-box/langfuse"))
            .expect("the secret resolves");
        assert_eq!(found.as_str(), LANGFUSE);
    }

    /// **A missing field, or a secret that is not JSON, is refused and never echoed.**
    #[test]
    fn a_missing_field_is_refused_without_the_secret() {
        let secret = serde_json::json!({ "LANGSMITH_API_KEY": "lsv2-secret-value" }).to_string();
        let (endpoint, _received) = stand_in("200 OK", "", &answer(&secret));
        let error = source(&[("AWS_REGION", "us-west-2")], Some(endpoint))
            .fetch(&locator(
                "aws-secretsmanager://strands-box/telemetry#LANGFUSE_AUTH",
            ))
            .expect_err("no such field")
            .to_string();
        assert!(error.contains("has no field \"LANGFUSE_AUTH\""), "{error}");
        assert!(
            !error.contains("lsv2-secret-value"),
            "the secret leaked: {error}"
        );

        let (endpoint, _received) = stand_in("200 OK", "", &answer("plain-secret-value"));
        let error = source(&[("AWS_REGION", "us-west-2")], Some(endpoint))
            .fetch(&locator(
                "aws-secretsmanager://strands-box/telemetry#LANGFUSE_AUTH",
            ))
            .expect_err("not JSON")
            .to_string();
        assert!(error.contains("not a JSON object"), "{error}");
        assert!(
            !error.contains("plain-secret-value"),
            "the secret leaked: {error}"
        );
    }

    /// **A refusal names the service's error, and the reference stays redacted.**
    #[test]
    fn a_refusal_names_the_service_error() {
        let (endpoint, _received) = stand_in(
            "400 Bad Request",
            "",
            r#"{"__type":"ResourceNotFoundException","Message":"Secrets Manager can't find the specified secret."}"#,
        );
        let error = source(&[("AWS_REGION", "us-west-2")], Some(endpoint))
            .fetch(&locator(
                "aws-secretsmanager://strands-box/telemetry#LANGFUSE_AUTH",
            ))
            .expect_err("a 400 is a refusal")
            .to_string();
        assert!(
            error.contains("ResourceNotFoundException")
                && error.contains("can't find the specified secret"),
            "{error}"
        );
        assert!(
            !error.contains(SECRET),
            "the reference is redacted: {error}"
        );
    }

    /// **An ARN names its own region; a plain name needs one from the environment.**
    #[test]
    fn the_region_comes_from_the_arn_or_the_environment() {
        assert_eq!(
            arn_region("arn:aws:secretsmanager:eu-west-1:111122223333:secret:x-AbCdEf"),
            Some("eu-west-1")
        );
        assert_eq!(arn_region(SECRET), None);
        let error = source(&[], Some("http://127.0.0.1:9".into()))
            .fetch(&locator("aws-secretsmanager://strands-box/telemetry"))
            .expect_err("no region")
            .to_string();
        assert!(error.contains("AWS_REGION"), "{error}");
    }

    /// **Only a plain secret name or ARN, and a plain field, are accepted.**
    #[test]
    fn a_reference_is_plain_and_bounded() {
        assert_eq!(
            secret_reference("aws-secretsmanager://strands-box/telemetry#LANGFUSE_AUTH").ok(),
            Some((SECRET, Some("LANGFUSE_AUTH")))
        );
        assert_eq!(
            secret_reference("aws-secretsmanager://arn:aws:secretsmanager:us-west-2:1:secret:a-1")
                .ok(),
            Some(("arn:aws:secretsmanager:us-west-2:1:secret:a-1", None))
        );
        let too_long = format!("aws-secretsmanager://{}", "a".repeat(MAXIMUM_SECRET_ID + 1));
        for refused in [
            "aws-secretsmanager://",
            "aws-secretsmanager://a b",
            "aws-secretsmanager://a?b",
            "aws-secretsmanager://a#",
            "aws-secretsmanager://a#b#c",
            too_long.as_str(),
        ] {
            assert!(
                secret_reference(refused).is_err(),
                "{refused:?} was accepted"
            );
        }
    }

    /// **A fetch names the credential provider that signed it, and never the secret.**
    #[test]
    fn a_fetch_discloses_the_signing_provider() {
        let (endpoint, _received) = stand_in("200 OK", "", &answer(LANGFUSE));
        let (_, disclosure) = source(&[("AWS_REGION", "us-west-2")], Some(endpoint))
            .fetch_disclosed(&locator("aws-secretsmanager://strands-box/langfuse"))
            .expect("the secret resolves");
        let disclosure = disclosure.expect("a disclosure");
        assert!(
            disclosure.contains("chain's fixed test credentials provider"),
            "{disclosure}"
        );
        assert!(
            !disclosure.contains(LANGFUSE) && !disclosure.contains("langfuse"),
            "{disclosure}"
        );
    }

    /// **Every fetch in the process goes to one worker**, so they share one HTTPS client.
    #[test]
    fn every_fetch_shares_one_worker() {
        let first = worker().expect("a worker") as *const _;
        let second = worker().expect("a worker") as *const _;
        assert!(std::ptr::eq(first, second));
    }

    /// **The SDK adds no second crypto provider.** Its default features compile `aws-lc` beside
    /// `ring`, and `rustls::ClientConfig::builder()` then panics in the egress gateway.
    #[test]
    fn no_second_crypto_provider_is_linked() {
        let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));
        for package in ["aws-lc-rs", "aws-lc-sys"] {
            assert!(
                !lock.contains(&format!("name = \"{package}\"\n")),
                "{package} is in Cargo.lock; keep the AWS SDK's default features off"
            );
        }
        assert_eq!(
            lock.matches("name = \"rustls\"\n").count(),
            1,
            "one rustls version in the process"
        );
    }
}
