//! `aws-secretsmanager://SECRET[#FIELD]` — one `GetSecretValue` request, driven on the default
//! chain's worker ([`SdkChainProvider::call`]) with that worker's runtime, HTTPS client and
//! credentials, so this source adds the request and nothing else.

use std::ffi::OsString;
use std::time::Duration;

use aws_sdk_secretsmanager::config::timeout::TimeoutConfig;
use aws_sdk_secretsmanager::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_secretsmanager::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use zeroize::{Zeroize, Zeroizing};

use crate::sources::aws_chain::{CallContext, SdkChainProvider};
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

/// The longest a fetch waits for the worker: a credential resolve, then the call.
const ANSWER_DEADLINE: Duration = Duration::from_secs(20);

/// A variable lookup, so a test reads no host state.
type Lookup = Box<dyn Fn(&str) -> Option<OsString> + Send + Sync>;

/// Which default-chain worker a fetch runs on.
enum Chain {
    /// The process's one worker, started on first use.
    Shared,
    /// A worker over fixed credentials, so a test reads no host state.
    #[cfg(test)]
    Own(SdkChainProvider),
}

/// Reads a secret from AWS Secrets Manager (`aws-secretsmanager://SECRET[#FIELD]`).
pub(crate) struct SecretsManagerSource {
    lookup: Lookup,
    chain: Chain,
    endpoint: Option<String>,
}

/// One `GetSecretValue` call on the worker, signed with the chain's credentials.
async fn get_secret_value(
    context: CallContext,
    endpoint: Option<String>,
    region: String,
    secret_id: String,
) -> Result<Zeroizing<String>> {
    let credentials = Credentials::new(
        context.credentials.access_key_id.clone(),
        context.credentials.secret_access_key.clone(),
        context.credentials.session_token.clone(),
        None,
        "strands-box-default-chain",
    );
    let mut config = aws_sdk_secretsmanager::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region))
        .http_client(context.http_client)
        .timeout_config(
            TimeoutConfig::builder()
                .operation_timeout(FETCH_DEADLINE)
                .connect_timeout(CONNECT_DEADLINE)
                .build(),
        )
        .credentials_provider(credentials);
    if let Some(endpoint) = endpoint {
        config = config.endpoint_url(endpoint);
    }
    let sent = aws_sdk_secretsmanager::Client::from_conf(config.build())
        .get_secret_value()
        .secret_id(&secret_id)
        .send()
        .await;
    match sent {
        Ok(mut output) => output
            .secret_string
            .take()
            .map(Zeroizing::new)
            .ok_or_else(|| {
                CredentialError::Credential(
                    "the secret holds binary data, and the box reads a SecretString".to_string(),
                )
            }),
        Err(error) => Err(CredentialError::Credential(refusal(&error, &secret_id))),
    }
}

impl SecretsManagerSource {
    /// The source over the process environment, on the default chain a bare `aws://` uses.
    pub(crate) fn new() -> Self {
        Self {
            lookup: Box::new(|name: &str| std::env::var_os(name)),
            chain: Chain::Shared,
            endpoint: None,
        }
    }

    /// One variable's value, when it is present, UTF-8 and not blank.
    fn variable(&self, name: &str) -> Option<String> {
        let value = (self.lookup)(name)?.into_string().ok()?;
        (!value.trim().is_empty()).then_some(value)
    }

    /// The default-chain worker this source fetches on.
    fn chain(&self) -> &SdkChainProvider {
        match &self.chain {
            Chain::Shared => SdkChainProvider::shared(),
            #[cfg(test)]
            Chain::Own(provider) => provider,
        }
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
        let (endpoint, secret_id) = (self.endpoint.clone(), secret_id.to_string());
        let fetched = self
            .chain()
            .call(ANSWER_DEADLINE, move |context| {
                get_secret_value(context, endpoint, region, secret_id)
            })
            .map_err(|error| refused(error.to_string()))?;
        let value = match field {
            None if is_json_object(&fetched) => {
                return Err(refused(
                    "the secret is a JSON object, so name one field with `#FIELD`; the whole \
                     object holds more than one key"
                        .to_string(),
                ));
            }
            None => fetched,
            Some(field) => json_field(&fetched, field).map_err(refused)?,
        };
        let disclosure = format!(
            "{} read from Secrets Manager, signed with the host's ambient AWS identity from the \
             default credential provider chain. Grant the workload no write access to ~/.aws",
            redact_credential_ref(reference)
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

/// One string field of a JSON secret, never echoing the secret in a refusal. Every other value the
/// parse copied is wiped before it drops, and the field moves out rather than being cloned.
fn json_field(value: &str, field: &str) -> std::result::Result<Zeroizing<String>, String> {
    let mut parsed: serde_json::Map<String, serde_json::Value> = serde_json::from_str(value)
        .map_err(|_| format!("the secret is not a JSON object, so it has no field {field:?}"))?;
    let found = parsed.remove(field);
    wipe_object(&mut parsed);
    match found {
        Some(serde_json::Value::String(found)) => Ok(Zeroizing::new(found)),
        Some(mut other) => {
            wipe_value(&mut other);
            Err(format!("the secret's field {field:?} is not a string"))
        }
        None => Err(format!("the secret has no field {field:?}")),
    }
}

/// Whether a whole secret is a JSON object, wiping the copy the check parsed.
fn is_json_object(value: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(value) {
        Ok(serde_json::Value::Object(mut object)) => {
            wipe_object(&mut object);
            true
        }
        Ok(mut other) => {
            wipe_value(&mut other);
            false
        }
        Err(_) => false,
    }
}

/// Wipe every string a parsed JSON value holds.
fn wipe_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe_value),
        serde_json::Value::Object(object) => wipe_object(object),
        _ => {}
    }
}

/// Wipe every string value a parsed JSON object holds.
fn wipe_object(object: &mut serde_json::Map<String, serde_json::Value>) {
    object.values_mut().for_each(wipe_value);
}

/// Why the call failed: the service's error code and message, or the transport's error chain, with
/// the secret's name replaced wherever the service quotes it.
fn refusal<E, R>(error: &SdkError<E, R>, secret_id: &str) -> String
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
    R: std::fmt::Debug,
{
    let reason = match error.as_service_error() {
        Some(service) => format!(
            "{} ({})",
            service.code().unwrap_or("unknown error"),
            service.message().unwrap_or("no message")
        ),
        None => DisplayErrorContext(error).to_string(),
    };
    reason.replace(secret_id, "[REDACTED]")
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
            chain: Chain::Own(SdkChainProvider::with_resolver_and_io(|| {
                Ok((
                    crate::AwsSessionCredentials {
                        access_key_id: "AKIDEXAMPLE".to_string(),
                        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
                        session_token: None,
                        region: None,
                    },
                    None,
                ))
            })),
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

    /// **A chain that finds no identity stops the fetch before any call**, and the refusal keeps
    /// the reference redacted.
    #[test]
    fn a_missing_identity_is_refused_before_any_call() {
        let source = SecretsManagerSource {
            lookup: Box::new(|name| (name == "AWS_REGION").then(|| OsString::from("us-west-2"))),
            chain: Chain::Own(SdkChainProvider::with_resolver_and_io(|| {
                Err(CredentialError::KeystoreAccess(
                    "AWS default credential chain resolved no credentials".to_string(),
                ))
            })),
            endpoint: Some("http://127.0.0.1:9".to_string()),
        };
        let error = source
            .fetch(&locator(
                "aws-secretsmanager://strands-box/telemetry#LANGFUSE_AUTH",
            ))
            .expect_err("no identity")
            .to_string();
        assert!(error.contains("resolved no credentials"), "{error}");
        assert!(
            !error.contains(SECRET),
            "the reference is redacted: {error}"
        );
    }

    /// **A whole-secret read of a JSON object is refused**, so one vendor is never sent every
    /// key the object holds.
    #[test]
    fn a_whole_json_object_is_refused() {
        let secret =
            serde_json::json!({ "LANGFUSE_AUTH": LANGFUSE, "OTHER": "lsv2-other" }).to_string();
        let (endpoint, _received) = stand_in("200 OK", "", &answer(&secret));
        let error = source(&[("AWS_REGION", "us-west-2")], Some(endpoint))
            .fetch(&locator("aws-secretsmanager://strands-box/telemetry"))
            .expect_err("a JSON object needs a field")
            .to_string();
        assert!(error.contains("name one field with `#FIELD`"), "{error}");
        assert!(
            !error.contains("lsv2-other") && !error.contains(LANGFUSE),
            "{error}"
        );
    }

    /// **A service refusal that quotes the secret's name is redacted**, as an `AccessDenied`
    /// message quotes the resource.
    #[test]
    fn a_service_message_that_quotes_the_secret_is_redacted() {
        let (endpoint, _received) = stand_in(
            "400 Bad Request",
            "",
            r#"{"__type":"AccessDeniedException","Message":"User: arn:aws:sts::111122223333:assumed-role/r/s is not authorized to perform: secretsmanager:GetSecretValue on resource: strands-box/telemetry"}"#,
        );
        let error = source(&[("AWS_REGION", "us-west-2")], Some(endpoint))
            .fetch(&locator(
                "aws-secretsmanager://strands-box/telemetry#LANGFUSE_AUTH",
            ))
            .expect_err("denied")
            .to_string();
        assert!(error.contains("AccessDeniedException"), "{error}");
        assert!(!error.contains(SECRET), "the name leaked: {error}");
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

    /// **A fetch says it signed with the ambient identity, and never names the secret.**
    #[test]
    fn a_fetch_discloses_the_ambient_identity() {
        let (endpoint, _received) = stand_in("200 OK", "", &answer(LANGFUSE));
        let (_, disclosure) = source(&[("AWS_REGION", "us-west-2")], Some(endpoint))
            .fetch_disclosed(&locator("aws-secretsmanager://strands-box/langfuse"))
            .expect("the secret resolves");
        let disclosure = disclosure.expect("a disclosure");
        assert!(
            disclosure.contains("ambient AWS identity from the default credential provider chain"),
            "{disclosure}"
        );
        assert!(
            !disclosure.contains(LANGFUSE) && !disclosure.contains("langfuse"),
            "{disclosure}"
        );
    }

    /// **The source fetches on the default chain's shared worker**, the one a bare `aws://` signs
    /// with, and starts no worker of its own.
    #[test]
    fn the_source_fetches_on_the_shared_default_chain() {
        let source = SecretsManagerSource::new();
        assert!(std::ptr::eq(source.chain(), SdkChainProvider::shared()));
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
