//! Rust SDK credential providers behind the synchronous signing boundary.

use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, SystemTime};

use aws_config::default_provider::credentials::DefaultCredentialsChain;
use aws_config::environment::region::EnvironmentVariableRegionProvider;
use aws_config::imds::region::ImdsRegionProvider;
use aws_config::meta::region::RegionProviderChain;
use aws_config::profile::{ProfileFileCredentialsProvider, ProfileFileRegionProvider};
use aws_config::provider_config::ProviderConfig;
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_smithy_http_client::{Builder, tls};
use zeroize::Zeroizing;

use crate::{AwsSessionCredentials, CredentialError, Result};

const LOAD_TIMEOUT: Duration = Duration::from_secs(30);
const REPLY_TIMEOUT: Duration = Duration::from_secs(35);

type Reply = SyncSender<Result<Zeroizing<AwsSessionCredentials>>>;

pub(super) struct SdkCredentials {
    requests: SyncSender<Reply>,
}

impl SdkCredentials {
    pub(super) fn open(profile: Option<String>) -> Result<Self> {
        let warm_chain = profile.is_none();
        let (requests, receiver) = mpsc::sync_channel::<Reply>(1);
        let (ready, initialized) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("box-aws-credentials".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ = ready.send(Err(failure("runtime initialization failed")));
                        return;
                    }
                };
                let mut provider = None;
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while let Ok(reply) = receiver.recv() {
                    let result = runtime.block_on(async {
                        tokio::time::timeout(LOAD_TIMEOUT, async {
                            if provider.is_none() {
                                provider = Some(load_provider(profile.as_deref()).await);
                            }
                            resolve(provider.as_ref().expect("provider was loaded")).await
                        })
                        .await
                        .map_err(|_| failure("credential resolution timed out"))?
                    });
                    let _ = reply.send(result);
                }
            })
            .map_err(|_| failure("worker could not start"))?;
        initialized
            .recv_timeout(REPLY_TIMEOUT)
            .map_err(|_| failure("worker initialization did not complete"))??;
        let credentials = Self { requests };
        if warm_chain {
            credentials.resolve()?;
        }
        Ok(credentials)
    }

    pub(super) fn resolve(&self) -> Result<Zeroizing<AwsSessionCredentials>> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.requests
            .try_send(reply)
            .map_err(|_| failure("worker is busy or unavailable"))?;
        receiver
            .recv_timeout(REPLY_TIMEOUT)
            .map_err(|_| failure("worker did not return credentials"))?
    }
}

async fn load_provider(profile: Option<&str>) -> SharedCredentialsProvider {
    let http = Builder::new()
        .tls_provider(tls::Provider::Rustls(
            tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https();
    let config = ProviderConfig::default().with_http_client(http);
    match profile {
        None => SharedCredentialsProvider::new(
            DefaultCredentialsChain::builder()
                .configure(config)
                .build()
                .await,
        ),
        Some(profile) => {
            let region = RegionProviderChain::first_try(EnvironmentVariableRegionProvider::new())
                .or_else(
                    ProfileFileRegionProvider::builder()
                        .configure(&config)
                        .profile_name(profile)
                        .build(),
                )
                .or_else(ImdsRegionProvider::builder().configure(&config).build())
                .region()
                .await;
            SharedCredentialsProvider::new(
                ProfileFileCredentialsProvider::builder()
                    .configure(&config.with_region(region))
                    .profile_name(profile)
                    .build(),
            )
        }
    }
}

async fn resolve(chain: &SharedCredentialsProvider) -> Result<Zeroizing<AwsSessionCredentials>> {
    let credentials = chain
        .provide_credentials()
        .await
        .map_err(|_| failure("no usable credentials; check the trusted AWS configuration"))?;
    if credentials
        .expiry()
        .is_some_and(|expiry| expiry <= SystemTime::now())
    {
        return Err(failure("provider returned expired credentials"));
    }
    for value in [
        Some(credentials.access_key_id()),
        Some(credentials.secret_access_key()),
        credentials.session_token(),
    ]
    .into_iter()
    .flatten()
    {
        if value.trim().is_empty() || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(failure("provider returned an invalid credential field"));
        }
    }
    Ok(Zeroizing::new(AwsSessionCredentials {
        access_key_id: credentials.access_key_id().to_string(),
        secret_access_key: credentials.secret_access_key().to_string(),
        session_token: credentials.session_token().map(str::to_string),
        region: None,
    }))
}

fn failure(message: &str) -> CredentialError {
    CredentialError::Credential(format!("AWS SDK credentials: {message}"))
}

#[cfg(test)]
#[path = "aws_sdk_tests.rs"]
mod tests;
