//! A credential binding attaches a secret only to a request the policy permits.

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, RouteSpec, SecretSourceCommand, Vault,
    VaultConfig,
};
use egress_gateway::{
    AuditDecision, CapabilitySet, CredentialCapability, MitmConfig, MitmInterceptor, StubEmitter,
};
use harness::{TlsUpstream, WorkloadClient};
use policy::{EgressPolicyInterceptor, GovernedBox, Policy, PolicyEngine, Principal};

const HOST: &str = "api.bound.test";
const REAL_SECRET: &str = "sk_live_method_scope_7c1e";

fn env_locator(secret: &str) -> Locator {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "CREDENTIAL_METHOD_SCOPE_SECRET_{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // SAFETY: the name is unique to this call, so no other test reads or writes it.
    unsafe { std::env::set_var(&name, secret) };
    Locator::parse_uri(&format!("env://{name}")).expect("an env locator parses")
}

/// One opaque `Authorization: Bearer` route bound to `host:port`, with its minted phantom.
fn bound_vault(host: &str, port: u16) -> (Arc<Vault>, String) {
    vault_over(Backend::local(), env_locator(REAL_SECRET), host, port)
}

/// One opaque `Authorization: Bearer` route bound to `host:port` whose secret `backend` reads
/// for `locator`, with its minted phantom.
fn vault_over(backend: Backend, locator: Locator, host: &str, port: u16) -> (Arc<Vault>, String) {
    let pattern =
        DestinationPattern::parse(&format!("{host}:{port}")).expect("a host:port pattern");
    let opened = Vault::open(VaultConfig::new(backend, "tenant").route(RouteSpec::opaque(
        pattern,
        locator,
        InjectMode::header("Bearer {}".to_string(), None).expect("a header placement"),
    )))
    .expect("the vault opens");
    let phantom = opened.phantoms()[0].token().to_string();
    (Arc::new(opened.into_vault()), phantom)
}

fn get_only_policy(port: u16, history: &std::path::Path) -> PolicyEngine {
    PolicyEngine::open(
        vec![Policy {
            origin: PathBuf::from("credential-method-scope.dw"),
            text: format!(
                r#"permit(principal, action == Box::Action::"net:connect", resource)
when {{ context.input.host == "{HOST}" && context.input.port == {port} }};
permit(principal, action == Box::Action::"http:request", resource)
when {{ context.input.host == "{HOST}" && context.input.port == {port} && context.input.method == "GET" }};"#
            ),
        }],
        &history.join("dogwood.redb"),
    )
    .expect("the policy opens")
}

#[test]
fn a_bound_host_with_a_get_only_permit_refuses_delete_before_the_upstream_and_leaks_no_secret() {
    let upstream = TlsUpstream::start(HOST);
    let port = upstream.port();
    let (vault, phantom) = bound_vault(HOST, port);
    let history = tempfile::tempdir().expect("a history directory");
    let interceptor = EgressPolicyInterceptor::into_handle(
        Arc::new(get_only_policy(port, history.path())),
        Principal::agent(),
        GovernedBox::assigned("credential-method-scope"),
    );
    let capabilities = CapabilitySet::new(vec![CredentialCapability::new(
        DestinationPattern::parse(&format!("{HOST}:{port}")).expect("a host:port pattern"),
        vault,
    )]);
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(HOST.to_string(), "127.0.0.1".parse().expect("loopback"))],
        ..MitmConfig::default()
    };
    let records = StubEmitter::new();
    let handle = MitmInterceptor::start_with(
        config,
        capabilities,
        interceptor,
        Box::new(records.clone()),
        None,
    )
    .expect("the gateway starts");
    let proxy_port = handle.port().expect("a TCP gateway has a port");
    let authorization = format!("Bearer {phantom}");

    let mut get = WorkloadClient::connect(proxy_port, HOST, port);
    get.send_request(
        "GET",
        "/v1/items",
        &[("Authorization", &authorization)],
        b"",
    );
    let get_response = get.read_response();
    assert!(get_response.starts_with("HTTP/1.1 200 "), "{get_response}");
    let seen = upstream.last_request();
    assert_eq!(
        seen.header("authorization").as_deref(),
        Some(format!("Bearer {REAL_SECRET}").as_str()),
        "the permitted GET carries the real secret upstream: {}",
        seen.raw
    );
    assert!(!seen.raw.contains(&phantom), "{}", seen.raw);

    let mut delete = WorkloadClient::connect(proxy_port, HOST, port);
    delete.send_request(
        "DELETE",
        "/v1/items/1",
        &[("Authorization", &authorization)],
        b"",
    );
    let delete_response = delete.read_response();
    let (head, body) = delete_response
        .split_once("\r\n\r\n")
        .expect("an HTTP response");
    assert!(head.starts_with("HTTP/1.1 403 "), "{delete_response}");
    assert_eq!(
        body,
        format!(
            "http:request gate: policy denied this operation on '{HOST}:{port}/v1/items/1' \
             [default-deny]: No permit policy matched this request."
        )
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "the refused DELETE must never reach the upstream"
    );
    assert!(!delete_response.contains(REAL_SECRET), "{delete_response}");

    let records = records.records();
    assert!(
        records
            .iter()
            .any(|record| record.decision == AuditDecision::Deny),
        "the DELETE refusal is recorded: {records:?}"
    );
    for record in &records {
        assert!(!format!("{record:?}").contains(REAL_SECRET), "{record:?}");
    }
}

/// **The gateway attaches a secret that a declared program read**: a permitted request that
/// carries the placeholder reaches the origin with the secret, after the backend dropped its copy.
#[test]
fn a_secret_that_a_declared_program_read_rides_a_permitted_request() {
    const DECLARED_SECRET: &str = "sk_live_declared_program_5e2a";
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let script = scratch.path().join("vault.sh");
    std::fs::write(
        &script,
        format!(
            "echo \"$1\" >> '{}'\nprintf '%s\\n' {DECLARED_SECRET}\n",
            scratch.path().join("runs").display()
        ),
    )
    .expect("write the stand-in program");
    let command = ["/bin/sh", script.to_str().expect("a UTF-8 path"), "{ref}"].map(str::to_string);
    let declaration = SecretSourceCommand::new("vault", SecretSourceCommand::PROTOCOL, &command)
        .expect("a valid declaration");
    let checked = std::fs::File::open("/bin/sh").expect("the shell opens");
    let backend = Backend::declared([(declaration, checked)]).expect("the scheme is free");

    let upstream = TlsUpstream::start(HOST);
    let port = upstream.port();
    let locator = Locator::parse_uri("vault://team/api-key").expect("the reference parses");
    let (vault, phantom) = vault_over(backend.clone(), locator, HOST, port);
    // The vault holds the secret now, so the run drops the copy of the backend.
    backend.close_declared();
    assert_eq!(
        std::fs::read_to_string(scratch.path().join("runs")).expect("the program ran"),
        "team/api-key\n"
    );
    assert_ne!(phantom, DECLARED_SECRET);

    let history = tempfile::tempdir().expect("a history directory");
    let interceptor = EgressPolicyInterceptor::into_handle(
        Arc::new(get_only_policy(port, history.path())),
        Principal::agent(),
        GovernedBox::assigned("credential-method-scope"),
    );
    let capabilities = CapabilitySet::new(vec![CredentialCapability::new(
        DestinationPattern::parse(&format!("{HOST}:{port}")).expect("a host:port pattern"),
        vault,
    )]);
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(HOST.to_string(), "127.0.0.1".parse().expect("loopback"))],
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start_with(
        config,
        capabilities,
        interceptor,
        Box::new(StubEmitter::new()),
        None,
    )
    .expect("the gateway starts");
    let proxy_port = handle.port().expect("a TCP gateway has a port");

    let mut get = WorkloadClient::connect(proxy_port, HOST, port);
    get.send_request(
        "GET",
        "/v1/items",
        &[("Authorization", &format!("Bearer {phantom}"))],
        b"",
    );
    let response = get.read_response();
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    let seen = upstream.last_request();
    assert_eq!(
        seen.header("authorization").as_deref(),
        Some(format!("Bearer {DECLARED_SECRET}").as_str()),
        "the permitted request carries the secret of the program: {}",
        seen.raw
    );
    assert!(!seen.raw.contains(&phantom), "{}", seen.raw);
    assert!(!response.contains(DECLARED_SECRET), "{response}");
}
