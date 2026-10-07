//! A credential binding attaches a secret only to a request the policy permits.

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, RouteSpec, Vault, VaultConfig,
};
use egress_gateway::{
    AuditDecision, CapabilitySet, CredentialCapability, MitmConfig, MitmInterceptor,
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
    let pattern =
        DestinationPattern::parse(&format!("{host}:{port}")).expect("a host:port pattern");
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(
        RouteSpec::opaque(
            pattern,
            env_locator(REAL_SECRET),
            InjectMode::header("Bearer {}".to_string(), None).expect("a header placement"),
        ),
    ))
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
    let capabilities = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(
            DestinationPattern::parse(&format!("{HOST}:{port}")).expect("a host:port pattern"),
            vault,
        ))
        .build();
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(HOST.to_string(), "127.0.0.1".parse().expect("loopback"))],
        ..MitmConfig::default()
    };
    let handle =
        MitmInterceptor::start(config, capabilities, interceptor).expect("the gateway starts");
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

    let events = handle.drain_audit_events();
    assert!(
        events
            .iter()
            .any(|event| event.decision == AuditDecision::Deny),
        "the DELETE refusal is audited: {events:?}"
    );
    for event in &events {
        assert!(!format!("{event:?}").contains(REAL_SECRET), "{event:?}");
    }
}
