//! Requests the real egress gateway refuses on its own reach the real policy history.
//!
//! The gateway refuses some requests before it asks policy, such as an inner `Host` that names
//! another authority. This drives such probes over TLS through `MitmInterceptor` and the shipped
//! `EgressPolicyInterceptor`, and asserts that a temporal attempt cap counts them:
//!
//! ```text
//! workload --TLS--> proxy --refusal--> EgressPolicyInterceptor::observe_refused --> history
//!                     '--next request--> EgressPolicyInterceptor::intercept --> decide (cap)
//! ```

#![cfg(feature = "egress-adapter")]

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use egress_gateway::{AuditDecision, CapabilitySet, MitmConfig, MitmInterceptor, StubEmitter};
use policy::{EgressPolicyInterceptor, GovernedBox, Policy, Principal};

use harness::{TlsUpstream, WorkloadClient};

/// Three `http:request` attempts on the host within the window refuse every later one.
const ATTEMPT_CAP: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when { context.input.host == "api.probed.test" };
forbid(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when temporal {
  exists (n: Long). (
    (count for (t: Timepoint). where (
      formerly within 3600s (
        Box::Action::"http:request"::request{ input.host: "api.probed.test" } && tp(t)
      )
    )) == n
    && n >= 3
  )
};
"#;

/// Send `probes` requests the gateway refuses on its own, then one ordinary request, and return
/// the ordinary request's status, the request-leg denial reasons, and the upstream request count.
fn probe_then_request(probes: usize) -> (u16, Vec<String>, usize) {
    let host = "api.probed.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let policy = Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("attempt_cap.dw"),
            text: ATTEMPT_CAP.to_string(),
        }])
        .expect("the attempt cap loads"),
    );
    let interceptor = EgressPolicyInterceptor::into_handle(
        policy,
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );
    let records = StubEmitter::new();
    let handle = MitmInterceptor::start_with(
        MitmConfig {
            upstream_ca_pems: vec![upstream.ca_pem()],
            dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
            ..MitmConfig::default()
        },
        CapabilitySet::default(),
        interceptor,
        Box::new(records.clone()),
        None,
    )
    .expect("proxy starts");
    let proxy = handle.port().expect("a TCP-mode proxy has a port");

    for _ in 0..probes {
        let mut client = WorkloadClient::connect(proxy, host, port);
        client.send_request_with_authority("GET", "/admin", "metadata.google.internal", &[], b"");
        assert_eq!(client.read_status(), 403, "the gateway refuses the probe");
    }
    let mut client = WorkloadClient::connect(proxy, host, port);
    client.send_request("GET", "/v1/items", &[], b"");
    let status = client.read_status();

    let denials = records
        .records()
        .into_iter()
        .filter(|record| record.decision == AuditDecision::Deny && !record.method.is_empty())
        .map(|record| record.reason)
        .collect();
    (status, denials, upstream.request_count())
}

#[test]
fn refused_probes_count_toward_an_attempt_cap_through_the_real_proxy() {
    let (status, denials, reached) = probe_then_request(2);
    assert_eq!(
        status, 403,
        "two refused probes and this request reach the cap: {denials:?}"
    );
    assert_eq!(denials.len(), 3, "{denials:?}");
    assert!(
        denials[..2]
            .iter()
            .all(|reason| reason.contains("does not match CONNECT authority")),
        "the gateway refused each probe on its own: {denials:?}"
    );
    assert!(
        denials[2].contains("request effect interception failed"),
        "policy, not the gateway, refused the ordinary request: {denials:?}"
    );
    assert_eq!(reached, 0, "no request reached the origin");
}

#[test]
fn without_probes_the_same_request_is_under_the_cap() {
    let (status, denials, reached) = probe_then_request(0);
    assert_eq!(status, 200, "one attempt is under the cap: {denials:?}");
    assert!(denials.is_empty(), "{denials:?}");
    assert_eq!(reached, 1);
}
