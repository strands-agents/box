//! One program, two boundaries, one history.
//!
//! The Shell and the egress proxy are independent enforcement points: neither knows the
//! other exists. Pointing both at the same `Arc<PolicyEngine>` gives them one ordered event
//! history, which is what makes a rule spanning them enforceable — read a secret through
//! the Shell, and the outbound request that follows is refused.
//!
//! ```text
//!   Shell  --fs:read /secrets--> ShellPolicyInterceptor  --.
//!                                                          >-- one Policy, one history
//!   proxy  --http:request-------> EgressPolicyInterceptor --'
//! ```
//!
//! That rule is unexpressible if each boundary owns its own engine, so this is the test
//! that justifies sharing a temporal stream rather than partitioning per enforcement
//! point. It is also the only place both adapters run against one another.

#![cfg(all(feature = "shell-adapter", feature = "egress-adapter"))]

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use egress_gateway::{CapabilitySet, MitmConfig, MitmHandle, MitmInterceptor};
use policy::{
    EgressPolicyInterceptor, GovernedBox, Policy, PolicyEngine, Principal, ShellPolicyInterceptor,
};
use strands_shell::Shell;

use harness::{TlsUpstream, WorkloadClient};

/// The box this suite governs. One box, so one name.
const BOX_NAME: &str = "cross-boundary";

/// Run a future on the current-thread runtime the Shell requires.
fn run<F, T>(body: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds");
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(body))
}

fn proxy_port(handle: &MitmHandle) -> u16 {
    handle.port().expect("a TCP-mode proxy always has a port")
}

/// Permit the transport legs the cross-boundary rule does not govern.
///
/// The rule below gates `http:request`; without these the connect would be refused first
/// and the request leg would never be reached.
const TRANSPORT: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource);
"#;

/// Shell effects the workload needs in order to reach the secret at all.
const SHELL_ACCESS: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
"#;

/// The cross-boundary rule: no outbound request after a secret has been read.
///
/// The predicate matches a `fs:read` **resolution** whose path is the secret, so it can
/// only fire because the Shell's permit recorded that outcome. `!(formerly …)` is the
/// exfiltration shape: everything is permitted until the read happens, then egress
/// closes.
const NO_EGRESS_AFTER_SECRET_READ: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
unless temporal {
    formerly within 300s
    Box::Action::"fs:read"::response{ input.path: "/tmp/secrets/token", input.operation: Box::FsReadOperation::"read_content" }
};
"#;

fn shared_policy(sources: &[&str]) -> Arc<PolicyEngine> {
    let text = sources.join("\n");
    Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("cross-boundary.dw"),
            text,
        }])
        .expect("policy loads"),
    )
}

fn shell_on(policy: &Arc<PolicyEngine>) -> Shell {
    Shell::builder()
        .effect_interceptor(ShellPolicyInterceptor::into_handle(
            Arc::clone(policy),
            Principal::agent(),
            GovernedBox::assigned(BOX_NAME),
        ))
        .build()
        .expect("shell builds")
}

fn proxy_on(policy: &Arc<PolicyEngine>, host: &str, upstream: &TlsUpstream) -> MitmHandle {
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    MitmInterceptor::start(
        config,
        CapabilitySet::default(),
        EgressPolicyInterceptor::into_handle(
            Arc::clone(policy),
            Principal::agent(),
            GovernedBox::assigned(BOX_NAME),
        ),
    )
    .expect("proxy starts")
}

/// Send one request through the proxy and return its status.
fn request_through(handle: &MitmHandle, host: &str, port: u16) -> u16 {
    let mut client = WorkloadClient::connect(proxy_port(handle), host, port);
    client.send_request("POST", "/v1/upload", &[], b"payload");
    client.read_status()
}

#[test]
fn reading_a_secret_in_the_shell_closes_egress_in_the_proxy() {
    let host = "api.exfil.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();

    let policy = shared_policy(&[TRANSPORT, SHELL_ACCESS, NO_EGRESS_AFTER_SECRET_READ]);
    let mut shell = shell_on(&policy);
    let handle = proxy_on(&policy, host, &upstream);

    run(async {
        // Egress is open before the secret is touched.
        assert_eq!(
            request_through(&handle, host, port),
            200,
            "egress is permitted before any secret read"
        );

        // Stage the secret and read it *through the Shell*. This is the only step that
        // touches the other boundary, and it records the history the rule reads.
        shell
            .write_file("/tmp/secrets/token", b"super-secret")
            .await
            .expect("staging the secret is permitted");
        let contents = shell
            .read_file("/tmp/secrets/token")
            .await
            .expect("reading the secret is permitted");
        assert_eq!(contents, b"super-secret");

        // The same request is now refused — by a Shell effect, at the network boundary.
        assert_eq!(
            request_through(&handle, host, port),
            403,
            "egress must close once the secret has been read in the Shell"
        );

        // And it stays closed for the window.
        assert_eq!(request_through(&handle, host, port), 403);
    });

    // The upstream saw only the requests that were allowed.
    assert_eq!(
        upstream.request_count(),
        1,
        "exactly one request reached the network"
    );
}

#[test]
fn reading_an_unrelated_file_leaves_egress_open() {
    // The control that makes the test above meaningful. Same policy, same boundaries,
    // same call sequence — but the Shell reads a different path, so the rule's predicate
    // does not match and egress stays open. Without this, the denial above could be
    // caused by any Shell activity rather than by reading the secret.
    let host = "api.control.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();

    let policy = shared_policy(&[TRANSPORT, SHELL_ACCESS, NO_EGRESS_AFTER_SECRET_READ]);
    let mut shell = shell_on(&policy);
    let handle = proxy_on(&policy, host, &upstream);

    run(async {
        assert_eq!(request_through(&handle, host, port), 200);

        shell
            .write_file("/tmp/notes.txt", b"harmless")
            .await
            .expect("write is permitted");
        shell
            .read_file("/tmp/notes.txt")
            .await
            .expect("read is permitted");

        assert_eq!(
            request_through(&handle, host, port),
            200,
            "an unrelated read must not close egress"
        );
    });

    assert_eq!(upstream.request_count(), 2);
}

#[test]
fn each_boundary_still_enforces_its_own_rules_independently() {
    // Sharing a history must not merge the two vocabularies. A policy that permits
    // egress and denies Shell writes has to keep doing both: the boundaries are
    // independent enforcement points that happen to consult one authority.
    let host = "api.independent.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();

    let policy = shared_policy(&[
        TRANSPORT,
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);"#,
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);"#,
    ]);
    let mut shell = shell_on(&policy);
    let handle = proxy_on(&policy, host, &upstream);

    run(async {
        // Egress is permitted.
        assert_eq!(request_through(&handle, host, port), 200);
        // The Shell filesystem is not: no `fs:write` permit exists.
        assert!(
            shell.write_file("/tmp/blocked.txt", b"x").await.is_err(),
            "a Shell write must be refused even while egress is open"
        );
    });
}
