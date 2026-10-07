//! Monty and the egress proxy, one authority, one history.
//!
//! The Script counterpart of [`cross_boundary_e2e`], and it exists for the same reason:
//! a rule spanning two enforcement points is only enforceable if both consult **one**
//! `Policy` instance. `Policy::decide` observes each request into temporal history
//! before answering, so two instances are two disjoint histories and such a rule loads
//! cleanly while enforcing nothing.
//!
//! ```text
//!   Monty  --fs:read /secrets--> ScriptPolicyInterceptor  --.
//!                                                           >-- one Policy, one history
//!   proxy  --net:connect-------> EgressPolicyInterceptor  --'
//! ```
//!
//! # What this pins, and what the box's own suite pins
//!
//! This is the **library-level** guard: two enforcement points, one `Arc<PolicyEngine>`, and a
//! rule that spans them. `box` is the consumer — `box/src/monty/host.rs` hosts Monty on the
//! daemon's instance — and its `box_shell.rs::a_python_read_closes_egress` asserts the same
//! property end to end through the real alias, socket, and proxy. Both are kept: this one
//! fails fast and names the seam, that one proves the product is wired to reach it.
//!
//! One `Policy` per box is a premise (docs/design/decisions.md#one-policy-engine-per-box). If
//! a future consumer opens its own `Policy`, the shape asserted here is what it will have
//! broken.
//!
//! # What it does not cover
//!
//! The **floors beneath policy**. This exercises the authority; it says nothing about the
//! path confinement that stops a permit from reaching outside the box home, because that is
//! the host's job rather than the adapter's. `box/src/monty/host.rs::confine` owns it, and
//! the box suite pins it — including two escapes an adversarial review found there.

#![cfg(all(feature = "script-adapter", feature = "egress-adapter"))]

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;

mod support;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use egress_gateway::{CapabilitySet, MitmConfig, MitmHandle, MitmInterceptor};
use monty_types::{MontyPath, OsFunctionCall};
use policy::{
    EgressPolicyInterceptor, FsResult, GovernedBox, Policy, PolicyEngine, Principal,
    ScriptPolicyInterceptor,
};

use harness::{TlsUpstream, WorkloadClient};

/// The box this suite governs. One box, so one name.
const BOX_NAME: &str = "cross-boundary-script";

/// Permit the transport legs the cross-boundary rule does not govern.
const TRANSPORT: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource);
"#;

/// The reads a Python script needs in order to reach the file at all.
const SCRIPT_ACCESS: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
"#;

/// The cross-boundary rule: no outbound request after Python has read the secret.
///
/// The predicate matches an `fs:read` **resolution**, so it can only fire because a
/// `ScriptPermit` reported that outcome — a denied attempt cannot satisfy it, which is
/// the distinction `policy/CLAUDE.md` records under "Known Limits".
fn no_egress_after_script_read(path: &str) -> String {
    format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
unless temporal {{
    formerly within 300s
    Box::Action::"fs:read"::response{{ input.path: "{path}", input.operation: Box::FsReadOperation::"read_content" }}
}};
"#
    )
}

fn shared_policy(sources: &[&str]) -> Arc<PolicyEngine> {
    Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("cross-boundary-script.dw"),
            text: sources.join("\n"),
        }])
        .expect("policy loads"),
    )
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
    let mut client = WorkloadClient::connect(
        handle.port().expect("a TCP-mode proxy always has a port"),
        host,
        port,
    );
    client.send_request("POST", "/v1/upload", &[], b"payload");
    client.read_status()
}

/// Read `path` through the Script seam, exactly as a Monty broker would.
///
/// Admit, perform the effect **against the resolved path the permit carries**, then
/// record the outcome. The record is what enters history; without it the rule below has
/// nothing to match, which is the failure mode a broker that dropped its permits would
/// have.
fn script_reads(policy: &PolicyEngine, path: &std::path::Path) -> Vec<u8> {
    let interceptor =
        ScriptPolicyInterceptor::new(policy, Principal::agent(), GovernedBox::assigned(BOX_NAME));
    let call = OsFunctionCall::ReadText(MontyPath::new(
        path.to_str().expect("utf-8 path").to_string(),
    ));

    let permit = interceptor.admit(&call).expect("the read is permitted");
    let resolved = permit.path().expect("a filesystem permit carries a path");
    let contents = fs::read(resolved).expect("the file reads");
    permit
        .record(FsResult::Completed)
        .expect("history accepts the outcome");
    contents
}

#[test]
fn a_python_read_closes_egress_in_the_proxy() {
    let host = "api.script-exfil.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();

    let directory = tempfile::tempdir().expect("temp dir");
    let secret = directory.path().join("token");
    fs::write(&secret, "super-secret").expect("fixture writes");
    let secret_path = secret.to_str().expect("utf-8 path").to_string();

    let policy = shared_policy(&[
        TRANSPORT,
        SCRIPT_ACCESS,
        &no_egress_after_script_read(&secret_path),
    ]);
    let handle = proxy_on(&policy, host, &upstream);

    // Egress is open before Python touches the secret.
    assert_eq!(
        request_through(&handle, host, port),
        200,
        "egress is permitted before any script read"
    );

    // The read happens through the Script seam — the only step touching the other
    // boundary, and what records the history the rule reads.
    assert_eq!(
        script_reads(&policy, &secret),
        b"super-secret",
        "the permitted read must reach the file"
    );

    // The same request is now refused — by a Python effect, at the network boundary.
    assert_eq!(
        request_through(&handle, host, port),
        403,
        "egress must close once Python has read the secret"
    );

    assert_eq!(
        upstream.request_count(),
        1,
        "exactly one request reached the network"
    );
}

/// The control that makes the test above mean something.
///
/// Same policy, same boundaries, same sequence — but Python reads a different path, so
/// the predicate does not match and egress stays open. Without this, the denial above
/// could be caused by any script activity rather than by reading that file.
#[test]
fn a_python_read_of_an_unrelated_file_leaves_egress_open() {
    let host = "api.script-control.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();

    let directory = tempfile::tempdir().expect("temp dir");
    let secret = directory.path().join("token");
    let harmless = directory.path().join("notes");
    fs::write(&secret, "super-secret").expect("fixture writes");
    fs::write(&harmless, "harmless").expect("fixture writes");

    let policy = shared_policy(&[
        TRANSPORT,
        SCRIPT_ACCESS,
        &no_egress_after_script_read(secret.to_str().expect("utf-8 path")),
    ]);
    let handle = proxy_on(&policy, host, &upstream);

    assert_eq!(request_through(&handle, host, port), 200);
    assert_eq!(script_reads(&policy, &harmless), b"harmless");
    assert_eq!(
        request_through(&handle, host, port),
        200,
        "an unrelated read must not close egress"
    );
}

/// Python and the Shell write into **one** history, so a rule sees either.
///
/// This is the property that a third `Policy` instance would have destroyed. Asserted with two
/// independent Script interceptors over one policy — the shape a broker and a future
/// second consumer would have — because each interceptor borrows the policy rather than
/// owning it, so nothing about the seam encourages a second instance.
#[test]
fn two_script_boundaries_share_one_history() {
    let directory = tempfile::tempdir().expect("temp dir");
    let secret = directory.path().join("token");
    fs::write(&secret, "super-secret").expect("fixture writes");

    // A budget of one read across the whole box. Two interceptors, one history: the
    // second read must be refused even though *that* interceptor has admitted nothing.
    let budget = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
unless temporal {
    formerly within 300s
    Box::Action::"fs:read"::response{ input.path: _, input.operation: Box::FsReadOperation::"read_content" }
};
"#;
    let policy = shared_policy(&[budget]);

    let call = OsFunctionCall::ReadText(MontyPath::new(
        secret.to_str().expect("utf-8 path").to_string(),
    ));

    let first =
        ScriptPolicyInterceptor::new(&policy, Principal::agent(), GovernedBox::assigned(BOX_NAME));
    let permit = first.admit(&call).expect("the first read is within budget");
    permit
        .record(FsResult::Completed)
        .expect("history accepts the outcome");

    // A *different* interceptor, as a second broker or a second consumer would be.
    let second =
        ScriptPolicyInterceptor::new(&policy, Principal::agent(), GovernedBox::assigned(BOX_NAME));
    assert!(
        second.admit(&call).is_err(),
        "the budget is the box's, not the interceptor's: a second seam must see the \
         first one's history"
    );
}
