//! Compiles each Rust example in the README against the real surface.
//!
//! A README that names a method the crate does not have is worse than a stale one: a
//! reader trusts it and the compiler never contradicts them. So every Rust block in
//! `README.md` is copied down here, and the compiler judges the copy.
//!
//! **Read what that does and does not catch.** Nothing extracts the text from
//! `README.md`. Each copy sits inside a `#[test]` wrapper and therefore one extra level
//! of indentation, and is otherwise the README's own code. So this file fails when a
//! copied example names a method the crate no longer has — and it stays green when the
//! README is edited and the copy is not. The two are kept together by hand. Edit both,
//! and add a test here when you add an example there.

#![cfg(feature = "egress-adapter")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use policy::{
    ApprovedPath, Decision, Delivery, EgressPolicyInterceptor, GovernedBox, Outcome, PathRefusal,
    PathResolver, Policy, PolicyEngine, PolicyError, Principal, Request,
};

/// Mint the `ApprovedPath` a `Request::Fs` now demands.
///
/// `PathResolver` is the only public minter. These paths are synthetic, so the resolver
/// runs in the **virtual** namespace and touches no filesystem.
fn approved(path: &str) -> ApprovedPath {
    PathResolver::over([PathBuf::from("/workspace")])
        .expect("the root is absolute")
        .approve_virtual(std::path::Path::new(path))
        .unwrap_or_else(|refusal| panic!("a fixture path must resolve: {refusal}"))
}

#[test]
fn minimal_example() -> Result<(), PolicyError> {
    let history = tempfile::tempdir().expect("history directory");
    fn open_policy(database_path: &Path) -> Result<PolicyEngine, PolicyError> {
        PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("example.cedar"),
                text: r#"
                    permit(
                        principal == Box::Agent::"self",
                        action == Box::Action::"net:connect",
                        resource
                    )
                    when {
                        context.input.host == "api.github.com" &&
                        context.input.port == 443
                    };
                "#
                .to_owned(),
            }],
            database_path,
        )
    }

    let policy = open_policy(&history.path().join("dogwood.redb"))?;
    let decision = policy.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &Request::Connect {
            host: "api.github.com",
            ip: None,
            port: 443,
        },
    );
    assert!(matches!(decision, Decision::Allow { .. }));
    Ok(())
}

#[test]
fn history_example() -> Result<(), PolicyError> {
    fn submit(policy: &PolicyEngine) -> Result<(), PolicyError> {
        policy.record(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Outcome::Http {
                host: "api.github.com",
                port: 443,
                method: "POST",
                path: "/v1/items",
                delivery: Delivery::Completed { bytes: 512 },
                status: Some(200),
            },
        )
    }

    let history = tempfile::tempdir().expect("history directory");
    let policy = PolicyEngine::open(
        vec![Policy {
            origin: PathBuf::from("example.cedar"),
            text:
                r#"permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);"#
                    .to_owned(),
        }],
        &history.path().join("dogwood.redb"),
    )?;
    submit(&policy)
}

/// The README's path-minting example.
///
/// The call runs and its result is discarded on purpose. `approve_host` touches the real
/// filesystem, so what this pins is that the example compiles against the only public
/// minter — not that `/workspace` exists on the host running the suite.
#[test]
fn path_minting_example() {
    fn approve(target: &Path) -> Result<ApprovedPath, PathRefusal> {
        let resolver = PathResolver::over([PathBuf::from("/workspace")])?;
        resolver.approve_host(target)
    }

    let _ = approve(Path::new("/workspace/main.py"));
}

#[test]
fn egress_interceptor_example() {
    fn egress_interceptor(policy: Arc<PolicyEngine>) -> Arc<dyn egress_gateway::EffectInterceptor> {
        EgressPolicyInterceptor::into_handle(
            policy,
            Principal::agent(),
            GovernedBox::assigned("test-box"),
        )
    }

    let history = tempfile::tempdir().expect("history directory");
    let policy = Arc::new(
        PolicyEngine::open(Vec::new(), &history.path().join("dogwood.redb"))
            .expect("an empty policy set loads"),
    );
    let _handle = egress_interceptor(policy);
}

/// A conforming `fs:*` request reaches evaluation and a catch-all permit allows it.
///
/// **This test used to assert the opposite half, and that half is no longer constructible.**
/// It passed an `AgentGateway` principal to an `fs:*` action, which the schema bound to
/// `[AgentShell, AgentScript]`, so the request gate refused it and the verdict was
/// `InternalFault` rather than the catch-all's allow. That was the only non-conformance a
/// caller could build through the public API, and it is what the engine differential
/// originally caught (32 verdicts where the stateless engine denied).
///
/// With one `Agent` principal, every action accepts it, so no principal is out of vocabulary.
/// The gate still runs before evaluation and still denies a non-conforming request — see
/// `to_cedar_request` — but nothing outside this crate can produce one any more. **So the gate
/// is now covered by construction rather than by a test**, which is weaker evidence, and it is
/// recorded here rather than left as an apparent gap.
#[test]
fn a_conforming_request_reaches_a_catch_all_permit() {
    let history = tempfile::tempdir().expect("history directory");
    let policy = PolicyEngine::open(
        vec![Policy {
            origin: PathBuf::from("catch-all.cedar"),
            text: r#"permit(principal, action, resource);"#.to_owned(),
        }],
        &history.path().join("dogwood.redb"),
    )
    .expect("loads");

    let approved = approved("/workspace/main.py");
    let verdict = policy.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &Request::Fs {
            path: &approved,
            operation: policy::FsOperation::ReadContent,
        },
    );
    assert!(
        verdict.is_allow(),
        "the one principal conforms to every action, so the gate passes it through: {verdict:?}"
    );
}

#[test]
fn the_operation_vocabulary_discriminates_within_one_access_verb() {
    // The README claims enumeration and a content read are both `fs:read` and can be
    // told apart by `context.input.operation`. Asserted here so the claim cannot rot.
    let history = tempfile::tempdir().expect("history directory");
    let policy = PolicyEngine::open(
        vec![Policy {
            origin: PathBuf::from("operation.cedar"),
            text: r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
                when { context.input.operation == Box::FsReadOperation::"enumerate" };"#
                .to_owned(),
        }],
        &history.path().join("dogwood.redb"),
    )
    .expect("loads");

    let dir = approved("/workspace");
    assert!(
        policy
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Fs {
                    path: &dir,
                    operation: policy::FsOperation::Enumerate,
                }
            )
            .is_allow(),
        "enumeration is permitted"
    );
    assert!(
        !policy
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Fs {
                    path: &dir,
                    operation: policy::FsOperation::ReadContent,
                }
            )
            .is_allow(),
        "a content read is refused under the same fs:read action"
    );
}
