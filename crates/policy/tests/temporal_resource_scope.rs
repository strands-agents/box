//! Temporal events use the same fixed identities as authorization requests.

mod support;

use policy::{
    Delivery, GovernedBox, Outcome, Policy, PolicyEngine, PolicyError, Principal, Request,
};

const FIXED_IDENTITY_BUDGET: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);

forbid(
    principal == Box::Agent::"self",
    action == Box::Action::"http:request",
    resource == Box::Resource::"unused"
)
when temporal {
    exists (n: Long). (
        (count for (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"http:request"::response{
                    callerPrincipal: Box::Agent::"self",
                    callerResource: Box::Resource::"unused",
                    input.host: _
                }
                && tp(t)
            )
        )) == n
        && n >= 2
    )
};
"#;

const MISSPELLED_RESERVED_FIELD: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);

forbid(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when temporal {
    formerly within 60s (
        Box::Action::"http:request"::response{
            callerResorce: Box::Resource::"unused",
            input.host: _
        }
    )
};
"#;

fn open(source: &str) -> Result<PolicyEngine, PolicyError> {
    support::open_policy(vec![Policy {
        origin: std::path::PathBuf::from("temporal-resource-scope.dw"),
        text: source.to_string(),
    }])
}

fn request() -> Request<'static> {
    Request::Http {
        host: "api.example.com",
        port: 443,
        method: "POST",
        path: "/v1/upload",
        body_bytes: 60,
        intercepted: true,
    }
}

fn delivered() -> Outcome<'static> {
    Outcome::Http {
        host: "api.example.com",
        port: 443,
        method: "POST",
        path: "/v1/upload",
        delivery: Delivery::Completed { bytes: 60 },
        status: Some(200),
    }
}

#[test]
fn temporal_history_uses_the_fixed_identities() {
    let policy = open(FIXED_IDENTITY_BUDGET).expect("policy opens");

    assert!(
        policy
            .decide(
                &GovernedBox::assigned("codex"),
                &Principal::agent().with_id("worker-1"),
                &request(),
            )
            .is_allow(),
        "a fresh budget must allow"
    );

    policy
        .record(
            &GovernedBox::assigned("codex"),
            &Principal::agent(),
            &delivered(),
        )
        .expect("first outcome records");

    assert!(
        policy
            .decide(
                &GovernedBox::assigned("review"),
                &Principal::agent().with_id("worker-2"),
                &request(),
            )
            .is_allow(),
        "one delivery must remain below the cap"
    );

    policy
        .record(
            &GovernedBox::assigned("review"),
            &Principal::agent().with_id("worker-2"),
            &delivered(),
        )
        .expect("second outcome records");

    assert!(
        !policy
            .decide(
                &GovernedBox::assigned("another-box"),
                &Principal::agent(),
                &request(),
            )
            .is_allow(),
        "all integration metadata must share the fixed Agent and Resource history"
    );
}

#[test]
fn a_misspelled_reserved_field_is_a_load_error() {
    let error = open(MISSPELLED_RESERVED_FIELD);
    assert!(
        matches!(error, Err(PolicyError::Schema(_))),
        "a misspelled callerResource field must fail strict validation: {error:?}"
    );
}
