//! Every integration box maps to the fixed policy resource.

mod support;

use policy::{GovernedBox, Policy, PolicyEngine, PolicyError, Principal, Request};

const FIXED_RESOURCE: &str = r#"
permit(
    principal == Box::Agent::"self",
    action == Box::Action::"net:connect",
    resource == Box::Resource::"unused"
)
when { context.input.host == "example.com" };
"#;

const UNCONSTRAINED_RESOURCE: &str = r#"
permit(principal, action == Box::Action::"net:connect", resource)
when { context.input.host == "example.com" };
"#;

fn open(source: &str) -> Result<PolicyEngine, PolicyError> {
    support::open_policy(vec![Policy {
        origin: std::path::PathBuf::from("fixed-resource.dw"),
        text: source.to_string(),
    }])
}

fn connect() -> Request<'static> {
    Request::Connect {
        host: "example.com",
        ip: None,
        port: 443,
    }
}

#[test]
fn every_box_maps_to_resource_unused() {
    let policy = open(FIXED_RESOURCE).expect("policy opens");
    let agent = Principal::agent();

    for name in ["codex", "review"] {
        assert!(
            policy
                .decide(&GovernedBox::assigned(name), &agent, &connect())
                .is_allow(),
            "{name} must map to Resource::\"unused\""
        );
    }
}

#[test]
fn an_unconstrained_resource_rule_still_applies() {
    let policy = open(UNCONSTRAINED_RESOURCE).expect("policy opens");
    let agent = Principal::agent();

    for name in ["codex", "review"] {
        assert!(
            policy
                .decide(&GovernedBox::assigned(name), &agent, &connect())
                .is_allow(),
            "a bare resource scope must cover {name}"
        );
    }
}

#[test]
fn the_removed_box_resource_type_is_a_load_error() {
    let result = open(
        r#"permit(principal, action == Box::Action::"net:connect", resource == Box::"codex");"#,
    );
    assert!(
        matches!(result, Err(PolicyError::Schema(_))),
        "the removed Box resource type must fail strict validation: {result:?}"
    );
}
