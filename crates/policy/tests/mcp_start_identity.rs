//! MCP start identity reaches both policy conditions and request history.

mod support;

use policy::{Decision, GovernedBox, Policy, PolicyEngine, Principal, Request};
use std::path::PathBuf;

fn engine(source: &str) -> PolicyEngine {
    support::open_policy(vec![Policy {
        origin: PathBuf::from("mcp-start.dw"),
        text: source.into(),
    }])
    .expect("policy loads")
}

fn spawn(server: Option<&str>) -> Request<'_> {
    Request::ShellSpawn {
        server,
        command: "launcher -y package alpha",
        program: "launcher",
        program_path: "/usr/bin/launcher",
        credential_reads: &[],
        args: &[],
        cwd: "/workspace",
    }
}

fn allows(engine: &PolicyEngine, server: Option<&str>) -> bool {
    matches!(
        engine
            .decide(
                &GovernedBox::assigned("test"),
                &Principal::agent(),
                &spawn(server)
            )
            .0,
        Decision::Allow { .. }
    )
}

#[test]
fn a_server_guard_distinguishes_identical_commands_and_ordinary_spawns() {
    let engine = engine(
        r#"
        permit(principal, action == Box::Action::"shell:spawn", resource)
        when { context.input has server && context.input.server == "alpha" };
    "#,
    );
    assert!(allows(&engine, Some("alpha")));
    assert!(!allows(&engine, Some("beta")));
    assert!(!allows(&engine, None));
}

#[test]
fn an_existing_program_permit_accepts_named_and_ordinary_spawns() {
    let engine = engine(
        r#"
        permit(principal, action == Box::Action::"shell:spawn", resource)
        when { context.input.program == "launcher" };
    "#,
    );
    for server in [None, Some("alpha"), Some("beta")] {
        assert!(allows(&engine, server));
    }
}

#[test]
fn temporal_start_rules_read_the_admitted_server_name() {
    let engine = engine(
        r#"
        permit(principal, action == Box::Action::"shell:spawn", resource)
        when { !(context.input has server) };
        permit(principal, action == Box::Action::"shell:spawn", resource)
        when { context.input has server && context.input.server == "alpha" };
        permit(principal, action == Box::Action::"shell:spawn", resource)
        when { context.input has server && context.input.server == "beta" }
        when temporal {
            formerly within 3600s (
                Box::Action::"shell:spawn"::request { input.server: "alpha" }
            )
        };
    "#,
    );
    for _ in 0..64 {
        assert!(allows(&engine, None));
        assert!(!allows(&engine, Some("beta")));
    }
    assert!(allows(&engine, Some("alpha")));
    for _ in 0..64 {
        assert!(allows(&engine, Some("beta")));
    }
}
