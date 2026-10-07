//! Black-box checks that a stdio MCP server starts only under a `shell:spawn` permit.

#![cfg(unix)]

use std::time::Duration;

use serde_json::json;

#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/runtime_mcp.rs"]
mod runtime_mcp;

use runtime_mcp::{DiscoveryBehavior, RuntimeMcpBox, Server};

const BOX_STARTUP: Duration = Duration::from_secs(45);
const STARTUP: Duration = Duration::from_secs(8);
const SHUTDOWN: Duration = Duration::from_secs(8);

const BLOCKING_WORKLOAD: &str = r#"
set -eu
: > "$HOME/workload.started"
while [ ! -e "$HOME/release" ]; do :; done
"#;

fn call_policy(servers: &[&str]) -> String {
    servers
        .iter()
        .map(|server| {
            format!(
                r#"permit (principal, action == Box::Action::"mcp:call", resource)
                when {{ context.input.server == "{server}" }};"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn start_permit_for(program: &str) -> String {
    format!(
        r#"@id("start_{program}")
        permit (principal, action == Box::Action::"shell:spawn", resource)
        when {{ context.input.program == "{program}" }};"#
    )
}

fn start_forbid_for(program: &str) -> String {
    format!(
        r#"@id("no_start_{program}")
        forbid (principal, action == Box::Action::"shell:spawn", resource)
        when {{ context.input.program == "{program}" }};"#
    )
}

fn assert_start_refused(box_: &RuntimeMcpBox, program: &str, rule: Option<&str>) {
    let refusal = box_.invoke_refused_open(program, SHUTDOWN);
    assert!(
        !refusal.status.success(),
        "a refused start must fail the open: {}",
        refusal.stderr
    );
    assert!(
        refusal.stderr.contains("may not start"),
        "the refusal must name the start: {}",
        refusal.stderr
    );
    if let Some(rule) = rule {
        assert!(
            refusal.stderr.contains(rule),
            "the refusal must name {rule}: {}",
            refusal.stderr
        );
    }
    assert_eq!(
        box_.invocation_count(program),
        0,
        "a refused server must never run"
    );
}

#[test]
fn absent_start_permit_refuses_the_server_and_it_never_runs() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-start-default-deny");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.write_workspace_as_authored(&call_policy(&["alpha"]), &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    assert_start_refused(&box_, "alpha-mcp", None);
    assert!(run.is_running(), "a refused start must not stop the box");

    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn a_program_permit_starts_its_server() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-start-permit");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    let policy = format!(
        "{}\n{}",
        call_policy(&["alpha"]),
        start_permit_for("alpha-mcp")
    );
    box_.write_workspace_as_authored(&policy, &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    assert_eq!(box_.invocation_count("alpha-mcp"), 1);
    client.initialize_and_activate(json!("initialize-alpha"), STARTUP);
    client.assert_running();

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn a_program_forbid_refuses_only_its_server() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-start-forbid");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    let beta = Server::new("beta", "beta-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.install_server(&beta);
    // The forbid overrides a permit that covers every start.
    box_.write_workspace(
        &format!(
            "{}\n{}",
            call_policy(&["alpha", "beta"]),
            start_forbid_for("alpha-mcp")
        ),
        &[alpha, beta],
        BLOCKING_WORKLOAD,
    );

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    assert_start_refused(&box_, "alpha-mcp", Some("no_start_alpha-mcp"));

    let mut beta_client = box_.open_client("beta-mcp");
    run.wait_for(box_.server_started("beta-mcp"), STARTUP);
    assert_eq!(box_.invocation_count("beta-mcp"), 1);
    beta_client.assert_running();

    drop(beta_client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn a_start_is_decided_on_the_canonical_program_and_its_arguments() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-start-canonical");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    std::os::unix::fs::symlink("alpha-mcp", box_.server_executable("alpha-link"))
        .expect("link the server under a second name");
    // The alias is the link's name, and the link resolves to the installed server.
    let linked = Server::new("alpha", "alpha-link", "read", DiscoveryBehavior::Ready);
    let policy = format!(
        r#"{}
        @id("no_canonical_start")
        forbid (principal, action == Box::Action::"shell:spawn", resource)
        when {{
            context.input.program == "alpha-link" &&
            context.input.program_path like "*/operator-bin/alpha-mcp" &&
            context.input has arg1 && context.input.arg1 == "--declared" &&
            context.input.arg_count == 2
        }};"#,
        call_policy(&["alpha"])
    );
    box_.write_workspace(&policy, &[linked], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    assert_start_refused(&box_, "alpha-link", Some("no_canonical_start"));
    assert_eq!(box_.invocation_count("alpha-mcp"), 0);

    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
    let records = std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
        .expect("read the drained policy telemetry");
    assert!(
        records.lines().any(|line| line.contains("shell:spawn")
            && line.contains("no_canonical_start")
            && line.contains("operator-bin/alpha-mcp")),
        "the refused start is recorded against its canonical program"
    );
}
