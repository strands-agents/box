//! Black-box checks that a stdio MCP server starts only under its applicable policy action.

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
    run.wait_for_through_alias(box_.server_started("alpha-mcp"), STARTUP);
    assert_eq!(box_.invocation_count("alpha-mcp"), 1);
    client.initialize_and_activate(json!("initialize-alpha"), STARTUP);
    client.assert_running();

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn an_absolute_command_starts_its_selected_symlink_instead_of_a_path_decoy() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-start-absolute");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    let directory = box_.server_executable("selected tools");
    std::fs::create_dir(&directory).expect("create the off-PATH directory");
    let target = directory.join("actual-mcp");
    std::fs::rename(box_.server_executable("alpha-mcp"), &target)
        .expect("move the selected server off PATH");
    let selected = directory.join("alpha-mcp");
    std::os::unix::fs::symlink("actual-mcp", &selected)
        .expect("name the selected server through a symlink");
    box_.install_server(&Server::new(
        "decoy",
        "alpha-mcp",
        "wrong",
        DiscoveryBehavior::Ready,
    ));
    let policy = format!(
        "{}\n{}",
        call_policy(&["alpha"]),
        start_permit_for("alpha-mcp")
    );
    box_.write_workspace_as_authored(&policy, &[alpha], BLOCKING_WORKLOAD);
    box_.set_server_executable("alpha", &selected);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("alpha-mcp");
    let (_, response) = client.initialize_and_activate(json!("initialize-alpha"), STARTUP);
    assert_eq!(answered_as(&response), "alpha");
    assert_eq!(box_.invocation_count("alpha-mcp"), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&box_.trace("alpha-mcp", "argv")).unwrap(),
        json!(["--declared", "alpha"])
    );
    assert_eq!(
        std::path::Path::new(box_.trace("alpha-mcp", "program").trim()),
        directory
            .canonicalize()
            .expect("resolve the selected parent")
            .join("alpha-mcp"),
        "the invoked symlink name survives canonical target authorization"
    );

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn a_missing_absolute_command_never_falls_back_to_path() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-absolute-missing");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.write_workspace(&call_policy(&["alpha"]), &[alpha], BLOCKING_WORKLOAD);
    let missing = box_.server_executable("missing/alpha-mcp");
    box_.set_server_executable("alpha", &missing);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let refusal = box_.invoke_refused_open("alpha-mcp", SHUTDOWN);
    assert!(!refusal.status.success(), "{}", refusal.stderr);
    assert!(
        refusal.stderr.contains(missing.to_str().unwrap()),
        "{}",
        refusal.stderr
    );
    assert_eq!(box_.invocation_count("alpha-mcp"), 0);

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
    run.wait_for_through_alias(box_.server_started("beta-mcp"), STARTUP);
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
    for absolute in [false, true] {
        let box_ = RuntimeMcpBox::new("mcp-start-canonical");
        let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
        box_.install_server(&alpha);
        std::os::unix::fs::symlink("alpha-mcp", box_.server_executable("alpha-link"))
            .expect("link the server under a second name");
        let linked = Server::new("alpha", "alpha-link", "read", DiscoveryBehavior::Ready);
        let policy = format!(
            r#"{}
        @id("no_canonical_start")
        forbid (principal, action == Box::Action::"shell:spawn", resource)
        when {{
            context.input.program == "alpha-link" &&
            context.input.command == "alpha-link --declared alpha" &&
            context.input.program_path like "*/operator-bin/alpha-mcp" &&
            context.input has arg1 && context.input.arg1 == "--declared" &&
            context.input.arg_count == 2
        }};"#,
            call_policy(&["alpha"])
        );
        box_.write_workspace(&policy, &[linked], BLOCKING_WORKLOAD);
        if absolute {
            box_.set_server_executable("alpha", &box_.server_executable("alpha-link"));
        }

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
}

/// One fixture server declared as `env <script> --declared <name>`.
fn through_env<'a>(
    box_: &RuntimeMcpBox,
    name: &'a str,
    script: &'a str,
    tool: &'a str,
) -> Server<'a> {
    let executable = box_.server_executable(script);
    Server::new(name, "env", tool, DiscoveryBehavior::Ready).launched_through(
        script,
        vec![
            executable.to_string_lossy().into_owned(),
            "--declared".to_string(),
            name.to_string(),
        ],
    )
}

/// The arguments a harness passes to `bin/env` to launch `script` as `name`.
fn env_arguments(box_: &RuntimeMcpBox, name: &str, script: &str) -> Vec<String> {
    vec![
        box_.server_executable(script)
            .to_string_lossy()
            .into_owned(),
        "--declared".to_string(),
        name.to_string(),
    ]
}

/// The `serverInfo.name` a server answers `initialize` with.
fn answered_as(response: &serde_json::Value) -> &str {
    response["result"]["serverInfo"]["name"]
        .as_str()
        .unwrap_or_else(|| panic!("an initialize result names its server: {response}"))
}

/// Assert that a launch was refused before any server started, and return its stderr.
fn assert_launch_refused(box_: &RuntimeMcpBox, program: &str, arguments: &[String]) -> String {
    let refusal = box_.invoke_refused_open_with(program, arguments, SHUTDOWN);
    assert!(
        !refusal.status.success(),
        "a launch that matches no declared command must fail: {}",
        refusal.stderr
    );
    refusal.stderr
}

#[test]
fn two_servers_on_one_launcher_each_start_through_their_own_full_command() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-shared-launcher");
    let alpha = through_env(&box_, "alpha", "alpha-mcp", "read");
    let beta = through_env(&box_, "beta", "beta-mcp", "write");
    box_.install_server(&alpha);
    box_.install_server(&beta);
    box_.write_workspace(
        &call_policy(&["alpha", "beta"]),
        &[alpha, beta],
        BLOCKING_WORKLOAD,
    );

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    assert!(
        box_.root().join("bin/env").is_file(),
        "one alias serves both servers"
    );

    let mut clients = Vec::new();
    for (name, script) in [("alpha", "alpha-mcp"), ("beta", "beta-mcp")] {
        let mut client = box_.open_client_with("env", &env_arguments(&box_, name, script));
        run.wait_for_through_alias(box_.server_started(script), STARTUP);
        let (_, response) = client.initialize_and_activate(json!(format!("init-{name}")), STARTUP);
        assert_eq!(
            answered_as(&response),
            name,
            "the launch reaches the server its full command declares"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&box_.trace(script, "argv"))
                .expect("parse the server's arguments"),
            json!(["--declared", name]),
            "the server starts from its own declared command"
        );
        clients.push(client);
    }
    assert_eq!(box_.invocation_count("alpha-mcp"), 1);
    assert_eq!(box_.invocation_count("beta-mcp"), 1);
    for client in &mut clients {
        client.assert_running();
    }

    drop(clients);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn a_launch_matching_no_declared_command_starts_no_server() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-wrong-server");
    let alpha = through_env(&box_, "alpha", "alpha-mcp", "read");
    // Installed for the operator, and declared nowhere in box.toml.
    let beta = through_env(&box_, "beta", "beta-mcp", "write");
    box_.install_server(&alpha);
    box_.install_server(&beta);
    box_.write_workspace(&call_policy(&["alpha"]), &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let launched = env_arguments(&box_, "beta", "beta-mcp");
    let refusal = assert_launch_refused(&box_, "env", &launched);
    assert!(
        refusal.contains(&format!(
            "no MCP server declares \"env {}\"",
            launched.join(" ")
        )),
        "the refusal must name the command it received: {refusal}"
    );
    assert!(
        refusal.contains("; servers on env: alpha"),
        "the refusal must name the servers declared on the program: {refusal}"
    );
    assert!(
        !refusal.contains("alpha-mcp --declared alpha"),
        "the refusal must not print a declared command: {refusal}"
    );
    assert_eq!(
        box_.invocation_count("alpha-mcp"),
        0,
        "no declared server starts in place of the one the harness asked for"
    );
    assert_eq!(box_.invocation_count("beta-mcp"), 0);
    assert!(run.is_running(), "a refused launch must not stop the box");

    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
    let records = std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
        .expect("read the drained policy telemetry");
    assert!(
        records
            .lines()
            .any(|line| line.contains("\"enforcement:mcp-command\"")
                && line.contains("shell:spawn")
                && line.contains("no MCP server declares")
                && line.contains("servers on env: alpha")),
        "the refused launch is recorded beside policy decisions, with the refusal the harness \
         received: {records}"
    );
    assert!(
        !records.contains("alpha-mcp --declared alpha"),
        "the record must not print a declared command: {records}"
    );
}

/// **An `[agent] env` runtime option does not reach a stdio MCP server.**
#[test]
fn an_agent_runtime_option_does_not_reach_an_mcp_server() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let mut box_ = RuntimeMcpBox::new("mcp-agent-runtime-option");
    box_.set_agent_env("NODE_OPTIONS", "--agent-only");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    let workload =
        format!("printf %s \"$NODE_OPTIONS\" > \"$HOME/node-options\"\n{BLOCKING_WORKLOAD}");
    box_.write_workspace(&call_policy(&["alpha"]), &[alpha], &workload);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    assert_eq!(
        std::fs::read_to_string(box_.workload_path("node-options"))
            .expect("read the agent's value"),
        "--agent-only",
        "the agent's own `env` must reach it"
    );
    let mut client = box_.open_client("alpha-mcp");
    run.wait_for_through_alias(box_.server_started("alpha-mcp"), STARTUP);
    client.initialize_and_activate(json!("init"), STARTUP);
    let environment: serde_json::Value =
        serde_json::from_str(&box_.trace("alpha-mcp", "environment"))
            .expect("parse the server's environment");
    assert!(
        environment.get("NODE_OPTIONS").is_none(),
        "the agent's `env` must not reach an MCP server: {environment}"
    );

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn a_launch_by_the_program_name_alone_is_refused() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-program-only");
    // One server on its program, declared with arguments, as `Server::new` declares every server.
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.write_workspace(&call_policy(&["alpha"]), &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let refusal = assert_launch_refused(&box_, "alpha-mcp", &[]);
    assert!(
        refusal.contains("no MCP server declares \"alpha-mcp\"; servers on alpha-mcp: alpha")
            && !refusal.contains("--declared"),
        "a harness that runs only the program is refused, with the server name only: {refusal}"
    );
    assert_eq!(box_.invocation_count("alpha-mcp"), 0);

    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

/// Runs `npx` through the hosted Shell, and records which `npx` the agent's own `PATH` finds.
const SHELL_NPX_THEN_BLOCK: &str = r#"
set -u
command -v npx > "$HOME/npx.path"
zsh -lc "npx jest --ci" > "$HOME/npx.out" 2> "$HOME/npx.err"
printf '%s\n' "$?" > "$HOME/npx.status"
: > "$HOME/workload.started"
while [ ! -e "$HOME/release" ]; do :; done
"#;

#[test]
fn the_shell_resolves_a_launcher_name_on_the_operators_path_and_not_the_mcp_alias() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let mut box_ = RuntimeMcpBox::new("mcp-shell-launcher");
    box_.install_program(
        "npx",
        "#!/bin/bash\nprintf 'OPERATOR_NPX_RAN %s\\n' \"$*\"\n",
    );
    let operator_bin = box_
        .server_executable("npx")
        .parent()
        .expect("the program has a directory")
        .canonicalize()
        .expect("the operator bin resolves");
    let interpreter_grants = if cfg!(target_os = "linux") {
        let bash = std::path::Path::new("/bin/bash")
            .canonicalize()
            .expect("resolve the launcher interpreter");
        format!("read_file = [{bash:?}]\n")
    } else {
        String::new()
    };
    box_.declare_tool(
        "npx",
        &format!(
            "[tool.npx]\ncommand = [\"npx\"]\n[tool.npx.filesystem]\nread = [{:?}]\n{interpreter_grants}",
            operator_bin.display().to_string()
        ),
    );
    // A server on `npx`, which never starts here.
    let playwright = Server::new("playwright", "npx", "read", DiscoveryBehavior::Ready);
    box_.write_workspace(
        &call_policy(&["playwright"]),
        &[playwright],
        SHELL_NPX_THEN_BLOCK,
    );

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let read = |name: &str| {
        std::fs::read_to_string(box_.workload_path(name))
            .unwrap_or_else(|error| panic!("read {name}: {error}"))
    };
    assert_eq!(
        std::path::Path::new(read("npx.path").trim()),
        box_.root().join("bin/npx"),
        "the agent's own PATH finds the MCP alias first"
    );
    assert_eq!(read("npx.status").trim(), "0", "{}", read("npx.err"));
    assert_eq!(
        read("npx.out").trim(),
        "OPERATOR_NPX_RAN jest --ci",
        "the Shell runs the operator's npx, found on the trusted process's PATH"
    );
    assert_eq!(box_.invocation_count("npx"), 0, "no MCP server started");

    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
    let records = std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
        .expect("read the drained policy telemetry");
    assert!(
        records.lines().any(|line| line.contains("shell:spawn")
            && line.contains("operator-bin/npx")
            && line.contains("permit")),
        "the start is decided on the operator's program: {records}"
    );
}

#[test]
fn a_launch_matches_the_declared_command_as_box_expands_it() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-expanded-command");
    let declared = vec![
        "--declared".to_string(),
        "alpha".to_string(),
        "--otlp=${OTEL_EXPORTER_OTLP_PROTOCOL}".to_string(),
    ];
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready)
        .launched_through("alpha-mcp", declared.clone());
    box_.install_server(&alpha);
    box_.write_workspace(&call_policy(&["alpha"]), &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);

    let expanded = ["--declared", "alpha", "--otlp=http/protobuf"];
    let mut client = box_.open_client_with("alpha-mcp", &expanded);
    run.wait_for_through_alias(box_.server_started("alpha-mcp"), STARTUP);
    let (_, response) = client.initialize_and_activate(json!("init"), STARTUP);
    assert_eq!(answered_as(&response), "alpha");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&box_.trace("alpha-mcp", "argv"))
            .expect("parse the server's arguments"),
        json!(expanded),
        "the server starts from the expanded command the harness ran"
    );

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn a_launch_of_the_command_as_written_selects_its_server() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-written-command");
    let declared = vec![
        "--declared".to_string(),
        "alpha".to_string(),
        "--otlp=${OTEL_EXPORTER_OTLP_PROTOCOL}".to_string(),
    ];
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready)
        .launched_through("alpha-mcp", declared.clone());
    box_.install_server(&alpha);
    box_.write_workspace(&call_policy(&["alpha"]), &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let written: Vec<&str> = declared.iter().map(String::as_str).collect();
    let mut client = box_.open_client_with("alpha-mcp", &written);
    run.wait_for_through_alias(box_.server_started("alpha-mcp"), STARTUP);
    let (_, response) = client.initialize_and_activate(json!("init"), STARTUP);
    assert_eq!(answered_as(&response), "alpha");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&box_.trace("alpha-mcp", "argv"))
            .expect("parse the server's arguments"),
        json!(["--declared", "alpha", "--otlp=http/protobuf"]),
        "a launch that spells the token selects the server, and Box starts it expanded"
    );

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn two_servers_whose_commands_expand_to_one_command_are_refused_at_start() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-expanded-duplicate");
    let token = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready)
        .launched_through(
            "alpha-mcp",
            vec!["--otlp=${OTEL_EXPORTER_OTLP_PROTOCOL}".to_string()],
        );
    let literal = Server::new("beta", "alpha-mcp", "write", DiscoveryBehavior::Ready)
        .launched_through("alpha-mcp", vec!["--otlp=http/protobuf".to_string()]);
    box_.install_server(&token);
    box_.write_workspace(
        &call_policy(&["alpha", "beta"]),
        &[token, literal],
        BLOCKING_WORKLOAD,
    );

    box_.release_workload();
    let output = box_.spawn_attempt().wait(SHUTDOWN);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`[mcp.alpha]` and `[mcp.beta]`"),
        "the refusal must name both tables: {stderr}"
    );
    assert!(
        !box_.workload_path("workload.started").exists(),
        "the workload must not start"
    );
}

#[test]
fn a_server_whose_command_does_not_expand_is_named_and_does_not_start() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-unexpandable");
    let declared = vec!["--declared".to_string(), "${NOT_A_BOX_VALUE}".to_string()];
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready)
        .launched_through("alpha-mcp", declared.clone());
    box_.install_server(&alpha);
    box_.write_workspace(&call_policy(&["alpha"]), &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let refusal = assert_launch_refused(&box_, "alpha-mcp", &declared);
    assert!(
        refusal.contains("; servers on alpha-mcp: alpha (its `command` does not expand)"),
        "the refusal must name the server whose command does not expand: {refusal}"
    );
    let refusal = assert_launch_refused(&box_, "alpha-mcp", &["--declared".to_string()]);
    assert!(
        refusal.contains("; servers on alpha-mcp: alpha (its `command` does not expand)"),
        "the refusal must name the server whose command does not expand: {refusal}"
    );
    assert!(
        !refusal.contains("NOT_A_BOX_VALUE"),
        "the refusal must not print a declared argument: {refusal}"
    );
    assert_eq!(box_.invocation_count("alpha-mcp"), 0);

    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn wildcard_slots_launch_received_values_without_expanding_them() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-star-arguments");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready)
        .launched_through(
            "alpha-mcp",
            [
                "--declared",
                "alpha",
                "--token",
                "*",
                "*",
                "--otlp=${OTEL_EXPORTER_OTLP_PROTOCOL}",
            ]
            .map(str::to_string)
            .to_vec(),
        );
    box_.install_server(&alpha);
    box_.write_workspace(&call_policy(&["alpha"]), &[alpha], BLOCKING_WORKLOAD);
    box_.set_argument_wildcards("alpha", true);
    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let received = [
        "--declared",
        "alpha",
        "--token",
        "${RUNTIME_VALUE:-literal}",
        "",
        "--otlp=http/protobuf",
    ];
    let mut wrong = received.map(str::to_string).to_vec();
    wrong[2] = "--password".into();
    assert_launch_refused(&box_, "alpha-mcp", &wrong);
    assert_eq!(box_.invocation_count("alpha-mcp"), 0);
    let mut client = box_.open_client_with("alpha-mcp", &received);
    run.wait_for_through_alias(box_.server_started("alpha-mcp"), STARTUP);
    let (_, response) = client.initialize_and_activate(json!("init"), STARTUP);
    assert_eq!(answered_as(&response), "alpha");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&box_.trace("alpha-mcp", "argv")).unwrap(),
        json!(received),
    );
    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn wildcard_arguments_remain_literal_without_opt_in() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for enabled in [None, Some(false)] {
        let box_ = RuntimeMcpBox::new("mcp-star-disabled");
        let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready)
            .launched_through("alpha-mcp", vec!["*".into()]);
        box_.install_server(&alpha);
        box_.write_workspace(&call_policy(&["alpha"]), &[alpha], BLOCKING_WORKLOAD);
        if let Some(enabled) = enabled {
            box_.set_argument_wildcards("alpha", enabled);
        }
        let mut run = box_.spawn();
        run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
        assert_launch_refused(&box_, "alpha-mcp", &["runtime-value".into()]);
        assert_eq!(box_.invocation_count("alpha-mcp"), 0);
        let mut client = box_.open_client_with("alpha-mcp", &["*"]);
        run.wait_for_through_alias(box_.server_started("alpha-mcp"), STARTUP);
        client.initialize_and_activate(json!("init"), STARTUP);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&box_.trace("alpha-mcp", "argv")).unwrap(),
            json!(["*"]),
        );
        drop(client);
        box_.release_workload();
        let output = run.wait(SHUTDOWN);
        assert!(output.status.success(), "{output:?}");
    }
}

#[test]
fn wildcard_launches_require_policy_to_permit_the_effective_command() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for explicit_forbid in [false, true] {
        let box_ = RuntimeMcpBox::new("mcp-star-policy");
        let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready)
            .launched_through("alpha-mcp", vec!["*".into()]);
        box_.install_server(&alpha);
        let mut policy = call_policy(&["alpha"]);
        if explicit_forbid {
            policy.push_str(&start_permit_for("alpha-mcp"));
            policy.push_str(
                r#"
                forbid (principal, action == Box::Action::"shell:spawn", resource)
                when {
                    context.input has arg1 &&
                    context.input.arg1 == "from-harness" &&
                    context.input.command == "alpha-mcp from-harness"
                };"#,
            );
        }
        box_.write_workspace_as_authored(&policy, &[alpha], BLOCKING_WORKLOAD);
        box_.set_argument_wildcards("alpha", true);
        let mut run = box_.spawn();
        run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
        let refusal = box_.invoke_refused_open_with("alpha-mcp", &["from-harness"], SHUTDOWN);
        assert!(!refusal.status.success());
        assert!(
            refusal.stderr.contains("may not start"),
            "{}",
            refusal.stderr
        );
        assert_eq!(box_.invocation_count("alpha-mcp"), 0);
        box_.release_workload();
        let output = run.wait(SHUTDOWN);
        assert!(output.status.success(), "{output:?}");
    }
}

#[test]
fn exact_and_wildcard_commands_select_their_own_server_configuration() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for exact_value in ["specific", "*"] {
        let box_ = RuntimeMcpBox::new("mcp-star-exact");
        let alpha = Server::new("alpha", "shared-mcp", "read", DiscoveryBehavior::Ready)
            .launched_through("shared-mcp", vec!["*".into()])
            .with_env("SELECTED_SERVER", "wildcard");
        let beta = Server::new("beta", "shared-mcp", "write", DiscoveryBehavior::Ready)
            .launched_through("shared-mcp", vec![exact_value.into()])
            .with_env("SELECTED_SERVER", "exact");
        box_.install_server(&alpha);
        box_.write_workspace(
            &call_policy(&["alpha", "beta"]),
            &[alpha, beta],
            BLOCKING_WORKLOAD,
        );
        box_.set_argument_wildcards("alpha", true);
        let mut run = box_.spawn();
        run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
        for (value, selected) in [("other", "wildcard"), (exact_value, "exact")] {
            let mut client = box_.open_client_with("shared-mcp", &[value]);
            client.initialize_and_activate(json!(selected), STARTUP);
            let environment: serde_json::Value =
                serde_json::from_str(&box_.trace("shared-mcp", "environment")).unwrap();
            assert_eq!(environment["SELECTED_SERVER"], selected);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&box_.trace("shared-mcp", "argv"))
                    .unwrap(),
                json!([value]),
            );
            drop(client);
        }
        assert_eq!(box_.invocation_count("shared-mcp"), 2);
        box_.release_workload();
        let output = run.wait(SHUTDOWN);
        assert!(output.status.success(), "{output:?}");
    }
}

#[test]
fn overlapping_wildcard_commands_are_refused_before_the_workload_starts() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for first in ["http/protobuf", "${OTEL_EXPORTER_OTLP_PROTOCOL}"] {
        let box_ = RuntimeMcpBox::new("mcp-star-overlap");
        let alpha = Server::new("alpha", "shared-mcp", "read", DiscoveryBehavior::Ready)
            .launched_through("shared-mcp", vec![first.into(), "*".into(), "alpha".into()]);
        let beta = Server::new("beta", "shared-mcp", "write", DiscoveryBehavior::Ready)
            .launched_through(
                "shared-mcp",
                vec!["http/protobuf".into(), "beta".into(), "*".into()],
            );
        box_.install_server(&alpha);
        box_.write_workspace(
            &call_policy(&["alpha", "beta"]),
            &[alpha, beta],
            BLOCKING_WORKLOAD,
        );
        box_.set_argument_wildcards("alpha", true);
        box_.set_argument_wildcards("beta", true);
        box_.release_workload();
        let output = box_.spawn_attempt().wait(SHUTDOWN);
        assert!(!output.status.success(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("overlapping wildcard commands"), "{stderr}");
        assert!(
            stderr.contains("[mcp.alpha]") && stderr.contains("[mcp.beta]"),
            "{stderr}"
        );
        assert!(!box_.workload_path("workload.started").exists());
        assert_eq!(box_.invocation_count("shared-mcp"), 0);

        box_.set_argument_wildcards("alpha", false);
        let output = box_.spawn_attempt().wait(SHUTDOWN);
        assert!(output.status.success(), "{output:?}");
        assert!(box_.workload_path("workload.started").exists());
    }
}

#[test]
fn a_late_server_is_refused_until_its_path_reaches_an_approved_program() {
    assert_a_late_server_requires_an_approved_program(false);
}

#[test]
fn a_late_absolute_server_is_refused_until_its_path_reaches_an_approved_program() {
    assert_a_late_server_requires_an_approved_program(true);
}

fn assert_a_late_server_requires_an_approved_program(absolute_command: bool) {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !fixture::namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let mut box_ = RuntimeMcpBox::new("mcp-late-grammar");
    let server_directory = box_.workload_path("server-bin");
    std::fs::create_dir(&server_directory).expect("create the workload's program directory");
    let server_path = server_directory.join("alpha-mcp");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready)
        .launched_through("alpha-mcp", vec!["start".to_string()])
        .with_env("PATH", &server_directory.display().to_string());
    let beta = Server::new("beta", "beta-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.install_server(&beta);
    let approved = box_
        .server_executable("alpha-mcp")
        .canonicalize()
        .expect("the approved program resolves");
    std::fs::copy(&approved, box_.workload_path("payload"))
        .expect("stage the synthetic server source for the workload");
    let chmod = std::path::Path::new("/bin/chmod")
        .canonicalize()
        .expect("resolve chmod");
    let sleep = std::path::Path::new("/bin/sleep")
        .canonicalize()
        .expect("resolve sleep");
    box_.set_agent_env("FIXTURE_CHMOD", &chmod.display().to_string());
    box_.set_agent_env("FIXTURE_SLEEP", &sleep.display().to_string());
    box_.declare_tool(
        "alpha",
        &format!(
            r#"[tool.alpha]
command = [{:?}]
[tool.alpha.grammar]
format = 1
version = 1
name = "alpha"
program = "alpha-mcp"
[tool.alpha.grammar.shell.start]
usage = "alpha-mcp start"
[experimental-features]
tool-grammars = true
"#,
            approved.display().to_string()
        ),
    );
    let policy = format!(
        r#"{}
permit (principal, action == Box::Action::"shell:spawn", resource);
@id("grammar_start")
permit (principal, action == Tool::alpha::Action::"start", resource);
"#,
        call_policy(&["alpha", "beta"])
    );
    let workload = r#"
set -eu
while IFS= read -r line || [ -n "$line" ]; do
    printf '%s\n' "$line"
done < "$HOME/payload" > "$HOME/server-bin/alpha-mcp"
"$FIXTURE_CHMOD" 700 "$HOME/server-bin/alpha-mcp"
: > "$HOME/workload.started"
set +e
{
    printf '%s\n' '{"jsonrpc":"2.0","id":"first","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"late-server-test","version":"1"}}}'
    "$FIXTURE_SLEEP" 2
} | alpha-mcp start > "$HOME/first.out" 2> "$HOME/first.err"
printf '%s\n' "$?" > "$HOME/first.status"
set -e
printf 'CONTINUED\n' > "$HOME/continued"
: > "$HOME/first.done"
while [ ! -e "$HOME/release" ]; do :; done
"#;
    box_.write_workspace_as_authored(&policy, &[alpha, beta], workload);
    let config_path = box_.operator_home().join("workspace/.strands-box/box.toml");
    let mut config: toml::Value =
        toml::from_str(&std::fs::read_to_string(&config_path).expect("read the authored config"))
            .expect("parse the authored config");
    if absolute_command {
        config["mcp"]["alpha"]["command"][0] =
            toml::Value::String(server_path.display().to_string());
    }
    config["agent"]["filesystem"]
        .as_table_mut()
        .expect("the agent has filesystem grants")
        .insert(
            "exec".to_string(),
            toml::Value::Array(
                [&chmod, &sleep]
                    .into_iter()
                    .map(|path| toml::Value::String(path.display().to_string()))
                    .collect(),
            ),
        );
    config["mcp"]["alpha"]["filesystem"]["read"]
        .as_array_mut()
        .expect("the server has a read list")
        .push(toml::Value::String(server_directory.display().to_string()));
    let server_filesystem = config["mcp"]["alpha"]["filesystem"].clone();
    config["tool"]["alpha"]
        .as_table_mut()
        .expect("the tool has a configuration table")
        .insert("filesystem".to_string(), server_filesystem);
    std::fs::write(
        config_path,
        toml::to_string(&config).expect("serialize the fixture grants"),
    )
    .expect("write the fixture grants");
    assert!(
        !server_path.exists(),
        "the server is absent before Box starts"
    );

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    run.wait_for_through_alias(box_.workload_path("first.done"), STARTUP);
    let first_error = std::fs::read_to_string(box_.workload_path("first.err"))
        .expect("read the contained workload's first refusal");
    assert!(
        first_error.contains("tool grammar requires an approved program file"),
        "the later executable must be refused despite both permits: {first_error}"
    );
    assert_eq!(
        std::fs::read_to_string(box_.workload_path("first.status"))
            .expect("read the first alias status")
            .trim(),
        "125",
        "the alias reports a refused start"
    );
    let late = std::fs::metadata(&server_path).expect("the workload created its server");
    let bound = std::fs::metadata(&approved).expect("the approved server still exists");
    assert_ne!(
        (late.dev(), late.ino()),
        (bound.dev(), bound.ino()),
        "the workload created a different program file"
    );
    assert_ne!(
        late.permissions().mode() & 0o111,
        0,
        "the new file is executable"
    );
    assert_eq!(box_.invocation_count("alpha-mcp"), 0);
    assert!(!box_.server_started("alpha-mcp").exists());
    assert_eq!(
        std::fs::read_to_string(box_.workload_path("continued"))
            .expect("the workload continues after the refusal"),
        "CONTINUED\n"
    );
    assert!(
        run.is_running(),
        "the refusal must leave the same Box running"
    );

    let mut beta_client = box_.open_client("beta-mcp");
    run.wait_for_through_alias(box_.server_started("beta-mcp"), STARTUP);
    let (_, beta_response) = beta_client.initialize_and_activate(json!("beta"), STARTUP);
    assert_eq!(answered_as(&beta_response), "beta");
    assert_eq!(box_.invocation_count("beta-mcp"), 1);

    // The trusted test host changes the path after observing the contained workload's refusal.
    let replacement = server_path.with_extension("approved");
    std::os::unix::fs::symlink(&approved, &replacement)
        .expect("name the program file Box approved at startup");
    std::fs::rename(replacement, &server_path)
        .expect("replace the late file with the approved link");
    let mut retry = box_.open_client("alpha-mcp");
    run.wait_for_through_alias(box_.server_started("alpha-mcp"), STARTUP);
    let (_, response) = retry.initialize_and_activate(json!("retry"), STARTUP);
    assert_eq!(answered_as(&response), "alpha");
    assert_eq!(box_.invocation_count("alpha-mcp"), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&box_.trace("alpha-mcp", "argv"))
            .expect("read the permitted server arguments"),
        json!(["start"])
    );
    assert!(run.is_running(), "the retry uses the original Box run");
    retry.assert_running();
    beta_client.assert_running();

    drop(retry);
    drop(beta_client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
    let records = std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
        .expect("read the drained policy telemetry");
    let mut grammar_start_recorded = false;
    for line in records.lines() {
        let batch: serde_json::Value = serde_json::from_str(line).expect("parse telemetry batch");
        for resource in batch["resourceLogs"].as_array().into_iter().flatten() {
            for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                for entry in scope["logRecords"].as_array().into_iter().flatten() {
                    let value = |key: &str| {
                        entry["attributes"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|attribute| attribute["key"] == key)
                            .and_then(|attribute| attribute["value"]["stringValue"].as_str())
                    };
                    grammar_start_recorded |= value("strands.box.policy.category")
                        == Some("Tool::alpha")
                        && value("strands.box.policy.action") == Some("start")
                        && value("strands.box.policy.verdict") == Some("permit")
                        && value("strands.box.policy.rule") == Some("grammar_start");
                }
            }
        }
    }
    assert!(
        grammar_start_recorded,
        "the approved retry must use its grammar permit: {records}"
    );
}
