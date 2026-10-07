//! Black-box checks for lazy runtime MCP policy staging through live MCP alias processes.

#![cfg(unix)]

use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/runtime_mcp.rs"]
mod runtime_mcp;

use runtime_mcp::{
    DiscoveryBehavior, RunningMcpClient, RuntimeMcpBox, Server, wait_for_process_exit,
};

const BOX_STARTUP: Duration = Duration::from_secs(45);
const STARTUP: Duration = Duration::from_secs(8);
const SHUTDOWN: Duration = Duration::from_secs(8);
const CATALOG_TIMEOUT: Duration = Duration::from_secs(20);
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(35);

const BLOCKING_WORKLOAD: &str = r#"
set -eu
: > "$HOME/workload.started"
while [ ! -e "$HOME/release" ]; do :; done
"#;

fn policy_for(server: &str, tool: &str) -> String {
    let namespace = server
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!(
        r#"permit (principal, action == Box::Action::"mcp:call", resource)
        when {{ context.input.server == "{server}" }};

        permit (
            principal,
            action == {namespace}::Action::"{tool}",
            resource
        );"#
    )
}

fn mcp_call_policy_for(server: &str) -> String {
    format!(
        r#"permit (principal, action == Box::Action::"mcp:call", resource)
        when {{ context.input.server == "{server}" }};"#
    )
}

fn mcp_call_policy_for_servers(servers: &[Server<'_>]) -> String {
    servers
        .iter()
        .map(|server| mcp_call_policy_for(server.name))
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_initialize_response(response: &Value, server: &str, id: &Value) {
    assert_eq!(
        response,
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": true}},
                "serverInfo": {"name": server, "version": "fixture-1"},
                "fixtureExtension": {"preserved": true}
            },
            "fixtureTopLevel": "preserved"
        }),
        "the initialize response must pass through unchanged"
    );
}

fn assert_list_page(response: &Value, id: &Value, tool: &str, page: usize) {
    assert_eq!(
        response.get("id"),
        Some(id),
        "the client id must be restored"
    );
    assert_eq!(
        response.pointer("/result/tools/0/name"),
        Some(&Value::String(tool.to_string()))
    );
    assert_eq!(
        response.pointer("/result/tools/0/fixtureField"),
        Some(&Value::String(format!("tool-{page}"))),
        "the cached tool must preserve extension fields"
    );
    assert_eq!(
        response.pointer("/result/fixturePageField"),
        Some(&Value::String(format!("page-{page}"))),
        "the cached result must preserve extension fields"
    );
    assert_eq!(
        response.get("fixtureResponseField"),
        Some(&Value::String(format!("response-{page}"))),
        "the cached response must preserve extension fields"
    );
}

fn assert_list_response(response: &Value, id: &Value, tool: &str) {
    assert_list_page(response, id, tool, 0);
}

fn error_code(response: &Value) -> Option<i64> {
    response.pointer("/error/code").and_then(Value::as_i64)
}

fn assert_follower_joined(client: &mut RunningMcpClient, response_id: Value, barrier_id: Value) {
    client.request_root_list(response_id);
    let barrier = client.call(barrier_id.clone(), "not-in-catalog", STARTUP);
    assert_eq!(barrier.get("id"), Some(&barrier_id), "{barrier}");
    assert_eq!(
        error_code(&barrier),
        Some(-32003),
        "the catalog refusal must arrive after the follower root request joined"
    );
}

#[derive(Debug, PartialEq, Eq)]
struct ObservedPolicyDecision {
    action: String,
    rule: String,
    verdict: String,
}

/// Every decision the box recorded, including the `shell:spawn` records
/// [`observed_policy_decisions`] drops.
#[derive(Debug, PartialEq, Eq)]
struct PolicyRecord {
    action: String,
    rule: String,
    verdict: String,
    resource: String,
}

fn observed_policy_decisions(path: &Path) -> Vec<ObservedPolicyDecision> {
    policy_records(path)
        .into_iter()
        // The server start is decided once per start and is pinned in `runtime_mcp_start`.
        .filter(|record| record.action != "shell:spawn")
        .map(|record| ObservedPolicyDecision {
            action: record.action,
            rule: record.rule,
            verdict: record.verdict,
        })
        .collect()
}

fn policy_records(path: &Path) -> Vec<PolicyRecord> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|error| {
        panic!(
            "read policy decision records at {}: {error}",
            path.display()
        )
    });
    let mut records = Vec::new();
    for line in text.lines() {
        let request: Value =
            serde_json::from_str(line).expect("a telemetry line is one OTLP request");
        if request.get("resourceSpans").is_some() {
            continue;
        }
        let resources = request["resourceLogs"]
            .as_array()
            .expect("the OTLP request has resource logs");
        for resource in resources {
            for scope in resource["scopeLogs"]
                .as_array()
                .expect("the resource has scope logs")
            {
                // The control plane shares this destination and carries no verdict.
                if scope["scope"]["name"] != "strands-box.policy" {
                    continue;
                }
                for record in scope["logRecords"]
                    .as_array()
                    .expect("the scope has log records")
                {
                    let attributes = record["attributes"]
                        .as_array()
                        .expect("the policy record has attributes");
                    let value = |key: &str| {
                        attributes
                            .iter()
                            .find(|attribute| attribute["key"] == key)
                            .and_then(|attribute| attribute["value"]["stringValue"].as_str())
                            .unwrap_or_else(|| panic!("the policy record has {key}"))
                            .to_string()
                    };
                    records.push(PolicyRecord {
                        action: value("strands.box.policy.action"),
                        rule: value("strands.box.policy.rule"),
                        verdict: value("strands.box.policy.verdict"),
                        resource: value("strands.box.policy.resource"),
                    });
                }
            }
        }
    }
    records
}

fn records_path(box_: &RuntimeMcpBox) -> std::path::PathBuf {
    box_.root()
        .join("private")
        .join("telemetry")
        .join("records.jsonl")
}

fn telemetry_attribute<'a>(record: &'a Value, key: &str) -> Option<&'a Value> {
    let matches = record["attributes"]
        .as_array()
        .expect("the telemetry record has attributes")
        .iter()
        .filter(|attribute| attribute["key"] == key)
        .collect::<Vec<_>>();
    assert!(matches.len() <= 1, "duplicate {key}: {record}");
    matches.first().map(|attribute| &attribute["value"])
}

fn telemetry_text<'a>(record: &'a Value, key: &str) -> Option<&'a str> {
    telemetry_attribute(record, key).and_then(|value| value["stringValue"].as_str())
}

fn assert_telemetry_id(value: &Value, length: usize) {
    let id = value.as_str().expect("an OTLP identifier is hexadecimal");
    assert_eq!(id.len(), length, "{id}");
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()), "{id}");
    assert!(id.bytes().any(|byte| byte != b'0'), "{id}");
}

fn observed_linked_policy_spans(box_: &RuntimeMcpBox) -> Vec<Value> {
    let stored: toml::Value = toml::from_str(
        &std::fs::read_to_string(box_.stored_record()).expect("read the trusted box record"),
    )
    .expect("parse the trusted box record");
    let box_id = stored["box_id"]
        .as_str()
        .expect("the stored box has an identity");
    let text = std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
        .expect("read the drained policy telemetry");
    assert!(!text.contains("fixture-private-argument"));
    assert!(!text.contains("fixture-private-metadata"));
    assert!(!text.contains("forged-tool"));
    let mut logs = Vec::new();
    let mut spans = Vec::new();
    let mut provenance = None;
    for line in text.lines() {
        let request: Value =
            serde_json::from_str(line).expect("a telemetry line is one OTLP request");
        for (resource_key, scope_key, record_key, records) in [
            ("resourceLogs", "scopeLogs", "logRecords", &mut logs),
            ("resourceSpans", "scopeSpans", "spans", &mut spans),
        ] {
            let Some(resources) = request.get(resource_key) else {
                continue;
            };
            for resource in resources
                .as_array()
                .expect("the OTLP resources are an array")
            {
                for scope in resource[scope_key]
                    .as_array()
                    .expect("the resource has scopes")
                {
                    if scope["scope"]["name"] != "strands-box.policy" {
                        continue;
                    }
                    let source = &resource["resource"];
                    assert_eq!(telemetry_text(source, "service.name"), Some("strands-box"));
                    assert_eq!(telemetry_text(source, "strands.box.source"), Some("box"));
                    assert_eq!(telemetry_text(source, "strands.box.name"), Some(box_id));
                    assert_telemetry_id(
                        &telemetry_attribute(source, "strands.box.run.id")
                            .expect("the box stamps its run identity")["stringValue"],
                        32,
                    );
                    if let Some(expected) = &provenance {
                        assert_eq!(
                            source, expected,
                            "logs and spans retain the same provenance"
                        );
                    } else {
                        provenance = Some(source.clone());
                    }
                    records.extend(
                        scope[record_key]
                            .as_array()
                            .expect("the policy scope has records")
                            .iter()
                            .filter(|record| {
                                telemetry_text(record, "strands.box.policy.action")
                                    != Some("shell:spawn")
                            })
                            .cloned(),
                    );
                }
            }
        }
    }
    assert!(
        !logs.is_empty(),
        "the live MCP exchange must record decisions"
    );
    assert_eq!(logs.len(), spans.len(), "each policy log has one span");
    let mut span_ids = std::collections::BTreeSet::new();
    for span in &spans {
        assert_telemetry_id(&span["traceId"], 32);
        assert_telemetry_id(&span["spanId"], 16);
        assert!(span_ids.insert(span["spanId"].as_str().unwrap()));
        let matching = logs
            .iter()
            .filter(|log| log["traceId"] == span["traceId"] && log["spanId"] == span["spanId"])
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "the span must link exactly one log: {span}"
        );
        let log = matching[0];
        // The span omits only what one of its own fields already states, so the log record's set is
        // the span's set plus that key. Everything else must agree exactly.
        let omitted = ["strands.box.trace.parent_span_id"];
        let kept = |record: &Value| {
            record["attributes"]
                .as_array()
                .expect("attributes")
                .iter()
                .filter(|attribute| {
                    !omitted.contains(&attribute["key"].as_str().unwrap_or_default())
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            kept(span),
            kept(log),
            "a span and its log record describe one decision: {span}"
        );
        for key in omitted {
            assert_eq!(
                telemetry_attribute(span, key),
                None,
                "a span field already states {key}: {span}"
            );
        }
        assert_eq!(span["kind"], 1, "a policy decision is an INTERNAL span");
        assert_eq!(span["startTimeUnixNano"], log["timeUnixNano"]);
        assert_eq!(span["startTimeUnixNano"], span["endTimeUnixNano"]);
        assert!(
            span["startTimeUnixNano"]
                .as_str()
                .and_then(|time| time.parse::<u64>().ok())
                .is_some_and(|time| time > 0)
        );
        assert_eq!(
            span["flags"].as_u64().expect("span flags") & 0xff,
            log["flags"].as_u64().expect("log trace flags")
        );
        assert!(
            span["status"].is_null() || span["status"]["code"] == 0,
            "an authored denial is not an evaluation fault: {span}"
        );
    }
    spans
}

/// One decision span, selected by its JSON-RPC identifier and, where two requests share one, by the
/// trace the caller expects.
fn mcp_policy_span<'a>(spans: &'a [Value], request_id: &str, trace_id: Option<&str>) -> &'a Value {
    let matching = spans
        .iter()
        .filter(|span| {
            telemetry_text(span, "jsonrpc.request.id") == Some(request_id)
                && trace_id.is_none_or(|trace| span["traceId"] == trace)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "one decision for {request_id}/{trace_id:?}: {spans:?}"
    );
    let span = matching[0];
    for removed in [
        "gen_ai.conversation.id",
        "gen_ai.tool.call.id",
        "gen_ai.tool.name",
        "mcp.method.name",
        "security_rule.uuid",
        "strands.box.policy.determining.tokens",
        "strands.box.trace.correlation",
        "strands.box.trace.link_traceparent",
    ] {
        assert_eq!(
            telemetry_attribute(span, removed),
            None,
            "{removed} was removed: {span}"
        );
    }
    assert_eq!(
        telemetry_text(span, "strands.box.policy.resource"),
        Some("alpha/read")
    );
    span
}

/// `category` is the action's own namespace for a box action, and the declaring namespace for a
/// per-tool action, which has none of its own.
fn assert_mcp_policy(span: &Value, action: &str, category: &str, verdict: &str, policy_id: &str) {
    assert_eq!(
        telemetry_text(span, "strands.box.policy.action"),
        Some(action)
    );
    assert_eq!(
        telemetry_text(span, "strands.box.policy.verdict"),
        Some(verdict)
    );
    assert_eq!(
        telemetry_text(span, "strands.box.policy.cause"),
        Some(if verdict == "permit" {
            "permitted"
        } else {
            "forbidden"
        })
    );
    assert_eq!(span["name"], format!("policy {action}"));
    // The governing rule is the authored `@id` when one exists, so this names the policy itself.
    assert_eq!(
        telemetry_text(span, "strands.box.policy.rule"),
        Some(policy_id)
    );
    assert_eq!(
        telemetry_text(span, "strands.box.policy.category"),
        Some(category)
    );
    assert_eq!(
        telemetry_attribute(span, "strands.box.policy.determining.ids"),
        Some(&json!({"arrayValue": {"values": [{"stringValue": policy_id}]}}))
    );
}

/// Every control-plane operation in `path`, as `(operation, subject)`.
///
/// The control plane shares the destination with the decisions, under its own scope.
fn observed_control_operations(path: &Path) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read control records at {}: {error}", path.display()));
    let mut operations = Vec::new();
    for line in text.lines() {
        let request: Value =
            serde_json::from_str(line).expect("a telemetry line is one OTLP request");
        let Some(resources) = request["resourceLogs"].as_array() else {
            continue;
        };
        for resource in resources {
            for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                if scope["scope"]["name"] != "strands-box.control" {
                    continue;
                }
                for record in scope["logRecords"].as_array().into_iter().flatten() {
                    let value = |key: &str| {
                        record["attributes"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|attribute| attribute["key"] == key)
                            .and_then(|attribute| attribute["value"]["stringValue"].as_str())
                            .unwrap_or_default()
                            .to_string()
                    };
                    operations.push((
                        value("strands.box.control.operation"),
                        value("strands.box.control.subject"),
                    ));
                }
            }
        }
    }
    operations
}

fn authority_after_discovery_order(name: &str, beta_first: bool) -> (Value, Value) {
    let box_ = RuntimeMcpBox::new(name);
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    let beta = Server::new("beta", "beta-mcp", "write", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.install_server(&beta);
    let policy = format!(
        "{}\n{}",
        policy_for("alpha", "read"),
        policy_for("beta", "write")
    );
    box_.write_workspace(&policy, &[alpha, beta], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut alpha_client = box_.open_client("alpha-mcp");
    let mut beta_client = box_.open_client("beta-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    run.wait_for(box_.server_started("beta-mcp"), STARTUP);
    alpha_client.initialize_and_activate(json!("alpha-initialize"), STARTUP);
    beta_client.initialize_and_activate(json!("beta-initialize"), STARTUP);

    if beta_first {
        let beta = beta_client.list_root(json!("beta-list"), STARTUP);
        assert_list_response(&beta, &json!("beta-list"), "write");
        let alpha = alpha_client.list_root(json!("alpha-list"), STARTUP);
        assert_list_response(&alpha, &json!("alpha-list"), "read");
    } else {
        let alpha = alpha_client.list_root(json!("alpha-list"), STARTUP);
        assert_list_response(&alpha, &json!("alpha-list"), "read");
        let beta = beta_client.list_root(json!("beta-list"), STARTUP);
        assert_list_response(&beta, &json!("beta-list"), "write");
    }

    let mut alpha_result = alpha_client.call(json!("alpha-call"), "read", STARTUP);
    let mut beta_result = beta_client.call(json!("beta-call"), "write", STARTUP);
    assert!(alpha_result.get("result").is_some(), "{alpha_result}");
    assert!(beta_result.get("result").is_some(), "{beta_result}");
    alpha_result
        .as_object_mut()
        .expect("the Alpha response is an object")
        .remove("id");
    beta_result
        .as_object_mut()
        .expect("the Beta response is an object")
        .remove("id");
    assert_eq!(box_.call_count("alpha-mcp"), 1);
    assert_eq!(box_.call_count("beta-mcp"), 1);
    assert_eq!(box_.list_count("alpha-mcp"), 1);
    assert_eq!(box_.list_count("beta-mcp"), 1);

    drop(alpha_client);
    drop(beta_client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the discovery-order run must finish normally: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (alpha_result, beta_result)
}

#[test]
fn open_starts_only_the_selected_server_and_initialize_does_not_discover() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-lazy-open");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    let unused = Server::new("unused", "unused-mcp", "other", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.install_server(&unused);
    box_.write_workspace(
        &policy_for("alpha", "read"),
        &[alpha, unused],
        BLOCKING_WORKLOAD,
    );

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    run.wait_for(box_.live_record(), STARTUP);
    assert_eq!(
        box_.invocation_count("alpha-mcp"),
        0,
        "run must not start a process for schema discovery"
    );
    assert_eq!(
        box_.invocation_count("unused-mcp"),
        0,
        "an unopened declaration must start no process"
    );

    let mut alpha_client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    assert_eq!(box_.invocation_count("alpha-mcp"), 1);
    assert_eq!(
        box_.list_count("alpha-mcp"),
        0,
        "Open must start the process before discovery"
    );

    let initialize_id = json!("initialize-alpha");
    let (request, response) = alpha_client.initialize_and_activate(initialize_id.clone(), STARTUP);
    run.wait_for(box_.server_initialized("alpha-mcp"), STARTUP);
    assert_initialize_response(&response, "alpha", &initialize_id);
    assert_eq!(
        box_.received_frames("alpha-mcp", "initialize"),
        vec![request],
        "the initialize request must pass through unchanged"
    );
    assert_eq!(
        box_.list_count("alpha-mcp"),
        0,
        "initialization without a root list must generate no schema"
    );
    assert_eq!(box_.invocation_count("unused-mcp"), 0);
    alpha_client.assert_running();

    let alpha_pid = box_.server_pid("alpha-mcp");
    drop(alpha_client);
    wait_for_process_exit(alpha_pid, SHUTDOWN);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "normal teardown after initialization must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tool_call_before_root_list_returns_an_error_without_starting_discovery() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-call-before-list");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.write_workspace(&policy_for("alpha", "read"), &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    client.initialize_and_activate(json!(1), STARTUP);
    run.wait_for(box_.server_initialized("alpha-mcp"), STARTUP);

    let response = client.call(json!(2), "read", STARTUP);
    assert_eq!(
        error_code(&response),
        Some(-32003),
        "the catalog guard must return a JSON-RPC refusal"
    );
    assert_eq!(
        box_.list_count("alpha-mcp"),
        0,
        "a tool call must not claim discovery"
    );
    assert_eq!(
        box_.call_count("alpha-mcp"),
        0,
        "a pre-catalog tool call must not reach the server"
    );

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the refused call must not fail the run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn an_absent_catalog_tool_reaches_neither_policy_observer_nor_server() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-absent-tool");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.write_workspace(&policy_for("alpha", "read"), &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    client.initialize_and_activate(json!(1), STARTUP);
    let list = client.list_root(json!(2), STARTUP);
    assert_list_response(&list, &json!(2), "read");

    let absent = client.call(json!(3), "absent", STARTUP);
    assert_eq!(error_code(&absent), Some(-32003), "{absent}");
    assert_eq!(
        box_.call_count("alpha-mcp"),
        0,
        "an absent catalog tool must not reach the MCP server"
    );

    let present = client.call(json!(4), "read", STARTUP);
    assert!(present.get("result").is_some(), "{present}");
    assert_eq!(
        box_.call_count("alpha-mcp"),
        1,
        "the accepted tool must prove the server counter can advance"
    );

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the catalog refusal must not fail the run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decisions = observed_policy_decisions(
        &box_
            .root()
            .join("private")
            .join("telemetry")
            .join("records.jsonl"),
    );
    assert_eq!(
        decisions
            .iter()
            .map(|decision| decision.action.as_str())
            .collect::<Vec<_>>(),
        ["mcp:call", "mcp:call", "read"]
    );
    assert!(
        decisions[0].rule.starts_with("policy_"),
        "the staging list must record its authored permit, not a bootstrap bypass: {}",
        decisions[0].rule
    );
    assert_eq!(decisions[0].verdict, "permit");
    assert_eq!(
        decisions[1],
        ObservedPolicyDecision {
            action: "mcp:call".to_string(),
            rule: "enforcement:mcp-catalog".to_string(),
            verdict: "deny".to_string(),
        },
        "the absent tool must record the catalog denial instead of the policy candidate"
    );
}

#[test]
fn a_policy_denied_list_reaches_neither_discovery_nor_the_server() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-denied-list");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.write_workspace("", &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    client.initialize_and_activate(json!(1), STARTUP);

    let refusal = client.list_root(json!(2), STARTUP);
    assert_eq!(error_code(&refusal), Some(-32001), "{refusal}");
    assert_eq!(
        box_.list_count("alpha-mcp"),
        0,
        "a policy-denied list must not reach the MCP server"
    );

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the denied list must not fail the run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decisions = observed_policy_decisions(
        &box_
            .root()
            .join("private")
            .join("telemetry")
            .join("records.jsonl"),
    );
    assert_eq!(
        decisions
            .iter()
            .map(|decision| decision.action.as_str())
            .collect::<Vec<_>>(),
        ["mcp:call"],
        "the denied list must raise only the coarse policy decision"
    );
    assert_eq!(decisions[0].verdict, "deny");
}

/// Runs `git status` through the hosted Shell before it reports started, so the refusal is on
/// disk when the MCP exchange begins.
const GIT_STATUS_THEN_BLOCK: &str = r#"
set -u
zsh -lc "git status" > "$HOME/git.out" 2> "$HOME/git.err"
printf '%s\n' "$?" > "$HOME/git.status"
: > "$HOME/workload.started"
while [ ! -e "$HOME/release" ]; do :; done
"#;

#[test]
fn a_shell_spawn_forbid_on_git_refuses_the_binary_and_leaves_the_git_servers_tool_call_permitted() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let mut box_ = RuntimeMcpBox::new("mcp-git-two-paths");
    let git = Server::new("git", "git-mcp", "status", DiscoveryBehavior::Ready);
    box_.install_server(&git);
    box_.install_program("git", "#!/bin/bash\nprintf 'GIT_BINARY_RAN\\n'\n");
    box_.declare_tool("git", "[tool.git]\ncommand = [\"git\"]\n");
    let policy = format!(
        "@id(\"no_git_binary\")\n\
         forbid (principal, action == Box::Action::\"shell:spawn\", resource)\n\
         when {{ context.input.program == \"git\" }};\n{}",
        mcp_call_policy_for("git")
    );
    box_.write_workspace(&policy, &[git], GIT_STATUS_THEN_BLOCK);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let status = std::fs::read_to_string(box_.workload_path("git.status"))
        .expect("the workload reports the git status");
    let refusal = std::fs::read_to_string(box_.workload_path("git.err"))
        .expect("the workload captures the git stderr");
    let printed = std::fs::read_to_string(box_.workload_path("git.out"))
        .expect("the workload captures the git stdout");
    assert_eq!(
        status.trim(),
        "126",
        "the git binary must be refused by policy: {refusal}"
    );
    assert!(
        refusal.contains("denied") && refusal.contains("no_git_binary"),
        "the refusal must name the shell:spawn forbid: {refusal}"
    );
    assert!(
        !printed.contains("GIT_BINARY_RAN"),
        "a refused binary must not run: {printed}"
    );

    let mut client = box_.open_client("git-mcp");
    run.wait_for(box_.server_started("git-mcp"), STARTUP);
    client.initialize_and_activate(json!(1), STARTUP);
    let list = client.list_root(json!(2), STARTUP);
    assert_list_response(&list, &json!(2), "status");
    let called = client.call(json!(3), "status", STARTUP);
    assert!(
        called.get("result").is_some(),
        "the git server's tool call must be permitted while the git binary is forbidden: {called}"
    );
    assert_eq!(box_.call_count("git-mcp"), 1);

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the two-path run must finish normally: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let records = policy_records(&records_path(&box_));
    let spawn_denials = records
        .iter()
        .filter(|record| record.action == "shell:spawn" && record.verdict == "deny")
        .collect::<Vec<_>>();
    assert_eq!(spawn_denials.len(), 1, "one spawn denial: {records:?}");
    assert_eq!(spawn_denials[0].rule, "no_git_binary");
    assert!(
        spawn_denials[0].resource.ends_with("/operator-bin/git"),
        "the denial names the refused binary: {:?}",
        spawn_denials[0]
    );
    let call_records = records
        .iter()
        .filter(|record| record.resource == "git/status")
        .collect::<Vec<_>>();
    assert_eq!(
        call_records.len(),
        1,
        "one record for the tool call: {records:?}"
    );
    assert_eq!(call_records[0].action, "mcp:call", "{:?}", call_records[0]);
    assert_eq!(call_records[0].verdict, "permit", "{:?}", call_records[0]);
    assert!(
        call_records[0].rule.starts_with("policy_"),
        "the permit is the authored rule, not a bypass: {:?}",
        call_records[0]
    );
    assert!(
        records
            .iter()
            .all(|record| !(record.action == "mcp:call" && record.verdict == "deny")),
        "the binary's forbid must not leak into the MCP path: {records:?}"
    );
    assert!(
        records.iter().all(|record| {
            !(record.action == "shell:spawn"
                && record.verdict == "permit"
                && record.resource.ends_with("/operator-bin/git"))
        }),
        "the server's permit must not leak into the binary path: {records:?}"
    );
}

#[test]
fn a_denied_tools_call_answers_the_requests_id_with_the_decision_and_the_method() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-denied-call-shape");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    let policy = format!(
        "{}\n@id(\"no_read_tool\")\n\
         forbid (principal, action == Box::Action::\"mcp:call\", resource)\n\
         when {{ context.input has tool && context.input.tool == \"read\" }};",
        mcp_call_policy_for("alpha")
    );
    box_.write_workspace(&policy, &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    client.initialize_and_activate(json!("initialize-1"), STARTUP);
    let list = client.list_root(json!(2), STARTUP);
    assert_list_response(&list, &json!(2), "read");

    let denied = client.call(json!("call-41"), "read", STARTUP);
    assert_eq!(
        denied,
        json!({
            "jsonrpc": "2.0",
            "id": "call-41",
            "error": {
                "code": -32001,
                "message": "policy denied this operation on 'alpha/read' [policy: no_read_tool]. (tools/call)"
            }
        }),
        "a denied call is a JSON-RPC error carrying the decision, the method, and the request id"
    );
    assert_eq!(
        box_.call_count("alpha-mcp"),
        0,
        "a denied call must not reach the server"
    );

    client.send(&json!({"jsonrpc": "2.0", "id": "ping-9", "method": "ping", "params": {}}));
    let pong = client.receive(STARTUP);
    assert_eq!(pong.get("id"), Some(&json!("ping-9")), "{pong}");
    assert_eq!(
        error_code(&pong),
        Some(-32601),
        "the fixture server answers a ping it does not implement, so the frame reached it: {pong}"
    );

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the denied call must not fail the run: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let records = policy_records(&records_path(&box_));
    let decided = records
        .iter()
        .filter(|record| record.action != "shell:spawn")
        .map(|record| {
            (
                record.action.as_str(),
                record.verdict.as_str(),
                record.resource.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        decided,
        [
            ("mcp:call", "permit", "alpha/tools/list"),
            ("mcp:call", "deny", "alpha/read"),
        ],
        "initialize and ping are floor methods and record no decision: {records:?}"
    );
    assert_eq!(
        records
            .iter()
            .find(|record| record.resource == "alpha/read")
            .map(|record| record.rule.as_str()),
        Some("no_read_tool")
    );
}

#[test]
fn concurrent_local_mcp_policy_spans_keep_each_messages_parent() {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("skipping: concurrent local MCP correlation requires a usable box launcher");
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-trace-concurrent");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    let policy = r#"
        @id("allow-mcp")
        permit (principal, action == Box::Action::"mcp:call", resource)
        when { context.input.server == "alpha" };
        @id("allow-read")
        permit (principal, action == alpha::Action::"read", resource);
        @id("deny-read")
        forbid (principal, action == alpha::Action::"read", resource)
        when { context.input.value == "denied" };
    "#;
    box_.write_workspace(policy, &[alpha], BLOCKING_WORKLOAD);
    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut allowed_client = box_.open_client("alpha-mcp");
    let mut denied_client = box_.open_client("alpha-mcp");
    for (client, id) in [(&mut allowed_client, "allow"), (&mut denied_client, "deny")] {
        let initialize_id = json!(format!("{id}-initialize"));
        let (_, response) = client.initialize_and_activate(initialize_id.clone(), STARTUP);
        assert_initialize_response(&response, "alpha", &initialize_id);
        let list_id = json!(format!("{id}-list"));
        assert_list_response(
            &client.list_root(list_id.clone(), STARTUP),
            &list_id,
            "read",
        );
    }
    let allowed = json!({
        "jsonrpc": "2.0", "id": 41, "method": "tools/call",
        "params": {
            "name": "read", "arguments": {"value": "fixture-private-argument"},
            "_meta": {
                "traceparent": "00-11111111111111111111111111111111-aaaaaaaaaaaaaaaa-01",
                "tracestate": "vendor=allowed",
                "threadId": "thread-allowed", "sessionId": "ignored-session",
                "callId": "call-allowed", "private": "fixture-private-metadata"
            }
        }
    });
    let denied = json!({
        "jsonrpc": "2.0", "id": 41, "method": "tools/call",
        "params": {
            "name": "read", "arguments": {"value": "denied"},
            "_meta": {
                "traceparent": "00-22222222222222222222222222222222-bbbbbbbbbbbbbbbb-00",
                "tracestate": "vendor=denied",
                "sessionId": "session-denied", "callId": "call-denied",
                "strands.box.source": "agent", "strands.box.policy.verdict": "permit",
                "gen_ai.tool.name": "forged-tool"
            }
        }
    });
    let barrier = std::sync::Barrier::new(2);
    let (allowed_response, denied_response) = std::thread::scope(|scope| {
        let allow = scope.spawn(|| {
            barrier.wait();
            allowed_client.send(&allowed);
            allowed_client.receive(STARTUP)
        });
        let deny = scope.spawn(|| {
            barrier.wait();
            denied_client.send(&denied);
            denied_client.receive(STARTUP)
        });
        (
            allow.join().expect("the allowed client"),
            deny.join().expect("the denied client"),
        )
    });
    assert_eq!(
        allowed_response,
        json!({
            "jsonrpc": "2.0", "id": 41,
            "result": {"content": [{"type": "text", "text": "called read"}], "isError": false}
        })
    );
    assert_eq!(denied_response["id"], 41);
    assert_eq!(
        error_code(&denied_response),
        Some(-32001),
        "{denied_response}"
    );
    assert!(
        denied_response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("deny-read")
    );
    assert_eq!(box_.call_count("alpha-mcp"), 1);
    assert_eq!(box_.received_frames("alpha-mcp", "call"), [allowed]);
    allowed_client.assert_running();
    denied_client.assert_running();
    drop((allowed_client, denied_client));
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
    let spans = observed_linked_policy_spans(&box_);
    assert_eq!(
        spans.len(),
        4,
        "two list decisions and two final call decisions"
    );
    for (trace, parent, state, verdict, rule) in [
        (
            "11111111111111111111111111111111",
            "aaaaaaaaaaaaaaaa",
            "vendor=allowed",
            "permit",
            "allow-read",
        ),
        (
            "22222222222222222222222222222222",
            "bbbbbbbbbbbbbbbb",
            "vendor=denied",
            "deny",
            "deny-read",
        ),
    ] {
        let span = mcp_policy_span(&spans, "41", Some(trace));
        assert_mcp_policy(span, "read", "alpha", verdict, rule);
        assert_eq!(span["traceId"], trace);
        assert_eq!(span["parentSpanId"], parent);
        assert_ne!(span["spanId"], span["parentSpanId"]);
        assert_eq!(
            span["traceState"].as_str().unwrap_or_default(),
            "",
            "the caller sent {state} and the box records no tracestate: {span}"
        );
        assert_eq!(span["flags"], 0x301, "the decision retains a remote parent");
        // The caller's parent reaches the span as a FIELD, asserted above, so the span omits the
        // attribute that would repeat it. The paired log record keeps it.
        assert_eq!(
            telemetry_attribute(span, "strands.box.trace.parent_span_id"),
            None,
            "a span field already states the parent: {span}"
        );
    }
}

#[test]
fn local_mcp_invalid_and_missing_parents_keep_message_ids_without_context_leaks() {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("skipping: local MCP fallback correlation requires a usable box launcher");
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-trace-fallback");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.write_workspace(
        r#"
        permit (principal, action == Box::Action::"mcp:call", resource)
        when { context.input.server == "alpha" && context.input.method == "tools/list" };
        @id("deny-calls")
        forbid (principal, action == Box::Action::"mcp:call", resource)
        when { context.input.server == "alpha" && context.input.method == "tools/call" };
        "#,
        &[alpha],
        BLOCKING_WORKLOAD,
    );
    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("alpha-mcp");
    client.initialize_and_activate(json!("initialize"), STARTUP);
    assert_list_response(
        &client.list_root(json!("list"), STARTUP),
        &json!("list"),
        "read",
    );
    for (id, meta) in [
        (
            json!("seed"),
            Some(json!({
                "traceparent": "00-33333333333333333333333333333333-cccccccccccccccc-01",
                "tracestate": "vendor=seed", "threadId": "thread-seed", "callId": "call-seed"
            })),
        ),
        (
            json!(42),
            Some(json!({
                "traceparent": "00-00000000000000000000000000000000-dddddddddddddddd-01",
                "tracestate": "vendor=invalid", "threadId": "thread-invalid", "callId": "call-invalid"
            })),
        ),
        (
            json!("missing-parent"),
            Some(json!({
                "tracestate": "vendor=orphan", "sessionId": "session-missing", "callId": "call-missing"
            })),
        ),
        (json!("missing-meta"), None),
    ] {
        let mut request = json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "read", "arguments": {"value": "fixture-private-argument"}}
        });
        if let Some(meta) = meta {
            request["params"]["_meta"] = meta;
        }
        client.send(&request);
        let response = client.receive(STARTUP);
        assert_eq!(response["id"], id);
        assert_eq!(error_code(&response), Some(-32001), "{response}");
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("deny-calls")
        );
        assert_eq!(box_.call_count("alpha-mcp"), 0);
        client.assert_running();
    }
    assert!(box_.received_frames("alpha-mcp", "call").is_empty());
    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
    let spans = observed_linked_policy_spans(&box_);
    assert_eq!(spans.len(), 5, "one list decision and four coarse refusals");
    let seed = mcp_policy_span(&spans, "seed", None);
    assert_eq!(seed["traceId"], "33333333333333333333333333333333");
    assert_eq!(seed["parentSpanId"], "cccccccccccccccc");
    assert_eq!(
        seed["traceState"].as_str().unwrap_or_default(),
        "",
        "the caller sent vendor=seed and the box records no tracestate: {seed}"
    );
    assert_mcp_policy(seed, "mcp:call", "mcp", "deny", "deny-calls");
    let mut traces = std::collections::BTreeSet::from([seed["traceId"].as_str().unwrap()]);
    for id in ["42", "missing-parent", "missing-meta"] {
        let span = mcp_policy_span(&spans, id, None);
        assert_mcp_policy(span, "mcp:call", "mcp", "deny", "deny-calls");
        assert!(traces.insert(span["traceId"].as_str().unwrap()), "{span}");
        assert_eq!(span["flags"], 3, "a fallback has no remote parent");
        assert!(
            span["parentSpanId"].is_null() || span["parentSpanId"] == "",
            "{span}"
        );
        assert!(
            span["traceState"].is_null() || span["traceState"] == "",
            "{span}"
        );
        assert!(
            span["links"].is_null() || span["links"] == json!([]),
            "{span}"
        );
        for key in [
            "strands.box.trace.parent_span_id",
            "strands.box.trace.parent_sampled",
            "strands.box.trace.state",
            "strands.box.trace.link_traceparent",
        ] {
            assert_eq!(telemetry_attribute(span, key), None, "{id} leaked {key}");
        }
    }
}

#[test]
fn multipage_exchange_routes_server_frames_and_stages_on_the_last_page() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-multipage-exchange");
    let alpha = Server::new(
        "alpha",
        "alpha-mcp",
        "read",
        DiscoveryBehavior::MultipageExchange,
    );
    box_.install_server(&alpha);
    box_.write_workspace(&policy_for("alpha", "read"), &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    client.initialize_and_activate(json!("initialize"), STARTUP);
    let request_shape = json!({
        "scope": "all",
        "fixtureOptions": {"includeAnnotations": true}
    });
    let exchange = client.list_all(1, request_shape.clone(), STARTUP);
    run.wait_for(
        box_.event("alpha-mcp", "finalization.notification"),
        STARTUP,
    );
    assert_eq!(exchange.pages.len(), 2, "{:?}", exchange.pages);
    assert_list_page(&exchange.pages[0], &json!(1), "read", 0);
    assert_list_page(&exchange.pages[1], &json!(2), "read-1", 1);
    for page in &exchange.pages {
        assert_eq!(
            page.pointer("/result/$defs/Shared/type"),
            Some(&json!("string")),
            "each page reaches the client unchanged"
        );
    }
    // Server frames keep flowing while the last page waits for its schema, so the finalization
    // notification can arrive before or after the held reply.
    let mut notifications = exchange.notifications.clone();
    if !notifications
        .iter()
        .any(|frame| frame.pointer("/params/phase") == Some(&json!("finalization")))
    {
        notifications.push(client.receive(STARTUP));
    }
    let mut phases = notifications
        .iter()
        .map(|frame| {
            frame
                .pointer("/params/phase")
                .and_then(Value::as_str)
                .expect("the fixture notification names its phase")
                .to_string()
        })
        .collect::<Vec<_>>();
    phases.sort();
    assert_eq!(phases, ["finalization", "pagination", "pagination"]);
    assert_eq!(
        exchange
            .requests
            .iter()
            .map(|request| request["method"].clone())
            .collect::<Vec<_>>(),
        [json!("ping"), json!("fixture/unsupported")],
        "server requests must reach the client"
    );
    assert_eq!(
        box_.received_frames("alpha-mcp", "broker"),
        vec![
            json!({"jsonrpc": "2.0", "id": "fixture-ping", "result": {}}),
            json!({
                "jsonrpc": "2.0",
                "id": 701,
                "error": {"code": -32601, "message": "Method not found"}
            }),
        ],
        "the client's answers must reach the server"
    );
    let discovery_requests = box_.received_frames("alpha-mcp", "list");
    assert_eq!(discovery_requests.len(), 2);
    assert_eq!(discovery_requests[0].get("id"), Some(&json!(1)));
    assert_eq!(
        discovery_requests[0].get("params"),
        Some(&request_shape),
        "the first page request reaches the server unchanged"
    );
    let mut second_shape = request_shape.clone();
    second_shape
        .as_object_mut()
        .expect("the request shape is an object")
        .insert("cursor".to_string(), json!("cursor-1"));
    assert_eq!(discovery_requests[1].get("params"), Some(&second_shape));

    let call = client.call(json!(3), "read", STARTUP);
    assert!(call.get("result").is_some(), "{call}");

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the multipage run must finish normally: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = box_
        .root()
        .join("private")
        .join("telemetry")
        .join("records.jsonl");
    let decisions = observed_policy_decisions(&records);
    assert!(
        decisions
            .iter()
            .all(|decision| decision.rule != "enforcement:mcp-catalog"),
        "no request is refused by the catalog: {decisions:?}"
    );
    let control = observed_control_operations(&records);
    assert!(
        control.contains(&("schema_installed".to_string(), "alpha".to_string())),
        "the staged schema must be recorded: {control:?}"
    );
    assert!(
        control
            .iter()
            .any(|(operation, _)| operation == "discovery_complete"),
        "and the authority becoming complete: {control:?}"
    );
}

#[test]
fn catalog_page_limit_accepts_256_pages_and_refuses_a_257th() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for (pages, accepted) in [(256, true), (257, false)] {
        let name = format!("mcp-pages-{pages}");
        let box_ = RuntimeMcpBox::new(&name);
        let server = Server::new(
            "paged",
            "paged-mcp",
            "read",
            DiscoveryBehavior::Pages(pages),
        );
        box_.install_server(&server);
        box_.write_workspace(
            &mcp_call_policy_for(server.name),
            &[server],
            BLOCKING_WORKLOAD,
        );

        let mut run = box_.spawn();
        run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
        let mut client = box_.open_client("paged-mcp");
        run.wait_for(box_.server_started("paged-mcp"), STARTUP);
        client.initialize_and_activate(json!("initialize"), STARTUP);
        let exchange = client.list_all(1, json!({}), CATALOG_TIMEOUT);
        assert_eq!(exchange.pages.len(), pages, "the client pages to the end");
        assert_list_page(&exchange.pages[0], &json!(1), "read", 0);
        if accepted {
            assert!(
                exchange.last().get("result").is_some(),
                "{}",
                exchange.last()
            );
        } else {
            assert_eq!(
                error_code(exchange.last()),
                Some(-32002),
                "{}",
                exchange.last()
            );
        }
        assert_eq!(
            box_.list_count("paged-mcp"),
            pages,
            "the server answers every page the client requests"
        );
        let requests = box_.received_frames("paged-mcp", "list");
        assert_eq!(requests.len(), pages);
        assert!(
            requests
                .iter()
                .all(|request| request.get("id").is_some_and(Value::is_u64)),
            "every page request must carry the client's own id"
        );

        drop(client);
        box_.release_workload();
        let output = run.wait(SHUTDOWN);
        assert!(
            output.status.success(),
            "the page-boundary run must stay isolated: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Time one box from its first `tools/list` to its first catalog, over `pages` pages.
fn time_to_first_catalog(pages: usize) -> Duration {
    let box_ = RuntimeMcpBox::new(&format!("mcp-first-catalog-{pages}"));
    let server = Server::new(
        "paged",
        "paged-mcp",
        "read",
        DiscoveryBehavior::Pages(pages),
    );
    box_.install_server(&server);
    box_.write_workspace(
        &mcp_call_policy_for(server.name),
        &[server],
        BLOCKING_WORKLOAD,
    );
    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("paged-mcp");
    run.wait_for(box_.server_started("paged-mcp"), STARTUP);
    client.initialize_and_activate(json!("initialize"), STARTUP);
    let started = std::time::Instant::now();
    let exchange = client.list_all(1, json!({}), CATALOG_TIMEOUT);
    let elapsed = started.elapsed();
    assert_list_page(&exchange.pages[0], &json!(1), "read", 0);
    assert!(
        exchange.last().get("result").is_some(),
        "{}",
        exchange.last()
    );
    assert_eq!(
        box_.list_count("paged-mcp"),
        pages,
        "the first catalog must page through the whole listing"
    );
    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the timed run must finish cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    elapsed
}

#[test]
fn the_first_catalog_of_256_pages_costs_at_most_three_times_one_of_128_pages() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const LARGEST_RATIO: f64 = 3.0;
    let full = time_to_first_catalog(256);
    let half = time_to_first_catalog(128);
    let ratio = full.as_secs_f64() / half.as_secs_f64().max(f64::EPSILON);
    let _ = writeln!(
        std::io::stderr().lock(),
        "NFR-09 time to the first catalog: 128 pages {half:?} ({:.1} ms per page), 256 pages \
         {full:?} ({:.1} ms per page), ratio {ratio:.2}, limit {LARGEST_RATIO}; {} build",
        half.as_secs_f64() * 1000.0 / 128.0,
        full.as_secs_f64() * 1000.0 / 256.0,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    assert!(
        ratio <= LARGEST_RATIO,
        "the first catalog of 256 pages took {full:?} against {half:?} for 128 pages (ratio \
         {ratio:.2}, limit {LARGEST_RATIO}): the cost per page grows with the page count"
    );
}

#[test]
fn invalid_catalog_variants_fail_closed_through_the_lazy_exchange() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-invalid-catalogs");
    let servers = [
        Server::new(
            "cursor",
            "cursor-mcp",
            "read",
            DiscoveryBehavior::RepeatedCursor,
        ),
        Server::new("tool", "tool-mcp", "read", DiscoveryBehavior::RepeatedTool),
        Server::new(
            "definitions",
            "definitions-mcp",
            "read",
            DiscoveryBehavior::ConflictingDefinitions,
        ),
        Server::new(
            "invalid",
            "invalid-mcp",
            "read",
            DiscoveryBehavior::InvalidResponse,
        ),
        Server::new(
            "error",
            "error-mcp",
            "read",
            DiscoveryBehavior::ErrorResponse,
        ),
    ];
    for server in &servers {
        box_.install_server(server);
    }
    box_.write_workspace(
        &mcp_call_policy_for_servers(&servers),
        &servers,
        BLOCKING_WORKLOAD,
    );

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    for (index, server) in servers.iter().enumerate() {
        let mut client = box_.open_client(server.program);
        run.wait_for(box_.server_started(server.program), STARTUP);
        client.initialize_and_activate(json!(index), STARTUP);
        let exchange = client.list_all(100, json!({}), STARTUP);
        assert_eq!(
            error_code(exchange.last()),
            Some(-32002),
            "{} must fail closed: {:?}",
            server.program,
            exchange.pages
        );
        client.wait(SHUTDOWN);
    }
    assert_eq!(box_.list_count("cursor-mcp"), 2);
    assert_eq!(box_.list_count("tool-mcp"), 2);
    assert_eq!(box_.list_count("definitions-mcp"), 2);
    assert_eq!(box_.list_count("invalid-mcp"), 1);
    assert_eq!(box_.list_count("error-mcp"), 1);
    assert!(
        run.is_running(),
        "catalog validation failures must not stop ready authority"
    );

    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "catalog failures must remain isolated: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn alpha_stays_ready_while_beta_is_discovered() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-alpha-beta");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    let beta = Server::new(
        "beta",
        "beta-mcp",
        "write",
        DiscoveryBehavior::WaitForRelease,
    );
    box_.install_server(&alpha);
    box_.install_server(&beta);
    let policy = format!(
        "{}\n{}",
        policy_for("alpha", "read"),
        policy_for("beta", "write")
    );
    box_.write_workspace(&policy, &[alpha, beta], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut alpha_client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    alpha_client.initialize_and_activate(json!("alpha-init"), STARTUP);
    run.wait_for(box_.server_initialized("alpha-mcp"), STARTUP);
    let alpha_list = alpha_client.list_root(json!("alpha-list"), STARTUP);
    assert_list_response(&alpha_list, &json!("alpha-list"), "read");
    assert_eq!(
        box_.invocation_count("beta-mcp"),
        0,
        "Alpha must return while unopened Beta remains pending"
    );

    let ready = alpha_client.call(json!("alpha-ready"), "read", STARTUP);
    assert!(ready.get("result").is_some(), "{ready}");
    assert_eq!(
        box_.call_count("alpha-mcp"),
        1,
        "Alpha's staged rule must serve while Beta remains undiscovered"
    );

    let mut beta_client = box_.open_client("beta-mcp");
    run.wait_for(box_.server_started("beta-mcp"), STARTUP);
    beta_client.initialize_and_activate(json!("beta-init"), STARTUP);
    run.wait_for(box_.server_initialized("beta-mcp"), STARTUP);
    beta_client.request_root_list(json!("beta-list"));
    run.wait_for(box_.list_started("beta-mcp"), STARTUP);
    box_.release_server("beta-mcp");
    let beta_list = beta_client.receive(STARTUP);
    assert_list_response(&beta_list, &json!("beta-list"), "write");

    let allowed = alpha_client.call(json!("alpha-allowed"), "read", STARTUP);
    assert_eq!(allowed.get("id"), Some(&json!("alpha-allowed")));
    assert!(allowed.get("result").is_some(), "{allowed}");
    run.wait_for(box_.call_received("alpha-mcp"), STARTUP);
    assert_eq!(
        box_.call_count("alpha-mcp"),
        2,
        "both permitted Alpha calls must reach the server"
    );
    assert!(run.is_running(), "accepted staging must keep the run live");

    drop(alpha_client);
    drop(beta_client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the complete staged bundle must finish normally: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn compatible_alpha_first_and_beta_first_discovery_install_equivalent_authority() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let alpha_first = authority_after_discovery_order("mcp-alpha-first", false);
    let beta_first = authority_after_discovery_order("mcp-beta-first", true);
    assert_eq!(
        alpha_first, beta_first,
        "compatible discovery order must produce the same Alpha and Beta verdicts"
    );
}

#[test]
fn child_exit_after_ready_keeps_the_accepted_catalog() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-ready-child-exit");
    let alpha = Server::new(
        "alpha",
        "alpha-mcp",
        "read",
        DiscoveryBehavior::ExitAfterReady,
    );
    box_.install_server(&alpha);
    box_.write_workspace(&policy_for("alpha", "read"), &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut first = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    first.initialize_and_activate(json!("first-initialize"), STARTUP);
    let accepted = first.list_root(json!("first-list"), STARTUP);
    assert_list_response(&accepted, &json!("first-list"), "read");
    run.wait_for(box_.event("alpha-mcp", "exit.waiting"), STARTUP);
    let first_pid = box_.server_pid("alpha-mcp");
    box_.release_server("alpha-mcp");
    wait_for_process_exit(first_pid, SHUTDOWN);
    let _ = first.wait(SHUTDOWN);

    let mut second = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    second.initialize_and_activate(json!("second-initialize"), STARTUP);
    let relisted = second.list_root(json!(902), STARTUP);
    assert_list_response(&relisted, &json!(902), "read");
    assert_eq!(
        box_.invocation_count("alpha-mcp"),
        2,
        "the second Open must start its own initialized process"
    );
    assert_eq!(
        box_.list_count("alpha-mcp"),
        2,
        "the second process answers its own list"
    );

    drop(second);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "a post-ready child exit must not fail the run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unused_beta_stays_unstarted_and_prevents_completion() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-unused-beta");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    let beta = Server::new("beta", "beta-mcp", "write", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.install_server(&beta);
    let policy = format!(
        "{}\n{}",
        policy_for("alpha", "read"),
        policy_for("beta", "write")
    );
    box_.write_workspace(&policy, &[alpha, beta], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut alpha_client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    alpha_client.initialize_and_activate(json!(1), STARTUP);
    alpha_client.list_root(json!(2), STARTUP);
    let ready = alpha_client.call(json!(3), "read", STARTUP);
    assert!(ready.get("result").is_some(), "{ready}");
    assert_eq!(box_.call_count("alpha-mcp"), 1);
    assert_eq!(
        box_.invocation_count("beta-mcp"),
        0,
        "an unused declaration must stay unstarted"
    );
    assert!(
        run.is_running(),
        "an Undiscovered Beta entry must prevent terminal completion"
    );
    assert!(
        box_.live_record().exists(),
        "the run must remain live while Beta can still add a schema"
    );

    drop(alpha_client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "normal teardown must not convert unused Beta into failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unresolved_completion_keeps_ready_tools_and_withdraws_live_state_on_exit() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-unresolved");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    let policy = format!(
        "{}\n{}",
        policy_for("alpha", "read"),
        policy_for("missing", "never")
    );
    box_.write_workspace(&policy, &[alpha], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    run.wait_for(box_.live_record(), STARTUP);
    let mut client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    client.initialize_and_activate(json!(1), STARTUP);
    let response = client.list_root(json!(2), STARTUP);
    assert_list_response(&response, &json!(2), "read");

    let ready = client.call(json!("alpha-ready"), "read", STARTUP);
    assert!(ready.get("result").is_some(), "{ready}");
    assert_eq!(box_.call_count("alpha-mcp"), 1);
    assert!(
        run.is_running() && box_.live_record().exists(),
        "an unresolved server must leave the ready tools and workload running"
    );
    assert!(
        !box_.workload_path("release").exists(),
        "the workload must remain active before its release condition"
    );
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(output.status.success(), "{output:?}");
    assert!(
        !box_.live_record().exists(),
        "normal shutdown must withdraw live state"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#"discovery denied tools/list for ["missing"]"#),
        "{stderr}"
    );
    drop(client);

    let stored = std::fs::read_to_string(box_.stored_record())
        .unwrap_or_else(|error| panic!("the box must remain after shutdown: {error}"));
    let parsed: toml::Value = toml::from_str(&stored)
        .unwrap_or_else(|error| panic!("the remaining record must parse: {error}\n{stored}"));
    assert_eq!(
        parsed["name"].as_str(),
        Some("mcp-unresolved"),
        "the remaining record must name the box: {stored}"
    );
}

#[test]
fn failed_discovery_reaps_its_process_group_and_refuses_later_open() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-failed-group");
    let broken = Server::new(
        "broken",
        "broken-mcp",
        "read",
        DiscoveryBehavior::FailAfterRelease,
    );
    box_.install_server(&broken);
    box_.write_workspace(
        &mcp_call_policy_for(broken.name),
        &[broken],
        BLOCKING_WORKLOAD,
    );

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("broken-mcp");
    run.wait_for(box_.server_started("broken-mcp"), STARTUP);
    client.initialize_and_activate(json!(1), STARTUP);
    client.request_root_list(json!(2));
    run.wait_for(box_.list_started("broken-mcp"), STARTUP);
    run.wait_for(
        box_.operator_home()
            .join(".runtime-mcp-test/broken-mcp.descendant.pid"),
        STARTUP,
    );
    let leader = box_.server_pid("broken-mcp");
    let descendant = box_.descendant_pid("broken-mcp");
    box_.release_server("broken-mcp");
    let response = client.receive(STARTUP);
    assert_eq!(error_code(&response), Some(-32002), "{response}");
    client.wait(SHUTDOWN);
    wait_for_process_exit(leader, SHUTDOWN);
    wait_for_process_exit(descendant, SHUTDOWN);

    let refusal = box_.invoke_refused_open("broken-mcp", SHUTDOWN);
    let invocations = box_.invocation_count("broken-mcp");
    assert!(
        !refusal.status.success(),
        "a later Open must be refused: status={}, stderr={:?}, invocations={invocations}",
        refusal.status,
        refusal.stderr
    );
    assert!(
        refusal.stderr.contains("failed") || refusal.stderr.contains("discovery"),
        "{}",
        refusal.stderr
    );
    assert_eq!(
        invocations, 1,
        "a later Open after Failed must not start a process"
    );
    assert!(
        run.is_running(),
        "a failed optional server must not stop ready authority"
    );

    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the failed server must remain isolated: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn one_failure_reaps_all_live_leader_and_follower_groups_before_exchange_close() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-failed-followers");
    let broken = Server::new(
        "broken",
        "broken-mcp",
        "read",
        DiscoveryBehavior::FailAfterRelease,
    );
    box_.install_server(&broken);
    box_.write_workspace(
        &mcp_call_policy_for(broken.name),
        &[broken],
        BLOCKING_WORKLOAD,
    );

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut clients = Vec::new();
    for index in 0..3 {
        let mut client = box_.open_client("broken-mcp");
        client.initialize_and_activate(json!(index), STARTUP);
        clients.push(client);
    }
    let groups = box_.process_groups("broken-mcp", clients.len(), STARTUP);
    let response_ids = [
        json!("leader"),
        json!("follower-one"),
        json!("follower-two"),
    ];

    clients[0].request_root_list(response_ids[0].clone());
    run.wait_for(box_.list_started("broken-mcp"), STARTUP);
    assert_follower_joined(
        &mut clients[1],
        response_ids[1].clone(),
        json!("follower-one-barrier"),
    );
    assert_follower_joined(
        &mut clients[2],
        response_ids[2].clone(),
        json!("follower-two-barrier"),
    );

    box_.release_server("broken-mcp");
    for (leader, descendant) in &groups {
        wait_for_process_exit(*leader, SHUTDOWN);
        wait_for_process_exit(*descendant, SHUTDOWN);
    }
    for client in &mut clients {
        client.assert_running();
    }

    for (index, mut client) in clients.into_iter().enumerate() {
        let response = client.receive(CATALOG_TIMEOUT);
        assert_eq!(response.get("id"), Some(&response_ids[index]), "{response}");
        assert_eq!(error_code(&response), Some(-32002), "{response}");
        client.wait(SHUTDOWN);
    }

    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the shared failure must remain isolated: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn discovery_timeout_reaps_its_process_group_and_refuses_later_open() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-timeout-group");
    let slow = Server::new("slow", "slow-mcp", "read", DiscoveryBehavior::Hang);
    box_.install_server(&slow);
    box_.write_workspace(&mcp_call_policy_for(slow.name), &[slow], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("slow-mcp");
    run.wait_for(box_.server_started("slow-mcp"), STARTUP);
    client.initialize_and_activate(json!(1), STARTUP);
    client.request_root_list(json!(2));
    run.wait_for(box_.list_started("slow-mcp"), STARTUP);
    run.wait_for(
        box_.operator_home()
            .join(".runtime-mcp-test/slow-mcp.descendant.pid"),
        STARTUP,
    );
    let leader = box_.server_pid("slow-mcp");
    let descendant = box_.descendant_pid("slow-mcp");
    let response = client.receive(DISCOVERY_TIMEOUT);
    assert_eq!(error_code(&response), Some(-32002), "{response}");
    client.wait(SHUTDOWN);
    wait_for_process_exit(leader, SHUTDOWN);
    wait_for_process_exit(descendant, SHUTDOWN);

    let refusal = box_.invoke_refused_open("slow-mcp", SHUTDOWN);
    let invocations = box_.invocation_count("slow-mcp");
    assert!(
        !refusal.status.success(),
        "a later Open must be refused: status={}, stderr={:?}, invocations={invocations}",
        refusal.status,
        refusal.stderr
    );
    assert_eq!(
        invocations, 1,
        "a later Open after timeout must not start a process"
    );
    assert!(run.is_running(), "timeout must not stop ready authority");

    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the timeout must remain isolated: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn at_most_four_catalog_attempts_progress_concurrently() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-attempt-limit");
    let servers = [
        Server::new("s0", "mcp-s0", "read", DiscoveryBehavior::WaitForRelease),
        Server::new("s1", "mcp-s1", "read", DiscoveryBehavior::WaitForRelease),
        Server::new("s2", "mcp-s2", "read", DiscoveryBehavior::WaitForRelease),
        Server::new("s3", "mcp-s3", "read", DiscoveryBehavior::WaitForRelease),
        Server::new("s4", "mcp-s4", "read", DiscoveryBehavior::WaitForRelease),
    ];
    for server in &servers {
        box_.install_server(server);
    }
    box_.write_workspace(
        &mcp_call_policy_for_servers(&servers),
        &servers,
        BLOCKING_WORKLOAD,
    );

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut clients = Vec::new();
    for (index, server) in servers.iter().enumerate() {
        let mut client = box_.open_client(server.program);
        run.wait_for(box_.server_started(server.program), STARTUP);
        client.initialize_and_activate(json!(index), STARTUP);
        client.request_root_list(json!(100 + index));
        clients.push(client);
    }
    for server in &servers[..4] {
        run.wait_for(box_.list_started(server.program), STARTUP);
    }
    assert_eq!(
        box_.list_count(servers[4].program),
        0,
        "the fifth catalog request must wait for a permit"
    );
    assert_eq!(
        box_.invocation_count(servers[4].program),
        1,
        "Open starts the fifth process even while its catalog attempt waits"
    );

    box_.release_server(servers[0].program);
    let first = clients[0].receive(STARTUP);
    assert_list_response(&first, &json!(100), "read");
    run.wait_for(box_.list_started(servers[4].program), STARTUP);
    for server in &servers[1..] {
        box_.release_server(server.program);
    }
    for (index, client) in clients.iter_mut().enumerate().skip(1) {
        let response = client.receive(STARTUP);
        assert_list_response(&response, &json!(100 + index), "read");
    }

    drop(clients);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "bounded concurrent staging must finish normally: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn open_uses_declared_command_and_trusted_launch_context() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-launch-context");
    let trace = Server::new("trace", "trace-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&trace);
    box_.write_workspace("", &[trace], BLOCKING_WORKLOAD);

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let client = box_.open_client("trace-mcp");
    run.wait_for(box_.server_started("trace-mcp"), STARTUP);

    assert_eq!(
        serde_json::from_str::<Value>(&box_.trace("trace-mcp", "argv"))
            .expect("parse the declared arguments"),
        json!(["--declared", "trace"]),
        "Open must use the arguments from the locked declaration"
    );
    assert_eq!(
        Path::new(&box_.trace("trace-mcp", "home")),
        box_.operator_home()
            .canonicalize()
            .expect("the operator home resolves"),
        "the MCP server must receive the operator HOME"
    );
    assert_eq!(
        box_.trace("trace-mcp", "path"),
        box_.trusted_path().to_string_lossy(),
        "the contained MCP leaf must receive the trusted run PATH, with no box bin"
    );
    assert_eq!(
        Path::new(&box_.trace("trace-mcp", "cwd")),
        box_.operator_home()
            .join("workspace")
            .canonicalize()
            .expect("the agent workspace resolves"),
        "the contained MCP leaf starts in the agent workspace (tool-leaf containment fallback)"
    );
    assert_eq!(
        box_.trace("trace-mcp", "sentinel"),
        "absent",
        "the MCP process must not inherit an unrelated variable"
    );
    let environment: serde_json::Map<String, Value> =
        serde_json::from_str(&box_.trace("trace-mcp", "environment"))
            .expect("parse the child environment");
    assert_eq!(
        environment.get("HOME").and_then(Value::as_str),
        Some(
            box_.operator_home()
                .canonicalize()
                .expect("the operator home resolves")
                .to_str()
                .expect("the operator home is UTF-8")
        )
    );
    assert_eq!(
        environment.get("PATH").and_then(Value::as_str),
        box_.trusted_path().to_str()
    );
    // A contained leaf receives the box's composed egress environment.
    assert_eq!(
        environment.get("USER").and_then(Value::as_str),
        Some("strands-box"),
        "the leaf runs as the box identity"
    );
    let proxy = environment
        .get("HTTPS_PROXY")
        .and_then(Value::as_str)
        .expect("the leaf is pointed at the egress gateway");
    assert!(
        proxy.starts_with("http://127.0.0.1:"),
        "the gateway proxy is on loopback: {proxy}"
    );
    let ca = environment
        .get("SSL_CERT_FILE")
        .and_then(Value::as_str)
        .expect("the leaf trusts the box CA bundle");
    assert!(
        ca.ends_with("/trust/cert.pem"),
        "the CA bundle is the box's trust cert: {ca}"
    );
    assert!(
        environment.contains_key("OTEL_EXPORTER_OTLP_ENDPOINT"),
        "the leaf reports telemetry to the box endpoint"
    );
    assert_eq!(box_.list_count("trace-mcp"), 0);

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the launch-context run must finish normally: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn trusted_launch_path_falls_back_when_the_run_path_is_absent() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-path-fallback");
    let executable = box_.server_executable("fallback-mcp");
    let trace = Server::new("trace", "env", "read", DiscoveryBehavior::Ready).launched_through(
        "fallback-mcp",
        vec![
            executable.to_string_lossy().into_owned(),
            "--declared".to_string(),
            "trace".to_string(),
        ],
    );
    box_.install_server(&trace);
    box_.write_workspace("", &[trace], BLOCKING_WORKLOAD);

    let mut run = box_.spawn_without_trusted_path();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let client = box_.open_client("env");
    run.wait_for(box_.server_started("env"), STARTUP);

    assert_eq!(
        box_.trace("env", "path"),
        "/usr/bin:/bin",
        "an absent trusted PATH must use the fixed MCP fallback, with no box bin"
    );
    let environment: serde_json::Map<String, Value> =
        serde_json::from_str(&box_.trace("env", "environment"))
            .expect("parse the fallback child environment");
    assert_eq!(
        environment.get("PATH").and_then(Value::as_str),
        Some("/usr/bin:/bin")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&box_.trace("env", "argv"))
            .expect("parse the fallback command arguments"),
        json!(["--declared", "trace"]),
        "the PATH fallback must still start the declared command"
    );

    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the fallback launch run must finish normally: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn runtime_ignores_workspace_and_private_generated_schema_artifacts() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-stale-schemas");
    box_.write_workspace("", &[], ":");
    let initialized = box_.spawn().wait(SHUTDOWN);
    assert!(
        initialized.status.success(),
        "the initial run must create valid private state: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let stale_schema = policy::generate_mcp_schema(
        "stale",
        r#"{
            "result": {
                "tools": [{
                    "name": "only",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                }]
            }
        }"#,
    )
    .expect("generate the stale schema artifact");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.write_workspace(&policy_for("stale", "only"), &[alpha], BLOCKING_WORKLOAD);
    let (workspace_actions, workspace_events, private_schemas) =
        box_.plant_generated_schema_artifacts(&stale_schema);
    let actions_before =
        std::fs::read(&workspace_actions).expect("read the stale workspace action schema");
    let events_before =
        std::fs::read(&workspace_events).expect("read the stale workspace event schema");
    let private_before =
        std::fs::read(&private_schemas).expect("read the stale private schema set");

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("alpha-mcp");
    run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    client.initialize_and_activate(json!(1), STARTUP);
    let refused = client.list_root(json!(2), STARTUP);
    assert_eq!(error_code(&refused), Some(-32001), "{refused}");
    assert_eq!(box_.list_count("alpha-mcp"), 0);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the unresolved server must degrade without stopping the workload: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#"discovery denied tools/list for ["stale"]"#),
        "the stale-only action must degrade rather than adopt a stored schema: {stderr}"
    );
    assert!(
        !box_.live_record().exists(),
        "normal shutdown must withdraw live state"
    );

    std::fs::remove_file(box_.workload_path("workload.started"))
        .expect("remove the first workload marker");
    std::fs::remove_file(box_.workload_path("release")).expect("reset the workload release");
    let mut second_run = box_.spawn_from_operator_home();
    second_run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut second_client = box_.open_client("alpha-mcp");
    second_run.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    second_client.initialize_and_activate(json!(3), STARTUP);
    let refused = second_client.list_root(json!(4), STARTUP);
    assert_eq!(error_code(&refused), Some(-32001), "{refused}");
    assert_eq!(box_.list_count("alpha-mcp"), 0);
    box_.release_workload();
    let second_output = second_run.wait(SHUTDOWN);
    assert!(
        second_output.status.success(),
        "the second run must keep the workload available: {second_output:?}"
    );
    assert!(
        String::from_utf8_lossy(&second_output.stderr)
            .contains(r#"discovery denied tools/list for ["stale"]"#),
        "the second run must also degrade the stale-only action: {}",
        String::from_utf8_lossy(&second_output.stderr)
    );
    drop(second_client);
    assert_eq!(
        std::fs::read(&workspace_actions).expect("read the retained workspace action schema"),
        actions_before,
        "runtime discovery must not rewrite the workspace action artifact"
    );
    assert_eq!(
        std::fs::read(&workspace_events).expect("read the retained workspace event schema"),
        events_before,
        "runtime discovery must not rewrite the workspace event artifact"
    );
    assert_eq!(
        std::fs::read(&private_schemas).expect("read the retained private schema set"),
        private_before,
        "runtime discovery must ignore the old private schema copy"
    );
    drop(client);
}

#[test]
fn one_locked_run_keeps_its_record_policy_and_mcp_snapshot() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = RuntimeMcpBox::new("mcp-snapshot");
    let alpha = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&alpha);
    box_.write_workspace(&policy_for("alpha", "read"), &[alpha], BLOCKING_WORKLOAD);

    let mut first = box_.spawn();
    first.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    first.wait_for(box_.live_record(), STARTUP);
    let stored_record =
        std::fs::read(box_.stored_record()).expect("read the first run's stored record");
    let stored_policy =
        std::fs::read(box_.stored_policy()).expect("read the first run's stored policy");

    let beta = Server::new("beta", "beta-mcp", "write", DiscoveryBehavior::Ready);
    box_.install_server(&beta);
    box_.write_workspace(
        &policy_for("beta", "write"),
        &[beta],
        r#"
set -eu
: > "$HOME/second-workload.started"
"#,
    );
    let second = box_.spawn_attempt().wait(Duration::from_secs(5));
    assert!(
        !second.status.success(),
        "a second run must not prepare a new snapshot while the first owns the box"
    );
    let refusal = String::from_utf8_lossy(&second.stderr);
    assert!(
        refusal.contains("already") || refusal.contains("in progress"),
        "{refusal}"
    );
    assert_eq!(
        std::fs::read(box_.stored_record()).expect("read the locked stored record"),
        stored_record,
        "the rejected run must not replace the record under the owner"
    );
    assert_eq!(
        std::fs::read(box_.stored_policy()).expect("read the locked stored policy"),
        stored_policy,
        "the rejected run must not replace the policy under the owner"
    );
    assert_eq!(
        box_.invocation_count("beta-mcp"),
        0,
        "the rejected snapshot must not start Beta"
    );
    assert!(
        !box_.workload_path("second-workload.started").exists(),
        "the rejected snapshot must not start its workload"
    );

    let mut alpha_client = box_.open_client("alpha-mcp");
    first.wait_for(box_.server_started("alpha-mcp"), STARTUP);
    alpha_client.initialize_and_activate(json!(1), STARTUP);
    let response = alpha_client.list_root(json!(2), STARTUP);
    assert_list_response(&response, &json!(2), "read");
    let allowed = alpha_client.call(json!(3), "read", STARTUP);
    assert!(allowed.get("result").is_some(), "{allowed}");
    assert_eq!(
        box_.invocation_count("beta-mcp"),
        0,
        "the locked run must keep the original MCP declaration snapshot"
    );

    drop(alpha_client);
    box_.release_workload();
    let output = first.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the first snapshot must finish on its original authority: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        box_.root().is_dir(),
        "the completed run must keep its configured box"
    );
}
