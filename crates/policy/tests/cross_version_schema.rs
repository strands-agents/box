//! A generated MCP tool schema and a rule's history over it survive a rollback to the last release.
//!
//! Each server's generated fragment is stored in the policy history, and every start validates it
//! again against that binary's own Box schema. A fragment that names a type only a newer Box schema
//! declares is dropped by the previous release on rollback, which removes every per-tool rule for
//! that server and resets its history. `fixtures/actions-v0.2.2.cedarschema` is the Box schema of
//! the release an operator can roll back to; refresh it when a release ships.

use std::path::{Path, PathBuf};

use cedar_policy::{Schema, SchemaFragment};
use dogwood_local_engine::DurableTemporalEngine;
use policy::{
    GovernedBox, McpReply, Outcome, Policy, PolicyEngine, Principal, Request, SchemaStage,
    generate_mcp_schema,
};
use serde_json::json;

const PREVIOUS_RELEASE: &str = include_str!("fixtures/actions-v0.2.2.cedarschema");

const DESK_TOOLS: &str = r#"{"result": {"tools": [{"name": "reset_password",
    "inputSchema": {"type": "object", "properties": {"user_name": {"type": "string"}},
        "required": ["user_name"]},
    "outputSchema": {"type": "object", "properties": {"reset": {"type": "boolean"}}}}]}}"#;

/// A budget of one `reset_password` an hour, on an event both releases record. The call being
/// decided records its own `::request`, so the second call sees a count of two.
const ONE_RESET_AN_HOUR: &str = r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "desk" };
permit(principal, action == desk::Action::"reset_password", resource);
@id("one_reset")
forbid(principal, action == desk::Action::"reset_password", resource)
when temporal {
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (
                desk::Action::"reset_password"::request{ input.user_name: _ } && tp(t)
            )
        )) == total && total >= 2
    )
};
"#;

/// Open the budget over `history` and stage desk's generated schema, as a start of this build does.
fn desk(history: &Path) -> PolicyEngine {
    let authority = PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        vec![Policy {
            origin: PathBuf::from("policy.dw"),
            text: ONE_RESET_AN_HOUR.to_string(),
        }],
        history,
    )
    .expect("the policy opens");
    assert_eq!(
        authority
            .stage_mcp_schema(
                "desk",
                generate_mcp_schema("desk", DESK_TOOLS).expect("the desk schema generates"),
            )
            .expect("desk's schema stages"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
    authority
}

/// Whether one `tools/call` of `reset_password` is allowed, recording both legs when it is.
fn reset(authority: &PolicyEngine, user_name: &str) -> bool {
    let governed = GovernedBox::assigned("test-box");
    let (decision, request_id) = authority.decide(
        &governed,
        &Principal::agent(),
        &Request::McpCall {
            server: "desk",
            method: "tools/call",
            tool: Some("reset_password"),
            prompt: None,
            uri: None,
            arguments: None,
        },
    );
    if !decision.is_allow() {
        return false;
    }
    let (refined, pending) = authority.refine_tool_call(
        &governed,
        &Principal::agent(),
        "desk",
        "reset_password",
        &json!({ "user_name": user_name }),
    );
    if !refined.is_allow() {
        return false;
    }
    authority
        .record(
            &governed,
            &Principal::agent(),
            &request_id.expect("an allowed call has a request id"),
            &Outcome::Mcp {
                server: "desk",
                method: "tools/call",
                tool: Some("reset_password"),
                prompt: None,
                uri: None,
            },
        )
        .expect("the coarse response records");
    if let Some(pending) = pending {
        authority
            .record_tool_response(pending, McpReply::Result)
            .expect("the tool response records");
    }
    true
}

/// The stored tool schema of `server`, composed with the previous release's Box schema the way
/// that release recovers it on start.
fn stored_schema_under_the_previous_release(
    history: &Path,
    server: &str,
) -> Result<Schema, String> {
    let stored = DurableTemporalEngine::open(history, 10_000)
        .expect("the store opens")
        .action_schema()
        .expect("the store holds an action schema");
    let (fragment, _) =
        SchemaFragment::from_cedarschema_str(&stored).expect("the stored schema parses");
    let mut namespaces = fragment.to_json_value().expect("the stored schema renders");
    let server_fragment = namespaces
        .as_object_mut()
        .and_then(|namespaces| namespaces.remove(server))
        .unwrap_or_else(|| panic!("the stored schema declares {server}"));
    let server_fragment = SchemaFragment::from_json_value(json!({ server: server_fragment }))
        .expect("the server fragment parses");
    let (previous, _) = SchemaFragment::from_cedarschema_str(PREVIOUS_RELEASE)
        .expect("the previous release's schema parses");
    Schema::from_schema_fragments([previous, server_fragment]).map_err(|error| error.to_string())
}

/// Tool lists covering each shape the generator renders: plain inputs, unions, numbers, enums,
/// nested objects, and declared outputs of each of those shapes under `output.structured`.
fn tool_lists() -> Vec<serde_json::Value> {
    vec![
        json!({"result": {"tools": [{"name": "read", "inputSchema": {"type": "object",
            "properties": {"path": {"type": "string"}}, "required": ["path"]}}]}}),
        json!({"result": {"tools": [{"name": "lookup", "inputSchema": {"type": "object",
            "properties": {
                "repo": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
                "limit": {"type": "number"},
                "mode": {"type": "string", "enum": ["fast", "full"]},
                "filter": {"type": "object", "properties": {"label": {"type": "string"}}}
            }, "required": ["repo"]}}]}}),
        json!({"result": {"tools": [{"name": "verify_identity",
            "inputSchema": {"type": "object", "properties": {"user_name": {"type": "string"}},
                "required": ["user_name"]},
            "outputSchema": {"type": "object", "properties": {"verified": {"type": "boolean"}},
                "required": ["verified"]}}]}}),
        json!({"result": {"tools": [{"name": "status",
        "inputSchema": {"type": "object", "properties": {}},
        "outputSchema": {"type": "object", "properties": {
            "state": {"type": "string", "enum": ["open", "closed"]},
            "count": {"type": "number"},
            "owner": {"type": "object", "properties": {"login": {"type": "string"}}},
            "labels": {"type": "array", "items": {"type": "string"}}
        }}}]}}),
    ]
}

#[test]
fn every_generated_tool_schema_composes_with_the_previous_release() {
    for tools in tool_lists() {
        let fragment =
            generate_mcp_schema("desk", &tools.to_string()).expect("the fragment generates");
        let composed = format!("{PREVIOUS_RELEASE}\n{fragment}");
        if let Err(error) = Schema::from_cedarschema_str(&composed) {
            panic!(
                "the previous release cannot read this generated schema, so a rollback would \
                 reset every per-tool rule's history: {error}\n{fragment}"
            );
        }
    }
}

#[test]
fn a_tool_budget_survives_a_restart_and_its_stored_schema_reads_under_the_previous_release() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("dogwood.redb");

    let first_run = desk(&history);
    assert!(reset(&first_run, "u"), "the first reset is in budget");
    assert!(!reset(&first_run, "v"), "the second reset is over budget");
    drop(first_run);

    if let Err(error) = stored_schema_under_the_previous_release(&history, "desk") {
        panic!(
            "the previous release drops desk's stored schema on start, so a rollback resets the \
             budget's history: {error}"
        );
    }

    let second_run = desk(&history);
    assert!(
        !reset(&second_run, "w"),
        "the reset from the first run still counts after a restart"
    );
}
