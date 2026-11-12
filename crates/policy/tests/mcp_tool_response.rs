//! A finished MCP tool call records the tool's own `::response`, with the input its request recorded.

use std::path::{Path, PathBuf};

use dogwood_local_engine::{DurableLog, Record};
use policy::{
    Decision, GovernedBox, McpReply, Outcome, PendingToolResponse, Policy, PolicyEngine,
    PolicyError, PolicyStagingError, Principal, Request, SchemaStage, generate_mcp_schema,
};
use serde_json::{Value, json};

const DESK_TOOLS: &str = r#"{"result": {"tools": [
    {"name": "verify_identity", "inputSchema": {"type": "object",
        "properties": {"user_name": {"type": "string"}}, "required": ["user_name"]}},
    {"name": "reset_password", "inputSchema": {"type": "object",
        "properties": {"user_name": {"type": "string"}}, "required": ["user_name"]}},
    {"name": "lookup", "inputSchema": {"type": "object",
        "properties": {"repo": {"anyOf": [{"type": "string"},
            {"type": "array", "items": {"type": "string"}}]}}, "required": ["repo"]}}
]}}"#;

const DESK_CALLS: &str = r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "desk" };
"#;

fn source(text: &str) -> Policy {
    Policy {
        origin: PathBuf::from("policy.dw"),
        text: text.to_string(),
    }
}

fn desk(policy: &str, history: &Path) -> PolicyEngine {
    let authority = PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        vec![source(&format!("{DESK_CALLS}{policy}"))],
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

/// One `tools/call` the way the broker runs it: the coarse gate, the per-tool gate, then both
/// response legs once the server replies.
fn call(authority: &PolicyEngine, tool: &str, arguments: Value) -> Decision {
    call_on(authority, "desk", tool, arguments)
}

/// [`call`] on any server.
fn call_on(authority: &PolicyEngine, server: &str, tool: &str, arguments: Value) -> Decision {
    call_ending(authority, server, tool, arguments, McpReply::Result)
}

/// [`call_on`], ending the way `reply` says.
fn call_ending(
    authority: &PolicyEngine,
    server: &str,
    tool: &str,
    arguments: Value,
    reply: McpReply,
) -> Decision {
    let governed = GovernedBox::assigned("test-box");
    let (decision, request_id) = authority.decide(
        &governed,
        &Principal::agent(),
        &Request::McpCall {
            server,
            method: "tools/call",
            tool: Some(tool),
            prompt: None,
            uri: None,
            arguments: None,
        },
    );
    if !decision.is_allow() {
        return decision;
    }
    let (refined, pending) =
        authority.refine_tool_call(&governed, &Principal::agent(), server, tool, &arguments);
    if !refined.is_allow() {
        assert!(pending.is_none(), "a refused call owes no response");
        return refined;
    }
    authority
        .record(
            &governed,
            &Principal::agent(),
            &request_id.expect("an allowed call has a request id"),
            &Outcome::Mcp {
                server,
                method: "tools/call",
                tool: Some(tool),
                prompt: None,
                uri: None,
            },
        )
        .expect("the coarse response records");
    if let Some(pending) = pending {
        authority
            .record_tool_response(pending, reply)
            .expect("the tool response records");
    }
    refined
}

/// Each recorded event as `(action, kind, input, requestId)`.
fn events(history: &Path) -> Vec<(String, String, String, String)> {
    let log = DurableLog::open(history).expect("the durable log opens");
    let mut out = Vec::new();
    log.scan_from(0, |_, bytes| {
        if let Record::Event(event) = Record::decode(bytes).expect("the record decodes") {
            let field = |name: &str| format!("{:?}", event.field_path(&[name.to_string()]));
            out.push((
                format!("{}::{}", event.namespace().join("::"), event.action()),
                event.kind().to_string(),
                field("input"),
                field("requestId"),
            ));
        }
    })
    .expect("the records scan");
    out
}

#[test]
fn a_finished_tool_call_records_the_tools_own_response_with_its_request_input() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("dogwood.redb");
    let authority = desk(
        r#"permit(principal, action == desk::Action::"verify_identity", resource);"#,
        &history,
    );
    assert!(call(&authority, "verify_identity", json!({ "user_name": "u" })).is_allow());
    drop(authority);

    let recorded = events(&history);
    let leg = |kind: &str| {
        recorded
            .iter()
            .find(|(action, event_kind, ..)| {
                action == "desk::Action::verify_identity" && event_kind == kind
            })
            .unwrap_or_else(|| panic!("no verify_identity::{kind} in {recorded:#?}"))
    };
    let (request, response) = (leg("request"), leg("response"));
    assert_eq!(
        response.2, request.2,
        "the response carries the request's input"
    );
    assert_eq!(
        response.3, request.3,
        "the response pairs with the per-tool request id"
    );
    assert!(
        recorded
            .iter()
            .any(|(action, kind, ..)| action == "Box::Action::mcp:call" && kind == "response"),
        "the coarse response is still recorded: {recorded:#?}"
    );
}

#[test]
fn a_union_argument_records_the_same_input_on_both_legs() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("dogwood.redb");
    let authority = desk(
        r#"permit(principal, action == desk::Action::"lookup", resource);"#,
        &history,
    );
    assert!(call(&authority, "lookup", json!({ "repo": ["a/b", "c/d"] })).is_allow());
    drop(authority);

    let recorded = events(&history);
    let inputs: Vec<&String> = recorded
        .iter()
        .filter(|(action, ..)| action == "desk::Action::lookup")
        .map(|(_, _, input, _)| input)
        .collect();
    assert_eq!(inputs.len(), 2, "{recorded:#?}");
    assert_eq!(inputs[0], inputs[1], "both legs carry the conformed input");
    assert!(inputs[0].contains("typeChoice"), "{}", inputs[0]);
}

#[test]
fn a_reset_follows_a_finished_verification_for_the_same_user_only() {
    let directory = tempfile::tempdir().expect("history directory");
    let authority = desk(
        r#"
permit(principal, action == desk::Action::"verify_identity", resource);
permit(principal, action == desk::Action::"reset_password", resource);
@id("reset_after_verify")
forbid(principal, action == desk::Action::"reset_password", resource)
unless temporal {
    formerly within 1h (
        desk::Action::"verify_identity"::response{ input.user_name: context.input.user_name }
    )
};
"#,
        &directory.path().join("dogwood.redb"),
    );
    assert!(
        !call(&authority, "reset_password", json!({ "user_name": "u" })).is_allow(),
        "no verification yet"
    );
    assert!(call(&authority, "verify_identity", json!({ "user_name": "u" })).is_allow());
    assert!(
        call(&authority, "reset_password", json!({ "user_name": "u" })).is_allow(),
        "a reset after a finished verification of the same user"
    );
    assert!(
        !call(
            &authority,
            "reset_password",
            json!({ "user_name": "other" })
        )
        .is_allow(),
        "a verification of one user does not allow another's reset"
    );
}

#[test]
fn a_refused_verification_does_not_satisfy_a_response_precondition() {
    let directory = tempfile::tempdir().expect("history directory");
    let authority = desk(
        r#"
permit(principal, action == desk::Action::"reset_password", resource);
forbid(principal, action == desk::Action::"verify_identity", resource);
forbid(principal, action == desk::Action::"reset_password", resource)
unless temporal {
    formerly within 1h (
        desk::Action::"verify_identity"::response{ input.user_name: context.input.user_name }
    )
};
"#,
        &directory.path().join("dogwood.redb"),
    );
    assert!(!call(&authority, "verify_identity", json!({ "user_name": "u" })).is_allow());
    assert!(
        !call(&authority, "reset_password", json!({ "user_name": "u" })).is_allow(),
        "asking and being refused is not a finished verification"
    );
}

#[test]
fn a_count_over_a_tools_response_caps_the_tool() {
    let directory = tempfile::tempdir().expect("history directory");
    let authority = desk(
        r#"
permit(principal, action == desk::Action::"reset_password", resource);
@id("one_reset")
forbid(principal, action == desk::Action::"reset_password", resource)
when temporal {
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (
                desk::Action::"reset_password"::response{ input.user_name: _ } && tp(t)
            )
        )) == total && total >= 1
    )
};
"#,
        &directory.path().join("dogwood.redb"),
    );
    assert!(call(&authority, "reset_password", json!({ "user_name": "u" })).is_allow());
    assert!(
        !call(&authority, "reset_password", json!({ "user_name": "v" })).is_allow(),
        "the second reset is over the cap"
    );
}

#[test]
fn a_tool_no_rule_declares_owes_no_tool_response() {
    let directory = tempfile::tempdir().expect("history directory");
    let authority = PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        vec![source(DESK_CALLS)],
        &directory.path().join("dogwood.redb"),
    )
    .expect("the policy opens");
    let (decision, pending): (Decision, Option<PendingToolResponse>) = authority.refine_tool_call(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        "desk",
        "verify_identity",
        &json!({ "user_name": "u" }),
    );
    assert!(
        decision.is_allow(),
        "an undeclared tool rides the coarse grant"
    );
    assert!(pending.is_none(), "no per-tool request was recorded");
}

#[test]
fn a_rule_on_an_mcp_error_is_refused_at_load() {
    for clause in [
        r#"desk::Action::"verify_identity"::error{ input.user_name: _ }"#,
        r#"Box::Action::"mcp:call"::error{ input.server: "desk" }"#,
    ] {
        let policy = format!(
            r#"{DESK_CALLS}
forbid(principal, action == Box::Action::"shell:exec", resource)
when temporal {{ formerly within 1h ( {clause} ) }};"#
        );
        let directory = tempfile::tempdir().expect("history directory");
        let refusal = PolicyEngine::open_staged(
            &policy::Operator::unanchored(),
            vec![source(&policy)],
            &directory.path().join("dogwood.redb"),
        )
        .map(|_| ())
        .expect_err("a rule on an MCP error cannot fire");
        assert!(
            matches!(
                refusal,
                PolicyStagingError::Policy(PolicyError::UnsupportedClause(_))
            ),
            "{clause}: {refusal}"
        );
        assert!(refusal.to_string().contains("::response"), "{refusal}");
        assert!(
            PolicyEngine::validate_staged(&[source(&policy)]).is_err(),
            "{clause}: the staged check refuses it too"
        );
    }
}

#[test]
fn a_rule_on_a_non_mcp_error_still_loads() {
    let directory = tempfile::tempdir().expect("history directory");
    PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        vec![source(
            r#"forbid(principal, action == Box::Action::"shell:exec", resource)
when temporal { formerly within 1h ( Box::Action::"http:request"::error{ input.host: _ } ) };"#,
        )],
        &directory.path().join("dogwood.redb"),
    )
    .map(|_| ())
    .expect("an http error is recorded, so the rule can fire");
}

#[test]
fn an_entity_shaped_argument_records_the_same_input_on_both_legs() {
    // An argument shaped like Cedar's `__entity` escape. The response must record the value the
    // request recorded, or a rule joining the two never matches.
    let entity_tool = |name: &str| {
        json!({"name": name, "inputSchema": {"type": "object",
            "properties": {"ref": {"type": "object", "properties": {"__entity": {"type": "object",
                "properties": {"type": {"type": "string"}, "id": {"type": "string"}},
                "required": ["type", "id"]}}, "required": ["__entity"]}},
            "required": ["ref"]}})
    };
    let tools = json!({"result": {"tools": [entity_tool("open"), entity_tool("close")]}});
    let directory = tempfile::tempdir().expect("history directory");
    let authority = PolicyEngine::open_with_mcp_schemas(
        vec![source(
            r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "refs" };
@id("close_needs_open")
forbid(principal, action == refs::Action::"close", resource)
unless temporal { formerly within 1h
  refs::Action::"open"::response{ input.ref.__entity.id: context.input.ref.__entity.id } };
"#,
        )],
        &[generate_mcp_schema("refs", &tools.to_string()).expect("the schema generates")],
        &directory.path().join("dogwood.redb"),
    )
    .expect("the policy opens");
    let arguments = json!({"ref": {"__entity": {"type": "Box::Resource", "id": "r1"}}});
    assert!(
        !call_on(&authority, "refs", "close", arguments.clone()).is_allow(),
        "a close with no open is refused"
    );
    assert!(call_on(&authority, "refs", "open", arguments.clone()).is_allow());
    assert!(
        call_on(&authority, "refs", "close", arguments).is_allow(),
        "the response records the argument as the request did, so the join matches"
    );
}

#[test]
fn a_call_that_ended_without_a_reply_does_not_satisfy_a_result_precondition() {
    let directory = tempfile::tempdir().expect("history directory");
    let authority = desk(
        r#"
permit(principal, action == desk::Action::"verify_identity", resource);
permit(principal, action == desk::Action::"reset_password", resource);
@id("reset_after_verify")
forbid(principal, action == desk::Action::"reset_password", resource)
unless temporal {
    formerly within 1h (
        desk::Action::"verify_identity"::response{
            input.user_name: context.input.user_name, output.reply: "result" }
    )
};
"#,
        &directory.path().join("dogwood.redb"),
    );
    assert!(
        call_ending(
            &authority,
            "desk",
            "verify_identity",
            json!({ "user_name": "u" }),
            McpReply::Cancelled
        )
        .is_allow()
    );
    assert!(
        !call(&authority, "reset_password", json!({ "user_name": "u" })).is_allow(),
        "a cancelled or uncertain verification is not an answered one"
    );
    assert!(call(&authority, "verify_identity", json!({ "user_name": "u" })).is_allow());
    assert!(
        call(&authority, "reset_password", json!({ "user_name": "u" })).is_allow(),
        "a verification the server answered allows the reset"
    );
}

#[test]
fn a_call_that_ended_without_a_reply_still_counts_toward_a_budget() {
    let directory = tempfile::tempdir().expect("history directory");
    let authority = desk(
        r#"
permit(principal, action == desk::Action::"reset_password", resource);
forbid(principal, action == desk::Action::"reset_password", resource)
when temporal {
    formerly within 1h ( desk::Action::"reset_password"::response{ input.user_name: _ } )
};
"#,
        &directory.path().join("dogwood.redb"),
    );
    assert!(
        call_ending(
            &authority,
            "desk",
            "reset_password",
            json!({ "user_name": "u" }),
            McpReply::Cancelled
        )
        .is_allow()
    );
    assert!(
        !call(&authority, "reset_password", json!({ "user_name": "v" })).is_allow(),
        "a cancelled reset still counts, so cancelling cannot escape the budget"
    );
}

#[test]
fn a_reply_frame_classifies_as_result_tool_error_or_protocol_error() {
    for (frame, reply) in [
        (
            json!({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}),
            McpReply::Result,
        ),
        (
            json!({"jsonrpc": "2.0", "id": 1, "result": {"content": [], "isError": false}}),
            McpReply::Result,
        ),
        (
            json!({"jsonrpc": "2.0", "id": 1, "result": {"content": [], "isError": true}}),
            McpReply::ToolError,
        ),
        (
            json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "x"}}),
            McpReply::ProtocolError,
        ),
        (json!({"jsonrpc": "2.0", "id": 1}), McpReply::Indeterminate),
        (
            json!({"jsonrpc": "2.0", "id": 1, "result": null}),
            McpReply::Indeterminate,
        ),
        (
            json!({"jsonrpc": "2.0", "id": 1, "result": "done"}),
            McpReply::Indeterminate,
        ),
        (
            json!({"jsonrpc": "2.0", "id": 1, "result": {"isError": "yes"}}),
            McpReply::Indeterminate,
        ),
    ] {
        assert_eq!(McpReply::of_reply(&frame), reply, "{frame}");
    }
}

#[test]
fn a_rule_on_an_output_reply_value_box_never_records_is_refused_at_load() {
    for (value, loads) in [("result", true), ("resutl", false)] {
        let policy = format!(
            r#"{DESK_CALLS}
forbid(principal, action == desk::Action::"reset_password", resource)
unless temporal {{ formerly within 1h ( desk::Action::"verify_identity"::response{{ output.reply: "{value}" }} ) }};"#
        );
        let directory = tempfile::tempdir().expect("history directory");
        let opened = PolicyEngine::open_staged(
            &policy::Operator::unanchored(),
            vec![source(&policy)],
            &directory.path().join("dogwood.redb"),
        );
        assert_eq!(opened.is_ok(), loads, "{value}");
        if !loads {
            let refusal = opened.map(|_| ()).unwrap_err().to_string();
            assert!(
                refusal.contains("resutl") && refusal.contains("\"result\""),
                "{refusal}"
            );
        }
    }
}
