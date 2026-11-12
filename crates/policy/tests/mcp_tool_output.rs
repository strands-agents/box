//! A tool's declared `structuredContent` is recorded as `output.structured` on its
//! own `::response`, so a precondition can require what the tool answered.

use std::path::{Path, PathBuf};

use dogwood_local_engine::{DurableLog, Record};
use policy::{
    Decision, GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request, SchemaStage,
    generate_mcp_schema,
};
use serde_json::{Value, json};

const DESK_TOOLS: &str = r#"{"result": {"tools": [
    {"name": "verify_identity", "inputSchema": {"type": "object",
        "properties": {"user_name": {"type": "string"}}, "required": ["user_name"]},
     "outputSchema": {"type": "object",
        "properties": {"verified": {"type": "boolean"}, "method": {"type": "string"},
                       "score": {"type": "number"},
                       "ref": {"anyOf": [{"type": "string"}, {"type": "integer"}]}},
        "required": ["verified"]}},
    {"name": "reset_password", "inputSchema": {"type": "object",
        "properties": {"user_name": {"type": "string"}}, "required": ["user_name"]}}
]}}"#;

const DESK_CALLS: &str = r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "desk" };
permit(principal, action == desk::Action::"verify_identity", resource);
"#;

const VERIFIED_BEFORE_RESET: &str = r#"
permit(principal, action == desk::Action::"reset_password", resource);
forbid (principal, action == desk::Action::"reset_password", resource)
unless temporal {
  formerly within 3600s (desk::Action::"verify_identity"::response{
    input.user_name: context.input.user_name,
    output.reply: "result",
    output.structured.verified: true })
};
"#;

fn desk(policy: &str, history: &Path) -> PolicyEngine {
    let authority = PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        vec![Policy {
            origin: PathBuf::from("policy.dw"),
            text: format!("{DESK_CALLS}{policy}"),
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

/// One `tools/call` the way the stdio broker runs it, ending with `reply` as the server's frame.
fn call(authority: &PolicyEngine, tool: &str, arguments: Value, reply: &Value) -> Decision {
    let governed = GovernedBox::assigned("test-box");
    let (decision, request_id) = authority.decide(
        &governed,
        &Principal::agent(),
        &Request::McpCall {
            server: "desk",
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
        authority.refine_tool_call(&governed, &Principal::agent(), "desk", tool, &arguments);
    if !refined.is_allow() {
        return refined;
    }
    authority
        .record(
            &governed,
            &Principal::agent(),
            &request_id.expect("an allowed call has a request id"),
            &Outcome::Mcp {
                server: "desk",
                method: "tools/call",
                tool: Some(tool),
                prompt: None,
                uri: None,
            },
        )
        .expect("the coarse response records");
    if let Some(pending) = pending {
        authority
            .record_tool_reply(pending, reply)
            .expect("the tool response records");
    }
    refined
}

fn result(structured: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "result": {
        "content": [{"type": "text", "text": structured.to_string()}],
        "structuredContent": structured }})
}

/// The `output` each `verify_identity::response` recorded, as Debug text.
fn outputs(history: &Path) -> Vec<String> {
    let log = DurableLog::open(history).expect("the durable log opens");
    let mut out = Vec::new();
    log.scan_from(0, |_, bytes| {
        if let Record::Event(event) = Record::decode(bytes).expect("the record decodes")
            && event.action() == "verify_identity"
            && event.kind() == "response"
        {
            out.push(format!("{:?}", event.field_path(&["output".to_string()])));
        }
    })
    .expect("the records scan");
    out
}

#[test]
fn the_generated_schema_declares_structured_output_only_for_tools_with_an_output_schema() {
    let schema = generate_mcp_schema("desk", DESK_TOOLS).expect("the schema generates");
    println!("{schema}");
    assert!(schema.contains("structured"), "{schema}");
    assert!(schema.contains("verify_identityOutput"), "{schema}");
}

#[test]
fn a_rule_on_output_structured_loads_and_a_misspelled_field_is_refused() {
    let directory = tempfile::tempdir().expect("history directory");
    let _authority = desk(VERIFIED_BEFORE_RESET, &directory.path().join("a.redb"));
    let misspelled = VERIFIED_BEFORE_RESET.replace("structured.verified", "structured.verifed");
    let refused = PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        vec![Policy {
            origin: PathBuf::from("policy.dw"),
            text: format!("{DESK_CALLS}{misspelled}"),
        }],
        &directory.path().join("b.redb"),
    )
    .expect("the staged policy opens")
    .stage_mcp_schema(
        "desk",
        generate_mcp_schema("desk", DESK_TOOLS).expect("the desk schema generates"),
    );
    assert!(
        !matches!(
            refused,
            Ok(SchemaStage::Accepted {
                authority_ready: true
            })
        ),
        "a rule on an undeclared output field is refused: {refused:?}"
    );
}

#[test]
fn a_reset_needs_a_verification_that_answered_verified() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("dogwood.redb");
    let authority = desk(VERIFIED_BEFORE_RESET, &history);
    let user = json!({"user_name": "u"});
    let ok = json!({"jsonrpc": "2.0", "id": 9, "result": {}});

    assert!(
        !call(&authority, "reset_password", user.clone(), &ok).is_allow(),
        "no verification yet"
    );
    assert!(
        call(
            &authority,
            "verify_identity",
            user.clone(),
            &result(json!({"verified": false}))
        )
        .is_allow()
    );
    assert!(
        !call(&authority, "reset_password", user.clone(), &ok).is_allow(),
        "a verification that answered false does not satisfy it"
    );
    assert!(
        call(
            &authority,
            "verify_identity",
            json!({"user_name": "other"}),
            &result(json!({"verified": true}))
        )
        .is_allow()
    );
    assert!(
        !call(&authority, "reset_password", user.clone(), &ok).is_allow(),
        "another user's verification does not satisfy it"
    );
    assert!(
        call(
            &authority,
            "verify_identity",
            user.clone(),
            &result(json!({"verified": true, "method": "sms", "secret": "dropped"}))
        )
        .is_allow()
    );
    assert!(
        call(&authority, "reset_password", user, &ok).is_allow(),
        "a verification that answered true satisfies it"
    );
    drop(authority);
    let recorded = outputs(&history);
    assert_eq!(recorded.len(), 3, "{recorded:#?}");
    assert!(recorded[2].contains("sms"), "{}", recorded[2]);
    assert!(
        !recorded[2].contains("dropped"),
        "an undeclared field is not recorded: {}",
        recorded[2]
    );
}

#[test]
fn an_error_result_or_a_nonconforming_output_records_only_the_reply() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("dogwood.redb");
    let authority = desk(VERIFIED_BEFORE_RESET, &history);
    let user = json!({"user_name": "u"});
    let ok = json!({"jsonrpc": "2.0", "id": 9, "result": {}});
    let mut tool_error = result(json!({"verified": true}));
    tool_error["result"]["isError"] = json!(true);
    for reply in [
        tool_error,
        result(json!({"verified": "yes"})),
        result(json!({"method": "sms"})),
        result(json!({"verified": true, "method": "x".repeat(20 * 1024)})),
    ] {
        assert!(call(&authority, "verify_identity", user.clone(), &reply).is_allow());
        assert!(
            !call(&authority, "reset_password", user.clone(), &ok).is_allow(),
            "{reply}"
        );
    }
    drop(authority);
    let recorded = outputs(&history);
    assert_eq!(recorded.len(), 4, "{recorded:#?}");
    for output in &recorded {
        assert!(!output.contains("structured"), "{output}");
        assert!(output.contains("reply"), "{output}");
    }
}

#[test]
fn a_union_and_a_number_output_are_converted_like_inputs() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("dogwood.redb");
    let authority = desk(
        r#"
permit(principal, action == desk::Action::"reset_password", resource);
forbid (principal, action == desk::Action::"reset_password", resource)
unless temporal {
  formerly within 3600s (desk::Action::"verify_identity"::response{
    output.structured.score: 7 })
};
"#,
        &history,
    );
    let user = json!({"user_name": "u"});
    let ok = json!({"jsonrpc": "2.0", "id": 9, "result": {}});
    assert!(
        call(
            &authority,
            "verify_identity",
            user.clone(),
            &result(json!({"verified": true, "score": 7, "ref": 12}))
        )
        .is_allow()
    );
    assert!(call(&authority, "reset_password", user, &ok).is_allow());
    drop(authority);
    let recorded = outputs(&history);
    assert!(recorded[0].contains("typeChoice"), "{}", recorded[0]);
}

/// Probe: a nested object, an array of objects, and a `$defs` reference in an `outputSchema`
/// generate, stage, and a rule can read the nested field.
#[test]
fn a_nested_output_schema_generates_and_a_rule_reads_a_nested_field() {
    const NESTED: &str = r##"{"result": {"tools": [
        {"name": "lookup", "inputSchema": {"type": "object", "properties": {}},
         "outputSchema": {"type": "object",
            "properties": {
                "user": {"type": "object", "properties": {
                    "name": {"type": "string"}, "active": {"type": "boolean"}},
                    "required": ["name"]},
                "groups": {"type": "array", "items": {"$ref": "#/$defs/group"}}},
            "required": ["user"],
            "$defs": {"group": {"type": "object", "properties": {"id": {"type": "string"}}}}}}
    ]}}"##;
    let schema = generate_mcp_schema("desk", NESTED).expect("the nested schema generates");
    println!("{schema}");
    let directory = tempfile::tempdir().expect("history directory");
    let authority = PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        vec![Policy {
            origin: PathBuf::from("policy.dw"),
            text: r#"
permit(principal, action == Box::Action::"mcp:call", resource);
permit(principal, action == desk::Action::"lookup", resource);
forbid(principal, action == desk::Action::"lookup", resource)
when temporal { formerly within 3600s (desk::Action::"lookup"::response{
  output.structured.user.active: true }) };
"#
            .to_string(),
        }],
        &directory.path().join("h.redb"),
    )
    .expect("the policy opens");
    assert_eq!(
        authority
            .stage_mcp_schema("desk", schema)
            .expect("desk's schema stages"),
        SchemaStage::Accepted {
            authority_ready: true
        }
    );
    let reply = |active: bool| {
        result(json!({"user": {"name": "n", "active": active, "extra": 1},
                      "groups": [{"id": "g", "x": 2}]}))
    };
    assert!(call(&authority, "lookup", json!({}), &reply(false)).is_allow());
    assert!(call(&authority, "lookup", json!({}), &reply(true)).is_allow());
    assert!(
        !call(&authority, "lookup", json!({}), &reply(true)).is_allow(),
        "a recorded nested user.active = true fires the forbid"
    );
}
