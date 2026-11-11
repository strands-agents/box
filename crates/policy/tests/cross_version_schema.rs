//! A generated MCP tool schema stays readable by the previous release.
//!
//! Each server's generated fragment is stored in the policy history, and every start validates it
//! again against that binary's own Box schema. A fragment that names a type only a newer Box schema
//! declares is dropped by the previous release on rollback, which removes every per-tool rule for
//! that server and resets its history. `fixtures/actions-v0.2.2.cedarschema` is the Box schema of
//! the release an operator can roll back to; refresh it when a release ships.

use cedar_policy::Schema;
use policy::generate_mcp_schema;
use serde_json::json;

const PREVIOUS_RELEASE: &str = include_str!("fixtures/actions-v0.2.2.cedarschema");

/// Tool lists covering each shape the generator renders: plain inputs, unions, numbers, enums,
/// nested objects, and a declared output.
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
