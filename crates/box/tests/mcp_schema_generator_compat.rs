use cedar_policy::{
    Context, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode, Validator,
};
use policy::{generate_mcp_schema, validate_mcp_schema_composition};

const ACTION: &str = r#"issues_mcp::Action::"read_wiki""#;
const GLOBAL_ENTITIES: &str = "namespace Box { entity Agent; entity Resource; }";

const TOOLS: &str = r#"
{
    "result": {
        "tools": [{
            "name": "read_wiki",
            "description": "Read one wiki page",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "page": {"type": "string"},
                    "revision": {"type": "integer"}
                },
                "required": ["page"]
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "body": {"type": "string"}
                },
                "required": ["body"]
            }
        }]
    }
}
"#;

#[test]
fn crates_io_generator_composes_with_box_and_preserves_closed_context() {
    let generated =
        generate_mcp_schema("issues-mcp", TOOLS).expect("compatible generator interface");

    assert!(generated.contains("namespace issues_mcp {"));
    assert_eq!(generated.matches("namespace ").count(), 1);
    assert!(!generated.contains("entity Agent"));
    assert!(!generated.contains("entity Resource"));
    assert!(generated.contains(r#"action "read_wiki" appliesTo"#));
    assert!(generated.contains("type read_wikiInput ="));
    assert!(generated.contains("input: read_wikiInput"));
    assert!(generated.contains("principal: [Box::Agent]"));
    assert!(generated.contains("resource: [Box::Resource]"));
    assert!(generated.contains("page: String"));
    assert!(generated.contains("revision?: Long"));
    assert!(!generated.contains(r#""output""#));
    assert!(!generated.contains("McpTool_"));
    assert!(!generated.contains("McpType_"));

    validate_mcp_schema_composition(&[("issues-mcp", &generated)])
        .expect("schema composes with Box");
    let schema_source = format!("{GLOBAL_ENTITIES}\n{generated}");
    let (schema, warnings) =
        Schema::from_cedarschema_str(&schema_source).expect("generated schema");
    assert_eq!(warnings.count(), 0);

    let policies: PolicySet = format!(
        r#"permit (
            principal == Box::Agent::"self",
            action == {ACTION},
            resource == Box::Resource::"unused"
        ) when {{
            context.input.page == "Policies"
        }};"#
    )
    .parse()
    .expect("valid policy");
    let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
    assert!(
        validation.validation_passed(),
        "strict validation failed: {validation:?}"
    );

    let principal: EntityUid = r#"Box::Agent::"self""#.parse().expect("principal");
    let action: EntityUid = ACTION.parse().expect("action");
    let resource: EntityUid = r#"Box::Resource::"unused""#.parse().expect("resource");
    let context =
        Context::from_json_str(r#"{"input":{"page":"Policies"}}"#, Some((&schema, &action)))
            .expect("conforming context");
    let request = Request::new(principal, action.clone(), resource, context, Some(&schema))
        .expect("schema-bound request");
    let response =
        cedar_policy::Authorizer::new().is_authorized(&request, &policies, &Entities::empty());
    assert_eq!(response.decision(), cedar_policy::Decision::Allow);

    let extra = Context::from_json_str(
        r#"{"input":{"page":"Policies","unexpected":true}}"#,
        Some((&schema, &action)),
    );
    assert!(
        extra.is_err(),
        "Cedar 4.11.0 must reject an input field absent from the generated schema"
    );
}
