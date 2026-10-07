//! Pure MCP tools/list to Cedar schema generation and composition validation.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

use cedar_policy::{Schema, SchemaFragment};
use cedar_policy_mcp_schema_generator::{SchemaGenerator, SchemaGeneratorConfig};
use mcp_tools_sdk::description::{ServerDescription, ToolDescription};

use crate::schema::{SCHEMA_SRC, cedar_identifier, mcp_action_namespace};

const SCHEMA_STUB: &str = include_str!("../schema/mcp.cedarschema");
const SCHEMA_STUB_NAMESPACE: &str = "Server";

#[derive(Debug)]
struct GeneratedShape {
    namespaces: Vec<Option<String>>,
    box_entity_declarations: usize,
    has_grouped_action: bool,
    action_declarations: usize,
}

/// A generated MCP schema could not be rendered or composed.
#[derive(Debug, thiserror::Error)]
pub enum McpSchemaError {
    /// The tools/list response is not a valid server description.
    #[error("cannot parse the tools from MCP server {server:?}: {reason}")]
    Description {
        /// The declared server name.
        server: String,
        /// The parser's refusal.
        reason: String,
    },

    /// The schema generator refused the server description.
    #[error("cannot generate the Cedar schema for MCP server {server:?}: {reason}")]
    Generate {
        /// The declared server name.
        server: String,
        /// The generator's refusal.
        reason: String,
    },

    /// The generated schema does not have the required shape.
    #[error("cannot use the Cedar schema for MCP server {server:?}: {reason}")]
    GeneratedShape {
        /// The declared server name.
        server: String,
        /// The shape requirement that failed.
        reason: &'static str,
    },

    /// The generated schema cannot be rendered as Cedar schema text.
    #[error("cannot render the Cedar schema for MCP server {server:?}: {reason}")]
    Render {
        /// The declared server name.
        server: String,
        /// The renderer's refusal.
        reason: String,
    },

    /// The generated schemas do not compose with the canonical policy schema.
    #[error("generated MCP schemas do not compose with the Box schema: {reason}")]
    Composition {
        /// The composition refusal.
        reason: String,
    },

    /// Two server names normalize to the same Cedar namespace.
    #[error(
        "MCP servers {first:?} and {second:?} normalize to the same Cedar namespace {namespace:?}"
    )]
    NamespaceCollision {
        /// The first server that uses the namespace.
        first: String,
        /// The second server that uses the namespace.
        second: String,
        /// The colliding Cedar namespace.
        namespace: String,
    },

    /// Two tool names normalize to the same Cedar identifier.
    #[error(
        "MCP tools {first:?} and {second:?} from server {server:?} normalize to the same Cedar identifier {identifier:?}"
    )]
    ToolNameCollision {
        /// The declared server name.
        server: String,
        /// The first tool that uses the identifier.
        first: String,
        /// The second tool that uses the identifier.
        second: String,
        /// The colliding Cedar identifier.
        identifier: String,
    },
}

/// Generate one Cedar schema from an MCP server's raw tools/list response.
pub fn generate_mcp_schema(server: &str, tools_list: &str) -> Result<String, McpSchemaError> {
    refuse_reserved_namespace(server)?;
    refuse_duplicate_tool_names(server, tools_list)?;
    // Lower each tool argument to a base Cedar type before generation, so a rule reads the
    // workload's bare value directly. The generator otherwise maps a JSON `enum` to a Cedar enum
    // *entity* and a JSON `number` to an opaque `Number` entity — neither of which the raw value a
    // tool call carries can satisfy, so the request fails schema conformance. See `lower_arg_types`.
    let compatible_tools_list = make_unsupported_schema_references_opaque(tools_list);
    let tools_list = lower_arg_types(&compatible_tools_list);
    let description = ServerDescription::from_json_str(&tools_list).map_err(|source| {
        McpSchemaError::Description {
            server: server.to_string(),
            reason: source.to_string(),
        }
    })?;
    let (description, action_names) = namespaced_description(server, &description)?;
    let server_namespace = mcp_action_namespace(server);
    let schema_stub = SCHEMA_STUB.replace(SCHEMA_STUB_NAMESPACE, &server_namespace);
    let config = SchemaGeneratorConfig::default()
        .objects_as_records(true)
        .flatten_namespaces(true);
    let mut generator = SchemaGenerator::from_cedarschema_str_with_config(&schema_stub, config)
        .map_err(|source| McpSchemaError::Generate {
            server: server.to_string(),
            reason: source.to_string(),
        })?;
    generator
        .add_actions_from_server_description(&description)
        .map_err(|source| McpSchemaError::Generate {
            server: server.to_string(),
            reason: source.to_string(),
        })?;

    let mut fragment = generator.get_schema().clone();
    let box_entity_declarations = fragment
        .0
        .iter()
        .find(|(name, _)| {
            name.as_ref()
                .is_some_and(|name| name.to_string() == server_namespace)
        })
        .map(|(_, definition)| {
            definition
                .entity_types
                .keys()
                .filter(|name| matches!(name.to_string().as_str(), "Agent" | "Resource"))
                .count()
        })
        .unwrap_or_default();
    let generator_shape = GeneratedShape {
        namespaces: fragment
            .0
            .keys()
            .map(|namespace| namespace.as_ref().map(ToString::to_string))
            .collect(),
        box_entity_declarations,
        has_grouped_action: fragment.0.values().any(|definition| {
            definition.actions.values().any(|action| {
                action
                    .member_of
                    .as_ref()
                    .is_some_and(|parents| !parents.is_empty())
            })
        }),
        action_declarations: 0,
    };
    validate_generator_shape(server, &generator_shape, &server_namespace)?;

    let action_count = action_names.len();
    {
        let definition = fragment
            .0
            .iter_mut()
            .find_map(|(name, definition)| {
                name.as_ref()
                    .is_some_and(|name| name.to_string() == server_namespace)
                    .then_some(definition)
            })
            .ok_or_else(|| McpSchemaError::GeneratedShape {
                server: server.to_string(),
                reason: "the generated namespace disappeared",
            })?;
        definition
            .entity_types
            .retain(|name, _| !matches!(name.to_string().as_str(), "Agent" | "Resource"));
        for (generated_name, action_name) in action_names {
            let action = definition
                .actions
                .remove(generated_name.as_str())
                .ok_or_else(|| McpSchemaError::GeneratedShape {
                    server: server.to_string(),
                    reason: "a generated MCP action disappeared before it was named",
                })?;
            if definition
                .actions
                .insert(action_name.into(), action)
                .is_some()
            {
                return Err(McpSchemaError::GeneratedShape {
                    server: server.to_string(),
                    reason: "two generated MCP actions have the same identity",
                });
            }
        }
        let mut definition_value =
            serde_json::to_value(&*definition).map_err(|_| McpSchemaError::GeneratedShape {
                server: server.to_string(),
                reason: "the generated namespace could not be converted",
            })?;
        repair_nested_namespace_flattening(&mut definition_value, &server_namespace).map_err(
            |reason| McpSchemaError::GeneratedShape {
                server: server.to_string(),
                reason,
            },
        )?;
        refuse_action_type_collision(&definition_value).map_err(|reason| {
            McpSchemaError::GeneratedShape {
                server: server.to_string(),
                reason,
            }
        })?;
        use_box_entities(&mut definition_value, &server_namespace);
        *definition = serde_json::from_value(definition_value).map_err(|_| {
            McpSchemaError::GeneratedShape {
                server: server.to_string(),
                reason: "the converted namespace could not be read",
            }
        })?;
    }
    let shape = GeneratedShape {
        namespaces: fragment
            .0
            .keys()
            .map(|namespace| namespace.as_ref().map(ToString::to_string))
            .collect(),
        box_entity_declarations,
        has_grouped_action: fragment.0.values().any(|definition| {
            definition.actions.values().any(|action| {
                action
                    .member_of
                    .as_ref()
                    .is_some_and(|parents| !parents.is_empty())
            })
        }),
        action_declarations: fragment
            .0
            .iter()
            .find(|(name, _)| {
                name.as_ref()
                    .is_some_and(|name| name.to_string() == server_namespace)
            })
            .map(|(_, definition)| definition.actions.len())
            .unwrap_or_default(),
    };
    validate_generated_shape(server, &shape, &server_namespace, action_count)?;
    fragment
        .to_cedarschema()
        .map_err(|source| McpSchemaError::Render {
            server: server.to_string(),
            reason: source.to_string(),
        })
}

fn validate_generator_shape(
    server: &str,
    shape: &GeneratedShape,
    expected_namespace: &str,
) -> Result<(), McpSchemaError> {
    if shape.namespaces.is_empty() {
        return Err(McpSchemaError::GeneratedShape {
            server: server.to_string(),
            reason: "the generator returned no namespace",
        });
    }
    let child_prefix = format!("{expected_namespace}::");
    for namespace in &shape.namespaces {
        let Some(namespace) = namespace else {
            return Err(McpSchemaError::GeneratedShape {
                server: server.to_string(),
                reason: "the generator returned a global namespace",
            });
        };
        if namespace != expected_namespace && !namespace.starts_with(&child_prefix) {
            return Err(McpSchemaError::GeneratedShape {
                server: server.to_string(),
                reason: "the generator returned an unexpected namespace",
            });
        }
    }
    if shape.has_grouped_action {
        return Err(McpSchemaError::GeneratedShape {
            server: server.to_string(),
            reason: "a generated MCP action belongs to an action group",
        });
    }
    if shape.box_entity_declarations != 2 {
        return Err(McpSchemaError::GeneratedShape {
            server: server.to_string(),
            reason: "the generated schema did not contain the Agent and Resource declarations",
        });
    }
    Ok(())
}

fn validate_generated_shape(
    server: &str,
    shape: &GeneratedShape,
    expected_namespace: &str,
    expected_action_count: usize,
) -> Result<(), McpSchemaError> {
    let namespaces = shape.namespaces.iter().cloned().collect::<BTreeSet<_>>();
    let expected = [Some(expected_namespace.to_string())]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if namespaces != expected {
        return Err(McpSchemaError::GeneratedShape {
            server: server.to_string(),
            reason: "the generated schema did not contain exactly one server namespace",
        });
    }
    if shape.action_declarations != expected_action_count {
        return Err(McpSchemaError::GeneratedShape {
            server: server.to_string(),
            reason: "the generated action count did not match the unique tool count",
        });
    }
    Ok(())
}

/// Validate that named generated schemas compose with the canonical policy schema.
pub fn validate_mcp_schema_composition(generated: &[(&str, &str)]) -> Result<(), McpSchemaError> {
    let mut fragments = Vec::with_capacity(generated.len() + 1);
    let mut warnings = 0;
    let (canonical, canonical_warnings) = SchemaFragment::from_cedarschema_str(SCHEMA_SRC)
        .map_err(|source| McpSchemaError::Composition {
            reason: source.to_string(),
        })?;
    warnings += canonical_warnings.count();
    fragments.push(canonical);

    let mut namespaces = BTreeMap::new();
    for (server, source) in generated {
        let namespace = mcp_action_namespace(server);
        if let Some(first) = namespaces.insert(namespace.clone(), (*server).to_string()) {
            return Err(McpSchemaError::NamespaceCollision {
                first,
                second: (*server).to_string(),
                namespace,
            });
        }
        validate_bound_mcp_schema(server, source)?;
        let (fragment, fragment_warnings) =
            SchemaFragment::from_cedarschema_str(source).map_err(|source| {
                McpSchemaError::Composition {
                    reason: source.to_string(),
                }
            })?;
        warnings += fragment_warnings.count();
        fragments.push(fragment);
    }
    if warnings != 0 {
        return Err(McpSchemaError::Composition {
            reason: format!("Cedar reported {warnings} schema warnings"),
        });
    }
    Schema::from_schema_fragments(fragments).map_err(|source| McpSchemaError::Composition {
        reason: source.to_string(),
    })?;
    Ok(())
}

pub(crate) fn validate_unbound_mcp_schema(source: &str) -> Result<(), McpSchemaError> {
    validate_mcp_schema_namespaces(None, source)
}

fn validate_bound_mcp_schema(server: &str, source: &str) -> Result<(), McpSchemaError> {
    validate_mcp_schema_namespaces(Some(server), source)
}

fn validate_mcp_schema_namespaces(
    server: Option<&str>,
    source: &str,
) -> Result<(), McpSchemaError> {
    let (fragment, warnings) = SchemaFragment::from_cedarschema_str(source).map_err(|error| {
        McpSchemaError::Composition {
            reason: error.to_string(),
        }
    })?;
    let warning_count = warnings.count();
    if warning_count != 0 {
        return Err(McpSchemaError::Composition {
            reason: format!("Cedar reported {warning_count} schema warnings"),
        });
    }
    let json = fragment
        .clone()
        .to_json_value()
        .map_err(|error| McpSchemaError::Composition {
            reason: error.to_string(),
        })?;
    let definitions = json
        .as_object()
        .ok_or_else(|| McpSchemaError::Composition {
            reason: "an MCP schema fragment was not an object".to_string(),
        })?;
    if definitions.len() != 1 || definitions.contains_key("") {
        return Err(McpSchemaError::Composition {
            reason: "an MCP schema fragment must contain one server namespace".to_string(),
        });
    }

    let namespace = definitions
        .keys()
        .next()
        .expect("the length check found one namespace");
    if namespace == "Box" {
        return Err(McpSchemaError::Composition {
            reason: "the Box namespace is reserved for the canonical policy schema".to_string(),
        });
    }
    if let Some(server) = server {
        let expected = mcp_action_namespace(server);
        if namespace != &expected {
            return Err(McpSchemaError::Composition {
                reason: format!(
                    "MCP server {server:?} requires namespace {expected:?}, found {namespace:?}"
                ),
            });
        }
    }

    let definition = definitions
        .get(namespace)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| McpSchemaError::Composition {
            reason: "the MCP server namespace was not a schema definition".to_string(),
        })?;
    let generated_entities = definition
        .get("entityTypes")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(serde_json::Map::keys);
    if generated_entities
        .into_iter()
        .any(|name| matches!(name.as_str(), "Agent" | "Resource"))
    {
        return Err(McpSchemaError::Composition {
            reason: "the MCP server namespace redeclares a Box entity".to_string(),
        });
    }
    if definition
        .get("actions")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(serde_json::Map::values)
        .any(|action| {
            !action_applies_to(action, "principalTypes", "Box::Agent")
                || !action_applies_to(action, "resourceTypes", "Box::Resource")
        })
    {
        return Err(McpSchemaError::Composition {
            reason: "an MCP action does not apply to the Box principal and resource".to_string(),
        });
    }

    let complete = format!("{SCHEMA_SRC}\n{source}");
    let (schema, warnings) =
        Schema::from_cedarschema_str(&complete).map_err(|error| McpSchemaError::Composition {
            reason: error.to_string(),
        })?;
    let warning_count = warnings.count();
    if warning_count != 0 {
        return Err(McpSchemaError::Composition {
            reason: format!("Cedar reported {warning_count} schema warnings"),
        });
    }
    let expected_action_type = format!("{namespace}::Action");
    if schema.actions().any(|action| {
        action.type_name().namespace_components().next().is_some()
            && action.type_name().to_string() != "Box::Action"
            && action.type_name().to_string() != expected_action_type
    }) {
        return Err(McpSchemaError::Composition {
            reason: "an MCP schema fragment declares an action outside its server namespace"
                .to_string(),
        });
    }
    if schema
        .action_groups()
        .any(|action| action.type_name().to_string() != "Box::Action")
    {
        return Err(McpSchemaError::Composition {
            reason: "an MCP schema fragment declares an action group".to_string(),
        });
    }
    Ok(())
}

fn action_applies_to(action: &serde_json::Value, field: &str, expected: &str) -> bool {
    action
        .get("appliesTo")
        .and_then(|applies_to| applies_to.get(field))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|types| {
            types.len() == 1 && types.first().and_then(serde_json::Value::as_str) == Some(expected)
        })
}

/// Lower every argument in a `tools/list` response to a base Cedar type: drop each `enum`
/// constraint (the field keeps its declared `type`, so the generator emits `String`/`Long`/`Bool`
/// instead of an enum entity) and rewrite `number`/`float` to `integer` (Cedar has no float, and
/// `decimal` needs a wrapped form, so an integer-valued number maps to `Long`; a fractional value
/// then fails conformance, which is rare). The bare value a tool call carries then conforms, and a
/// rule reads it as a plain value (`context.input.state == "open"`). Returns the original text
/// unchanged when it does not parse, so the generator surfaces the parse error.
fn lower_arg_types(tools_list: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(tools_list) else {
        return tools_list.to_string();
    };
    lower_schema_node(&mut value);
    value.to_string()
}

/// Recursively lower schema nodes: remove `enum`, and lower each `type` to base types.
fn lower_schema_node(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.remove("enum");
            if let Some(ty) = map.get("type").and_then(lower_type) {
                map.insert("type".to_string(), ty);
            }
            for child in map.values_mut() {
                lower_schema_node(child);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                lower_schema_node(child);
            }
        }
        _ => {}
    }
}

/// Lower a JSON Schema `type`, returning the replacement or `None` when it needs none. A
/// `number`/`float` becomes `integer` (→ Cedar `Long`). A `type` **array** (a union, or the common
/// `["X","null"]` nullable form) drops `null` and lowers each member; if one distinct member
/// remains it collapses to that scalar, so a nullable field becomes a plain type. A genuine
/// multi-member union stays an array — the generator renders it as a `typeChoice` record, which a
/// bare value still cannot satisfy (a residual, like a standalone `null`).
fn lower_type(ty: &serde_json::Value) -> Option<serde_json::Value> {
    fn lower_scalar(kind: &str) -> &str {
        if kind == "number" || kind == "float" {
            "integer"
        } else {
            kind
        }
    }
    match ty {
        serde_json::Value::String(kind) if kind == "number" || kind == "float" => {
            Some(serde_json::Value::String("integer".to_string()))
        }
        serde_json::Value::Array(kinds) => {
            let mut distinct: Vec<String> = Vec::new();
            for kind in kinds {
                let Some(kind) = kind.as_str() else { continue };
                if kind == "null" {
                    continue;
                }
                let kind = lower_scalar(kind).to_string();
                if !distinct.contains(&kind) {
                    distinct.push(kind);
                }
            }
            Some(if distinct.len() == 1 {
                serde_json::Value::String(distinct.pop().unwrap_or_default())
            } else {
                serde_json::Value::Array(
                    distinct
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                )
            })
        }
        _ => None,
    }
}

/// Compose the canonical action schema with ordered generated MCP schemas.
pub fn compose_action_schema(generated: &[(&str, &str)]) -> Result<String, McpSchemaError> {
    validate_mcp_schema_composition(generated)?;
    let fragments = generated
        .iter()
        .map(|(_, source)| (*source).to_string())
        .collect::<Vec<_>>();
    crate::schema::action_schema(&fragments)
        .map(|schema| schema.source)
        .map_err(|source| McpSchemaError::Composition {
            reason: source.to_string(),
        })
}

fn make_unsupported_schema_references_opaque(tools_list: &str) -> Cow<'_, str> {
    let Ok(mut response) = serde_json::from_str::<serde_json::Value>(tools_list) else {
        return Cow::Borrowed(tools_list);
    };
    if !make_unsupported_schema_references_opaque_in(&mut response) {
        return Cow::Borrowed(tools_list);
    }
    Cow::Owned(response.to_string())
}

fn make_unsupported_schema_references_opaque_in(value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            if object
                .get("$ref")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|reference| !reference.starts_with("#/$defs/"))
            {
                object.clear();
                return true;
            }
            let mut changed = false;
            for child in object.values_mut() {
                changed |= make_unsupported_schema_references_opaque_in(child);
            }
            changed
        }
        serde_json::Value::Array(values) => {
            let mut changed = false;
            for child in values {
                changed |= make_unsupported_schema_references_opaque_in(child);
            }
            changed
        }
        _ => false,
    }
}

fn refuse_duplicate_tool_names(server: &str, tools_list: &str) -> Result<(), McpSchemaError> {
    let Ok(response) = serde_json::from_str::<serde_json::Value>(tools_list) else {
        return Ok(());
    };
    let Some(tools) = response
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(());
    };
    let mut names = BTreeSet::new();
    for tool in tools {
        let Some(name) = tool.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !names.insert(name) {
            return Err(McpSchemaError::GeneratedShape {
                server: server.to_string(),
                reason: "two generated MCP actions have the same identity",
            });
        }
    }
    Ok(())
}

fn refuse_reserved_namespace(server: &str) -> Result<(), McpSchemaError> {
    if mcp_action_namespace(server) == "Box" {
        return Err(McpSchemaError::GeneratedShape {
            server: server.to_string(),
            reason: "the normalized server namespace is reserved for the Box schema",
        });
    }
    Ok(())
}

fn namespaced_description(
    server: &str,
    description: &ServerDescription,
) -> Result<(ServerDescription, BTreeMap<String, String>), McpSchemaError> {
    let mut source_tools = description.tool_descriptions().collect::<Vec<_>>();
    source_tools.sort_by_key(|tool| tool.name());
    let mut normalized_tools = BTreeMap::new();
    let mut action_names = BTreeMap::new();
    let tools = source_tools
        .into_iter()
        .map(|tool| {
            let normalized = cedar_identifier(tool.name());
            if let Some(first) =
                normalized_tools.insert(normalized.clone(), tool.name().to_string())
            {
                return Err(McpSchemaError::ToolNameCollision {
                    server: server.to_string(),
                    first,
                    second: tool.name().to_string(),
                    identifier: normalized,
                });
            }
            if action_names
                .insert(normalized.clone(), tool.name().to_string())
                .is_some()
            {
                return Err(McpSchemaError::GeneratedShape {
                    server: server.to_string(),
                    reason: "two generated MCP actions have the same identity",
                });
            }
            Ok(ToolDescription::new(
                normalized.into(),
                tool.inputs().clone(),
                tool.outputs().clone(),
                tool.type_definitions()
                    .map(|definition| (definition.name().into(), definition.clone()))
                    .collect(),
                tool.description().map(str::to_string),
            ))
        })
        .collect::<Result<Vec<_>, McpSchemaError>>()?;
    let type_definitions = description
        .type_definitions()
        .map(|definition| (definition.name().into(), definition.clone()))
        .collect();
    Ok((
        ServerDescription::new(tools.into_iter(), type_definitions),
        action_names,
    ))
}

fn repair_nested_namespace_flattening(
    value: &mut serde_json::Value,
    namespace: &str,
) -> Result<(), &'static str> {
    let Some(definition) = value.as_object_mut() else {
        return Err("the generated namespace could not be converted");
    };
    let server_namespace = namespace.rsplit("::").next().unwrap_or(namespace);
    let redundant_prefix = format!("{server_namespace}_");
    let mut renames = BTreeMap::new();

    for declaration_kind in ["commonTypes", "entityTypes"] {
        let Some(declarations) = definition
            .get_mut(declaration_kind)
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        let original = std::mem::take(declarations);
        for (name, declaration) in original {
            let repaired = name
                .strip_prefix(&redundant_prefix)
                .unwrap_or(&name)
                .to_string();
            if repaired != name {
                renames.insert(name.clone(), repaired.clone());
                renames.insert(
                    format!("{namespace}::{name}"),
                    format!("{namespace}::{repaired}"),
                );
            }
            if declarations.insert(repaired, declaration).is_some() {
                return Err("flattening the generated MCP types produced a name collision");
            }
        }
    }

    rewrite_schema_type_references(value, &renames);
    Ok(())
}

fn refuse_action_type_collision(value: &serde_json::Value) -> Result<(), &'static str> {
    let Some(definition) = value.as_object() else {
        return Err("the generated namespace could not be converted");
    };
    if ["commonTypes", "entityTypes"].into_iter().any(|kind| {
        definition
            .get(kind)
            .and_then(serde_json::Value::as_object)
            .is_some_and(|declarations| declarations.contains_key("Action"))
    }) {
        return Err("a generated type is named Action");
    }
    Ok(())
}

fn rewrite_schema_type_references(
    value: &mut serde_json::Value,
    renames: &BTreeMap<String, String>,
) {
    let serde_json::Value::Object(object) = value else {
        return;
    };
    let type_kind = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    if let Some(type_name) = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .and_then(|name| renames.get(name))
        .cloned()
    {
        object.insert("type".to_string(), serde_json::Value::String(type_name));
    }
    if matches!(type_kind.as_deref(), Some("Entity" | "EntityOrCommon"))
        && let Some(type_name) = object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .and_then(|name| renames.get(name))
            .cloned()
    {
        object.insert("name".to_string(), serde_json::Value::String(type_name));
    }

    for (field, child) in object {
        if matches!(
            field.as_str(),
            "principalTypes" | "resourceTypes" | "memberOfTypes"
        ) {
            rewrite_schema_name_list(child, renames);
        } else if field != "enum" {
            match child {
                serde_json::Value::Object(_) => rewrite_schema_type_references(child, renames),
                serde_json::Value::Array(values) => {
                    for value in values {
                        rewrite_schema_type_references(value, renames);
                    }
                }
                _ => {}
            }
        }
    }
}

fn rewrite_schema_name_list(value: &mut serde_json::Value, renames: &BTreeMap<String, String>) {
    let Some(names) = value.as_array_mut() else {
        return;
    };
    for name in names {
        let Some(repaired) = name.as_str().and_then(|name| renames.get(name)) else {
            continue;
        };
        *name = serde_json::Value::String(repaired.clone());
    }
}

fn use_box_entities(value: &mut serde_json::Value, namespace: &str) {
    let Some(definition) = value.as_object_mut() else {
        return;
    };
    if let Some(actions) = definition
        .get_mut("actions")
        .and_then(serde_json::Value::as_object_mut)
    {
        for action in actions.values_mut() {
            use_box_entities_in_action(action, namespace);
        }
    }
}

fn use_box_entities_in_action(value: &mut serde_json::Value, namespace: &str) {
    let Some(action) = value.as_object_mut() else {
        return;
    };
    let Some(applies_to) = action
        .get_mut("appliesTo")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    use_box_entity(
        applies_to.get_mut("principalTypes"),
        &format!("{namespace}::Agent"),
        "Agent",
        "Box::Agent",
    );
    use_box_entity(
        applies_to.get_mut("resourceTypes"),
        &format!("{namespace}::Resource"),
        "Resource",
        "Box::Resource",
    );
}

fn use_box_entity(
    value: Option<&mut serde_json::Value>,
    namespaced: &str,
    local: &str,
    box_entity: &str,
) {
    let Some(names) = value.and_then(serde_json::Value::as_array_mut) else {
        return;
    };
    for name in names {
        if matches!(name.as_str(), Some(name) if name == namespaced || name == local) {
            *name = serde_json::Value::String(box_entity.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use cedar_policy::{PolicySet, ValidationMode, Validator};

    use super::*;

    const TOOLS: &str = r#"
    {
        "result": {
            "tools": [{
                "name": "read",
                "description": "Read one item",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }
            }]
        }
    }
    "#;

    fn shared_type_tools(kind: &str) -> String {
        format!(
            r##"{{
                "result": {{
                    "tools": [{{
                        "name": "read",
                        "inputSchema": {{
                            "type": "object",
                            "properties": {{"shared": {{"$ref": "#/$defs/SharedText"}}}},
                            "required": ["shared"]
                        }}
                    }}],
                    "$defs": {{"SharedText": {{"type": "{kind}"}}}}
                }}
            }}"##
        )
    }

    #[test]
    fn actions_types_and_box_entities_are_rendered_in_one_server_namespace() {
        let tools = TOOLS.replace(r#""read""#, r#""read.wiki""#);
        let schema = generate_mcp_schema("issues-mcp", &tools).expect("generated schema");

        assert!(schema.contains("namespace issues_mcp {"));
        assert!(schema.contains("type read_wikiInput ="));
        assert!(schema.contains(r#"action "read.wiki" appliesTo"#));
        assert!(schema.contains("input: read_wikiInput"));
        assert!(schema.contains("principal: [Box::Agent]"), "{schema}");
        assert!(schema.contains("resource: [Box::Resource]"), "{schema}");
        assert!(!schema.contains("entity Agent"));
        assert!(!schema.contains("entity Resource"));
        assert!(!schema.contains("namespace Mcp::"));
        assert!(!schema.contains("McpTool_"));
        assert!(!schema.contains("McpType_"));
    }

    #[test]
    fn server_type_names_are_readable_and_compose_without_warnings() {
        let first =
            generate_mcp_schema("alpha", &shared_type_tools("string")).expect("first schema");
        let second =
            generate_mcp_schema("beta", &shared_type_tools("integer")).expect("second schema");

        assert!(first.contains("namespace alpha {"));
        assert!(second.contains("namespace beta {"));
        assert!(first.contains("type SharedText = String;"));
        assert!(second.contains("type SharedText = Long;"));
        assert!(!first.contains("McpType_"));
        assert!(!second.contains("McpType_"));
        validate_mcp_schema_composition(&[("alpha", &first), ("beta", &second)])
            .expect("composed schemas");
        let public = compose_action_schema(&[("alpha", &first), ("beta", &second)])
            .expect("public composition");
        let engine = crate::schema::action_schema(&[first, second])
            .expect("engine composition")
            .source;
        assert_eq!(public, engine);
    }

    #[test]
    fn a_zero_tool_catalog_has_one_namespace_and_no_generated_actions() {
        let generated = generate_mcp_schema("empty-server", r#"{"result":{"tools":[]}}"#)
            .expect("empty schema generates");

        assert!(
            generated.contains("namespace empty_server {"),
            "{generated}"
        );
        assert_eq!(generated.matches("namespace ").count(), 1, "{generated}");
        let (schema, warnings) =
            Schema::from_cedarschema_str(&format!("{SCHEMA_SRC}\n{generated}"))
                .expect("empty schema composes");
        assert_eq!(warnings.count(), 0);
        assert_eq!(
            schema
                .actions()
                .filter(|action| action.type_name().to_string() != "Box::Action")
                .count(),
            0
        );
    }

    #[test]
    fn exact_tool_names_survive_cedar_escaping() {
        let tool = "read.\"wiki\":item";
        let tools = serde_json::json!({
            "result": {
                "tools": [{
                    "name": tool,
                    "inputSchema": {"type": "object", "properties": {}}
                }]
            }
        });
        let generated =
            generate_mcp_schema("issues-mcp", &tools.to_string()).expect("schema generates");
        let (schema, warnings) =
            Schema::from_cedarschema_str(&format!("{SCHEMA_SRC}\n{generated}"))
                .expect("schema composes");

        assert_eq!(warnings.count(), 0);
        let action = schema
            .actions()
            .find(|action| action.type_name().to_string() == "issues_mcp::Action")
            .expect("the namespaced tool action exists");
        assert_eq!(action.id().unescaped(), tool);
    }

    #[test]
    fn two_servers_can_declare_the_same_tool_name() {
        let alpha = generate_mcp_schema("alpha", TOOLS).expect("Alpha schema");
        let beta = generate_mcp_schema("beta", TOOLS).expect("Beta schema");

        validate_mcp_schema_composition(&[("alpha", &alpha), ("beta", &beta)])
            .expect("like-named tools compose");
    }

    #[test]
    fn a_generated_type_cannot_collide_with_the_server_action_type() {
        let tools = r##"
        {
            "result": {
                "tools": [{
                    "name": "read",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"value": {"$ref": "#/$defs/Action"}},
                        "required": ["value"]
                    }
                }],
                "$defs": {"Action": {"type": "string"}}
            }
        }
        "##;
        let error = generate_mcp_schema("server", tools)
            .expect_err("a generated type must not collide with Cedar's Action type");
        assert!(matches!(
            error,
            McpSchemaError::GeneratedShape {
                reason: "a generated type is named Action",
                ..
            }
        ));
    }

    #[test]
    fn the_box_namespace_is_reserved_for_the_canonical_schema() {
        let error = generate_mcp_schema("Box", TOOLS)
            .expect_err("a generated server must not own the Box namespace");
        assert!(matches!(
            error,
            McpSchemaError::GeneratedShape {
                reason: "the normalized server namespace is reserved for the Box schema",
                ..
            }
        ));

        let fragment = r#"
namespace Box {
    type readInput = { path: String };
    action "read" appliesTo {
        principal: [Box::Agent],
        resource: [Box::Resource],
        context: { input: readInput }
    };
}
"#;
        validate_unbound_mcp_schema(fragment)
            .expect_err("an unbound fragment must not claim the Box namespace");
    }

    #[test]
    fn bound_composition_refuses_another_server_namespace() {
        let generated = generate_mcp_schema("alpha", TOOLS).expect("Alpha schema");
        let mismatched = generated.replace("namespace alpha", "namespace beta");

        validate_bound_mcp_schema("alpha", &mismatched)
            .expect_err("the fragment must use the declared server namespace");
    }

    #[test]
    fn composition_refuses_an_action_outside_the_box_identity() {
        let generated = generate_mcp_schema("alpha", TOOLS).expect("Alpha schema");
        let mismatched = generated.replace("principal: [Box::Agent]", "principal: [Box::Resource]");

        let error = validate_bound_mcp_schema("alpha", &mismatched)
            .expect_err("the generated action must use the Box principal");
        assert!(matches!(
            error,
            McpSchemaError::Composition { reason }
                if reason == "an MCP action does not apply to the Box principal and resource"
        ));
    }

    #[test]
    fn type_arrays_lower_nullable_to_a_scalar_and_a_number_to_long() {
        let tools = r#"
        {
            "result": {
                "tools": [{
                    "name": "act",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "note": {"type": ["string", "null"]},
                            "count": {"type": ["number", "null"]},
                            "value": {"type": ["string", "number", "boolean"]}
                        },
                        "required": ["note", "count", "value"]
                    }
                }]
            }
        }
        "#;
        let generated = generate_mcp_schema("srv", tools).expect("schema generates");
        // A nullable string collapses to `String`; a nullable number to `Long`.
        assert!(generated.contains("note: String"), "{generated}");
        assert!(generated.contains("count: Long"), "{generated}");
        // No opaque `Number` entity survives, even inside a genuine multi-type union.
        assert!(!generated.contains("entity Number"), "{generated}");
        validate_mcp_schema_composition(&[("srv", &generated)]).expect("composes");
    }

    #[test]
    fn nested_server_namespace_flattens_and_composes_with_lowered_arg_types() {
        let tools = r#"
        {
            "result": {
                "tools": [{
                    "name": "calculate",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "number": {"type": "number"},
                            "mode": {
                                "type": "string",
                                "enum": ["Mcp::admin", "user"]
                            }
                        },
                        "required": ["number", "mode"]
                    }
                }]
            }
        }
        "#;

        let generated = generate_mcp_schema("issues-mcp", tools).expect("nested namespace schema");

        assert_eq!(generated.matches("namespace ").count(), 1, "{generated}");
        assert!(generated.contains("namespace issues_mcp {"));
        assert!(generated.contains("type calculateInput ="));
        assert!(generated.contains(r#"action "calculate" appliesTo"#));
        assert!(generated.contains("input: calculateInput"));
        assert!(!generated.contains("issues_mcp_"), "{generated}");
        // Arg types are lowered so a rule reads the workload's bare value: the enum `mode` becomes a
        // `String` (no enum entity, no `"Mcp::admin"` variant) and the `number` becomes `Long` (no
        // `Number` entity).
        assert!(generated.contains("mode: String"), "{generated}");
        assert!(!generated.contains("enum ["), "{generated}");
        assert!(!generated.contains("Mcp::admin"), "{generated}");
        assert!(generated.contains("number: Long"), "{generated}");
        assert!(!generated.contains("entity Number"), "{generated}");
        validate_mcp_schema_composition(&[("issues-mcp", &generated)])
            .expect("warning-free canonical composition");
    }

    #[test]
    fn recursive_json_pointer_is_opaque_without_erasing_known_fields() {
        let tools = r##"
        {
            "result": {
                "tools": [{
                    "name": "create_canvas",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "blocks": {
                                "type": "array",
                                "items": {
                                    "anyOf": [
                                        {"type": "string"},
                                        {"$ref": "#/properties/blocks/items"}
                                    ]
                                }
                            }
                        },
                        "required": ["title"]
                    }
                }]
            }
        }
        "##;

        let generated =
            generate_mcp_schema("slack-mcp", tools).expect("recursive schema generates");

        assert!(generated.contains("title: String"));
        assert!(generated.contains("entity Unknown"));
        validate_mcp_schema_composition(&[("slack-mcp", &generated)])
            .expect("recursive schema composes");
    }

    #[test]
    fn input_local_type_shadows_the_server_type() {
        let tools = r##"
        {
            "result": {
                "tools": [{
                    "name": "read",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"shared": {"$ref": "#/$defs/SharedText"}},
                        "required": ["shared"],
                        "$defs": {"SharedText": {"type": "integer"}}
                    }
                }],
                "$defs": {"SharedText": {"type": "string"}}
            }
        }
        "##;
        let generated = generate_mcp_schema("shadow", tools).expect("generated schema");
        let (schema, warnings) =
            Schema::from_cedarschema_str(&format!("{SCHEMA_SRC}\n{generated}"))
                .expect("composed schema");
        assert_eq!(warnings.count(), 0);
        let policy = |value: &str| -> PolicySet {
            format!(
                r#"permit (
                    principal == Box::Agent::"self",
                    action == shadow::Action::"read",
                    resource == Box::Resource::"unused"
                ) when {{
                    context.input.shared == {value}
                }};"#
            )
            .parse()
            .expect("valid policy")
        };

        assert!(
            Validator::new(schema.clone())
                .validate(&policy("7"), ValidationMode::Strict)
                .validation_passed()
        );
        assert!(
            !Validator::new(schema)
                .validate(&policy(r#""server""#), ValidationMode::Strict)
                .validation_passed()
        );
    }

    #[test]
    fn generated_shape_refuses_no_namespaces() {
        let shape = GeneratedShape {
            namespaces: Vec::new(),
            box_entity_declarations: 2,
            has_grouped_action: false,
            action_declarations: 0,
        };
        let error = validate_generator_shape("server", &shape, "server")
            .expect_err("missing namespace must be refused");
        assert!(matches!(
            error,
            McpSchemaError::GeneratedShape {
                reason: "the generator returned no namespace",
                ..
            }
        ));
    }

    #[test]
    fn generated_shape_refuses_a_global_namespace() {
        let shape = GeneratedShape {
            namespaces: vec![None],
            box_entity_declarations: 2,
            has_grouped_action: false,
            action_declarations: 0,
        };
        let error = validate_generator_shape("server", &shape, "server")
            .expect_err("global namespace must be refused");
        assert!(matches!(
            error,
            McpSchemaError::GeneratedShape {
                reason: "the generator returned a global namespace",
                ..
            }
        ));
    }

    #[test]
    fn generated_shape_refuses_an_unexpected_namespace() {
        let shape = GeneratedShape {
            namespaces: vec![Some("other".to_string())],
            box_entity_declarations: 2,
            has_grouped_action: false,
            action_declarations: 0,
        };
        let error = validate_generator_shape("server", &shape, "server")
            .expect_err("unexpected namespace must be refused");
        assert!(matches!(
            error,
            McpSchemaError::GeneratedShape {
                reason: "the generator returned an unexpected namespace",
                ..
            }
        ));
    }

    #[test]
    fn generated_shape_refuses_an_action_group() {
        let shape = GeneratedShape {
            namespaces: vec![Some("server".to_string())],
            box_entity_declarations: 2,
            has_grouped_action: true,
            action_declarations: 0,
        };
        let error = validate_generator_shape("server", &shape, "server")
            .expect_err("action group must be refused");
        assert!(matches!(
            error,
            McpSchemaError::GeneratedShape {
                reason: "a generated MCP action belongs to an action group",
                ..
            }
        ));
    }

    #[test]
    fn generated_shape_refuses_missing_box_entities() {
        let shape = GeneratedShape {
            namespaces: vec![Some("server".to_string())],
            box_entity_declarations: 1,
            has_grouped_action: false,
            action_declarations: 0,
        };
        let error = validate_generator_shape("server", &shape, "server")
            .expect_err("missing entity must be refused");
        assert!(matches!(
            error,
            McpSchemaError::GeneratedShape {
                reason: "the generated schema did not contain the Agent and Resource declarations",
                ..
            }
        ));
    }

    #[test]
    fn final_shape_allows_one_server_namespace_with_actions_and_types() {
        let valid = GeneratedShape {
            namespaces: vec![Some("server".to_string())],
            box_entity_declarations: 2,
            has_grouped_action: false,
            action_declarations: 1,
        };
        validate_generated_shape("server", &valid, "server", 1).expect("valid final shape");

        let invalid = GeneratedShape {
            namespaces: vec![Some("server".to_string()), Some("Mcp::server".to_string())],
            ..valid
        };
        let error = validate_generated_shape("server", &invalid, "server", 1)
            .expect_err("an extra namespace must be refused");
        assert!(matches!(
            error,
            McpSchemaError::GeneratedShape {
                reason: "the generated schema did not contain exactly one server namespace",
                ..
            }
        ));
    }

    #[test]
    fn generated_shape_refuses_duplicate_tool_names() {
        let tools = r#"
        {
            "result": {
                "tools": [
                    {"name": "repeat", "inputSchema": {"type": "object", "properties": {}}},
                    {"name": "repeat", "inputSchema": {"type": "object", "properties": {}}}
                ]
            }
        }
        "#;
        let error =
            generate_mcp_schema("duplicate", tools).expect_err("duplicate tools must be refused");
        assert!(matches!(
            error,
            McpSchemaError::GeneratedShape {
                reason: "two generated MCP actions have the same identity",
                ..
            }
        ));
    }

    #[test]
    fn tool_normalization_collision_names_both_tools() {
        let tools = r#"
        {
            "result": {
                "tools": [
                    {
                        "name": "read-wiki",
                        "inputSchema": {"type": "object", "properties": {}}
                    },
                    {
                        "name": "read.wiki",
                        "inputSchema": {"type": "object", "properties": {}}
                    }
                ]
            }
        }
        "#;

        let error =
            generate_mcp_schema("issues-mcp", tools).expect_err("collision must be refused");
        assert!(matches!(
            error,
            McpSchemaError::ToolNameCollision {
                server,
                first,
                second,
                identifier
            } if server == "issues-mcp"
                && first == "read-wiki"
                && second == "read.wiki"
                && identifier == "read_wiki"
        ));
    }

    #[test]
    fn composition_names_both_servers_for_a_namespace_collision() {
        let first = generate_mcp_schema("a-b", TOOLS).expect("first schema");
        let second = generate_mcp_schema("a.b", TOOLS).expect("second schema");

        let error = validate_mcp_schema_composition(&[("a-b", &first), ("a.b", &second)])
            .expect_err("colliding namespaces must be refused");
        assert!(matches!(
            error,
            McpSchemaError::NamespaceCollision {
                first,
                second,
                namespace
            } if first == "a-b" && second == "a.b" && namespace == "a_b"
        ));
    }

    #[test]
    fn namespaced_actions_avoid_the_old_separator_collision() {
        let first_tools = TOOLS.replace(r#""read""#, r#""b___read""#);
        let first = generate_mcp_schema("a", &first_tools).expect("first schema");
        let second = generate_mcp_schema("a___b", TOOLS).expect("second schema");

        validate_mcp_schema_composition(&[("a", &first), ("a___b", &second)])
            .expect("server namespaces keep the actions distinct");
    }
}
