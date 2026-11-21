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
    let generated = generate_from_tools(server, tools_list);
    if generated.is_ok() {
        return generated;
    }
    // An `outputSchema` only adds `output.structured`, so one that Cedar cannot read must not
    // cost the server every tool.
    match without_unreadable_outputs(server, tools_list) {
        Some(readable) => generate_from_tools(server, &readable).or(generated),
        None => generated,
    }
}

/// `tools_list` without each `outputSchema` that does not generate alone, or without every
/// `outputSchema` when none fails alone; `None` when no tool declares one.
fn without_unreadable_outputs(server: &str, tools_list: &str) -> Option<String> {
    let mut response = serde_json::from_str::<serde_json::Value>(tools_list).ok()?;
    let pointer = if response.pointer("/result/tools").is_some() {
        "/result/tools"
    } else {
        "/tools"
    };
    let tools = response
        .pointer_mut(pointer)
        .and_then(serde_json::Value::as_array_mut)?;
    let mut removed = false;
    for tool in tools.iter_mut() {
        if !tool
            .get("outputSchema")
            .is_some_and(serde_json::Value::is_object)
        {
            continue;
        }
        let alone = serde_json::json!({ "result": { "tools": [tool.clone()] } }).to_string();
        if generate_from_tools(server, &alone).is_err()
            && let Some(tool) = tool.as_object_mut()
        {
            removed |= tool.remove("outputSchema").is_some();
        }
    }
    if !removed {
        for tool in tools
            .iter_mut()
            .filter_map(serde_json::Value::as_object_mut)
        {
            removed |= tool.remove("outputSchema").is_some();
        }
    }
    removed.then(|| response.to_string())
}

/// [`generate_mcp_schema`] for one tools/list response, with no retry.
fn generate_from_tools(server: &str, tools_list: &str) -> Result<String, McpSchemaError> {
    refuse_reserved_namespace(server)?;
    refuse_duplicate_tool_names(server, tools_list)?;
    // Lower each tool argument to a base Cedar type before generation, so a rule reads the
    // workload's bare value directly. The generator otherwise maps a JSON `enum` to a Cedar enum
    // *entity* and a JSON `number` to an opaque `Number` entity — neither of which the raw value a
    // tool call carries can satisfy, so the request fails schema conformance. See `lower_arg_types`.
    let tools_with_output = tools_declaring_output(tools_list);
    let compatible_tools_list = make_unsupported_schema_references_opaque(tools_list);
    let tools_list = lower_arg_types(&compatible_tools_list);
    let tools_list = make_definitions_generable(&tools_list);
    let (tools_list, argument_names) = identify_arguments(&tools_list);
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
        .flatten_namespaces(true)
        .include_outputs(true);
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
        finish_namespace(
            &mut definition_value,
            &server_namespace,
            &tools_with_output,
            &argument_names,
        );
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

/// Each MCP server namespace that `composed` declares and `base` does not, with its own fragment.
pub(crate) fn mcp_schemas_in(composed: &str, base: &str) -> Vec<(String, String)> {
    let namespaces = |source: &str| match SchemaFragment::from_cedarschema_str(source)
        .ok()
        .and_then(|(fragment, _)| fragment.to_json_value().ok())
    {
        Some(serde_json::Value::Object(definitions)) => Some(definitions),
        _ => None,
    };
    let (Some(definitions), Some(built_in)) = (namespaces(composed), namespaces(base)) else {
        return Vec::new();
    };
    definitions
        .into_iter()
        .filter(|(namespace, _)| {
            !namespace.is_empty() && !namespace.contains("::") && !built_in.contains_key(namespace)
        })
        .filter_map(|(namespace, definition)| {
            let single = serde_json::Value::Object(serde_json::Map::from_iter([(
                namespace.clone(),
                definition,
            )]));
            let source = SchemaFragment::from_json_value(single)
                .ok()?
                .to_cedarschema()
                .ok()?;
            validate_unbound_mcp_schema(&source).ok()?;
            Some((namespace, source))
        })
        .collect()
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
/// multi-member union stays an array — the generator renders it as a `typeChoice` record, and
/// `ToolInputs::conform` places a call's bare value in the member it matches.
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

/// The JSON Schema keywords below a schema whose values are schemas the generator reads, besides
/// the `properties` and `$defs` maps.
const SCHEMA_KEYWORDS: [&str; 6] = [
    "additionalProperties",
    "anyOf",
    "items",
    "json",
    "oneOf",
    "prefixItems",
];

/// The record fields that the generator and [`declare_reply_output`] add, which no argument
/// identifier may take.
const GENERATED_FIELDS: [&str; 4] = ["input", "output", "reply", "structured"];

/// `tools_list` with each input argument name that is not a Cedar identifier renamed to one, and
/// the exact name of each renamed identifier. `tools_list` is unchanged when it does not parse.
fn identify_arguments(tools_list: &str) -> (String, BTreeMap<String, String>) {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(tools_list) else {
        return (tools_list.to_string(), BTreeMap::new());
    };
    let mut names = ArgumentNames::for_response(&value);
    names.rename_tools(&mut value);
    if names.exact.is_empty() {
        return (tools_list.to_string(), BTreeMap::new());
    }
    (value.to_string(), names.exact)
}

/// Each property name in a schema value, at every depth.
fn collect_property_names(value: &serde_json::Value, names: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(properties) = object
                .get("properties")
                .and_then(serde_json::Value::as_object)
            {
                names.extend(properties.keys().cloned());
            }
            for child in object.values() {
                collect_property_names(child, names);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_property_names(child, names);
            }
        }
        _ => {}
    }
}

/// The input argument renames of one server's tools, or its definition renames.
#[derive(Default)]
struct ArgumentNames {
    /// Every name of the renamed kind that the server declares or uses, renamed or not.
    taken: BTreeSet<String>,
    /// The identifier given to each renamed exact name.
    identifiers: BTreeMap<String, String>,
    /// The exact name of each identifier given.
    exact: BTreeMap<String, String>,
    /// The next suffix to try for each base identifier.
    next_suffix: BTreeMap<String, u32>,
}

impl ArgumentNames {
    /// The renames for one tools/list response, with every name it declares already taken.
    fn for_response(response: &serde_json::Value) -> Self {
        let mut names = Self::default();
        names
            .taken
            .extend(GENERATED_FIELDS.iter().map(|field| field.to_string()));
        collect_property_names(response, &mut names.taken);
        names
    }

    /// Rename the arguments of each tool in a tools/list response, in the three shapes the
    /// generator reads: a `result` with `tools` and shared `$defs`, an array of tools, or one tool.
    fn rename_tools(&mut self, response: &mut serde_json::Value) {
        let tools = match response {
            serde_json::Value::Object(object) => match object.get_mut("result") {
                Some(serde_json::Value::Object(result)) => {
                    if let Some(serde_json::Value::Object(definitions)) = result.get_mut("$defs") {
                        for schema in definitions.values_mut() {
                            self.rename_in(schema);
                        }
                    }
                    match result.get_mut("tools") {
                        Some(serde_json::Value::Array(tools)) => tools.iter_mut().collect(),
                        _ => Vec::new(),
                    }
                }
                Some(_) => Vec::new(),
                None => vec![response],
            },
            serde_json::Value::Array(tools) => tools.iter_mut().collect(),
            _ => Vec::new(),
        };
        for tool in tools {
            let Some(tool) = tool.as_object_mut() else {
                continue;
            };
            let input = if tool.contains_key("parameters") {
                "parameters"
            } else {
                "inputSchema"
            };
            if let Some(schema) = tool.get_mut(input) {
                self.rename_in(schema);
            }
            if let Some(serde_json::Value::Object(definitions)) = tool.get_mut("$defs") {
                for definition in definitions.values_mut() {
                    self.rename_in(definition);
                }
            }
        }
    }

    /// Rename the arguments in one input schema value and the schemas below it.
    fn rename_in(&mut self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(serde_json::Value::Object(properties)) = object.get_mut("properties") {
                    let renames = self.rename_properties(properties);
                    if let Some(serde_json::Value::Array(required)) = object.get_mut("required") {
                        for name in required.iter_mut() {
                            if let Some(identifier) =
                                name.as_str().and_then(|name| renames.get(name))
                            {
                                *name = serde_json::Value::String(identifier.clone());
                            }
                        }
                    }
                }
                for (key, child) in object.iter_mut() {
                    match key.as_str() {
                        "properties" | "$defs" => {
                            if let serde_json::Value::Object(schemas) = child {
                                for schema in schemas.values_mut() {
                                    self.rename_in(schema);
                                }
                            }
                        }
                        _ if SCHEMA_KEYWORDS.contains(&key.as_str()) => self.rename_in(child),
                        _ => {}
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for child in values {
                    self.rename_in(child);
                }
            }
            _ => {}
        }
    }

    /// Rename the keys of one `properties` object, and return each rename it made.
    fn rename_properties(
        &mut self,
        properties: &mut serde_json::Map<String, serde_json::Value>,
    ) -> BTreeMap<String, String> {
        let renamed = properties
            .keys()
            .filter(|name| cedar_identifier(name) != **name)
            .cloned()
            .collect::<Vec<_>>();
        let mut renames = BTreeMap::new();
        for name in renamed {
            let identifier = self.identifier_for(&name);
            if let Some(schema) = properties.remove(&name) {
                properties.insert(identifier.clone(), schema);
            }
            renames.insert(name, identifier);
        }
        renames
    }

    /// The identifier for one exact name, unique among the names taken and given.
    fn identifier_for(&mut self, name: &str) -> String {
        if let Some(identifier) = self.identifiers.get(name) {
            return identifier.clone();
        }
        let base = cedar_identifier(name);
        let next = self.next_suffix.entry(base.clone()).or_insert(1);
        let identifier = loop {
            let candidate = if *next == 1 {
                base.clone()
            } else {
                format!("{base}_{next}")
            };
            *next += 1;
            if !self.taken.contains(&candidate) && !self.exact.contains_key(&candidate) {
                break candidate;
            }
        };
        self.identifiers
            .insert(name.to_string(), identifier.clone());
        self.exact.insert(identifier.clone(), name.to_string());
        identifier
    }
}

/// Give a generated namespace its exact argument names, Box's entities, and Box's reply output.
fn finish_namespace(
    value: &mut serde_json::Value,
    namespace: &str,
    tools_with_output: &BTreeSet<String>,
    argument_names: &BTreeMap<String, String>,
) {
    // Restore first: Box's own fields do not exist yet, so the restore cannot rename one.
    restore_argument_names(value, argument_names);
    use_box_entities(value, namespace);
    declare_reply_output(value, tools_with_output);
}

/// Give each record attribute that [`identify_arguments`] renamed its exact argument name again.
fn restore_argument_names(value: &mut serde_json::Value, exact: &BTreeMap<String, String>) {
    if exact.is_empty() {
        return;
    }
    match value {
        serde_json::Value::Object(object) => {
            if let Some(serde_json::Value::Object(attributes)) = object.get_mut("attributes") {
                let renamed = attributes
                    .keys()
                    .filter(|name| exact.contains_key(*name))
                    .cloned()
                    .collect::<Vec<_>>();
                for identifier in renamed {
                    if let (Some(attribute), Some(name)) =
                        (attributes.remove(&identifier), exact.get(&identifier))
                    {
                        attributes.insert(name.clone(), attribute);
                    }
                }
            }
            for child in object.values_mut() {
                restore_argument_names(child, exact);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                restore_argument_names(child, exact);
            }
        }
        _ => {}
    }
}

/// Compose the canonical action schema with ordered generated MCP schemas.
pub fn compose_action_schema(generated: &[(&str, &str)]) -> Result<String, McpSchemaError> {
    crate::ToolGrammars::default().compose_action_schema(generated)
}

/// The Cedar type names that no definition can take.
const RESERVED_TYPE_NAMES: [&str; 8] = [
    "Bool",
    "Boolean",
    "Entity",
    "Extension",
    "Long",
    "Record",
    "Set",
    "String",
];

/// The extension type names, which a server definition would shadow.
const RESERVED_SERVER_TYPE_NAMES: [&str; 4] = ["datetime", "decimal", "duration", "ipaddr"];

/// The deepest nesting of schema steps, through definitions, that a cut cycle or a moved array
/// element may leave, because Cedar resolves the types by recursion and can overflow the stack.
const MAXIMUM_DEFINITION_DEPTH: usize = 64;

/// `tools_list` with the server's `$defs` and each input schema's `$defs` in a shape the generator
/// accepts, or unchanged when it needs no fix or a cut or move leaves it too deep.
fn make_definitions_generable(tools_list: &str) -> Cow<'_, str> {
    let Ok(mut response) = serde_json::from_str::<serde_json::Value>(tools_list) else {
        return Cow::Borrowed(tools_list);
    };
    match make_definitions_generable_in(&mut response) {
        DefinitionFix::None => return Cow::Borrowed(tools_list),
        DefinitionFix::Restructured
            if deepest_definition(&mut response) > MAXIMUM_DEFINITION_DEPTH =>
        {
            return Cow::Borrowed(tools_list);
        }
        DefinitionFix::Renamed | DefinitionFix::Restructured => {}
    }
    Cow::Owned(response.to_string())
}

/// What [`make_definitions_generable_in`] changed in a tools/list response.
#[derive(Clone, Copy, PartialEq)]
enum DefinitionFix {
    /// No definition needs a fix.
    None,
    /// Definition names and the references to them, which leaves the nesting as it was.
    Renamed,
    /// An array element moved or a cycle cut, which can change the nesting.
    Restructured,
}

/// The deepest nesting of types that any definition in a tools/list response expands to.
fn deepest_definition(response: &mut serde_json::Value) -> usize {
    let (server, mut tools) = definition_scopes(response);
    let server = definition_depths(server.and_then(serde_json::Value::as_object_mut), &[]);
    let mut deepest = server.values().copied().max().unwrap_or_default();
    for tool in &mut tools {
        let own = definition_depths(
            tool.definitions
                .as_deref_mut()
                .and_then(serde_json::Value::as_object_mut),
            &[&server],
        );
        let input = definition_depths(
            schema_definitions(tool.input.as_deref_mut()),
            &[&own, &server],
        );
        for depths in [&input, &own] {
            deepest = deepest.max(depths.values().copied().max().unwrap_or_default());
        }
    }
    deepest
}

/// The deepest nesting of types each definition of one scope expands to, counting each schema the
/// generator reads on the way, with `outer` holding the depths of the enclosing scopes.
fn definition_depths(
    definitions: Option<&mut serde_json::Map<String, serde_json::Value>>,
    outer: &[&BTreeMap<String, usize>],
) -> BTreeMap<String, usize> {
    let Some(definitions) = definitions else {
        return BTreeMap::new();
    };
    let index = definitions
        .keys()
        .enumerate()
        .map(|(position, name)| (name.clone(), position))
        .collect::<BTreeMap<_, _>>();
    let nesting = definitions.values().map(json_depth).collect::<Vec<_>>();
    let references = definitions
        .values_mut()
        .map(|definition| {
            let mut targets = Vec::new();
            for_each_common_type_reference(definition, 1, &mut |reference, depth| {
                let name = reference
                    .get("$ref")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|reference| reference.strip_prefix("#/$defs/"))
                    .unwrap_or_default();
                let outer_depth = outer.iter().find_map(|depths| depths.get(name).copied());
                targets.push((
                    depth,
                    index.get(name).copied(),
                    outer_depth.unwrap_or_default(),
                ));
            });
            targets
        })
        .collect::<Vec<_>>();
    let mut depths = vec![None; references.len()];
    let mut open = vec![false; references.len()];
    for root in 0..references.len() {
        if depths[root].is_some() {
            continue;
        }
        open[root] = true;
        let mut path = vec![(root, 0)];
        while let Some((definition, next)) = path.last_mut() {
            let definition = *definition;
            if let Some(&(_, local, _)) = references[definition].get(*next) {
                *next += 1;
                if let Some(target) = local
                    && depths[target].is_none()
                    && !open[target]
                {
                    open[target] = true;
                    path.push((target, 0));
                }
                continue;
            }
            let deepest = references[definition]
                .iter()
                .map(|&(depth, local, outer)| {
                    depth + local.map_or(outer, |target| depths[target].unwrap_or_default())
                })
                .fold(nesting[definition], usize::max);
            depths[definition] = Some(deepest);
            open[definition] = false;
            path.pop();
        }
    }
    index
        .into_iter()
        .map(|(name, position)| (name, depths[position].unwrap_or_default()))
        .collect()
}

fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(object) => 1 + object.values().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn make_definitions_generable_in(response: &mut serde_json::Value) -> DefinitionFix {
    let mut names = ArgumentNames::default();
    names.taken.extend(
        RESERVED_TYPE_NAMES
            .iter()
            .chain(&RESERVED_SERVER_TYPE_NAMES)
            .map(|name| name.to_string()),
    );
    collect_reference_names(response, &mut names.taken);
    let (mut server, mut tools) = definition_scopes(response);
    let mut server_names = BTreeSet::new();
    for tool in &mut tools {
        let identifier = cedar_identifier(&tool.name);
        server_names.insert(format!("{identifier}Input"));
        server_names.insert(format!("{identifier}Output"));
        for definitions in tool.definitions_mut() {
            names.taken.extend(definitions.keys().cloned());
        }
        if let Some(definitions) = schema_definitions(tool.output.as_deref_mut()) {
            names.taken.extend(definitions.keys().cloned());
        }
    }
    names.taken.extend(server_names.iter().cloned());
    if let Some(definitions) = server
        .as_deref_mut()
        .and_then(serde_json::Value::as_object_mut)
    {
        names.taken.extend(definitions.keys().cloned());
    }

    let server_scope = DefinitionScope::rename(
        server
            .as_deref_mut()
            .and_then(serde_json::Value::as_object_mut),
        &mut names,
        |name| server_names.contains(name) || RESERVED_SERVER_TYPE_NAMES.contains(&name),
    );
    let mut renamed = !server_scope.renamed.is_empty();
    let mut restructured = false;
    for tool in &mut tools {
        let tool_scope = DefinitionScope::rename(
            tool.definitions
                .as_deref_mut()
                .and_then(serde_json::Value::as_object_mut),
            &mut names,
            |_| false,
        );
        let input_scope = DefinitionScope::rename(
            schema_definitions(tool.input.as_deref_mut()),
            &mut names,
            |_| false,
        );
        renamed |= [&tool_scope, &input_scope]
            .iter()
            .any(|scope| !scope.renamed.is_empty());
        if let Some(definitions) = tool.definitions.as_deref_mut() {
            renamed |= rewrite_definition_references(definitions, &[&tool_scope, &server_scope]);
        }
        if let Some(input) = tool.input.as_deref_mut() {
            renamed |=
                rewrite_definition_references(input, &[&input_scope, &tool_scope, &server_scope]);
        }
        for definitions in tool.definitions_mut() {
            restructured |= give_array_elements_definitions(definitions, &mut names);
            restructured |= make_definition_cycles_opaque(definitions);
        }
    }
    if let Some(definitions) = server.as_deref_mut() {
        renamed |= rewrite_definition_references(definitions, &[&server_scope]);
    }
    if let Some(definitions) = server.and_then(serde_json::Value::as_object_mut) {
        restructured |= give_array_elements_definitions(definitions, &mut names);
        restructured |= make_definition_cycles_opaque(definitions);
    }
    match (renamed, restructured) {
        (_, true) => DefinitionFix::Restructured,
        (true, false) => DefinitionFix::Renamed,
        (false, false) => DefinitionFix::None,
    }
}

/// The schemas of one tool whose `$defs` the generator reads.
struct ToolDefinitions<'a> {
    name: String,
    definitions: Option<&'a mut serde_json::Value>,
    input: Option<&'a mut serde_json::Value>,
    output: Option<&'a mut serde_json::Value>,
}

impl ToolDefinitions<'_> {
    /// The tool's own `$defs` map and that of its input schema.
    fn definitions_mut(&mut self) -> Vec<&mut serde_json::Map<String, serde_json::Value>> {
        let own = self
            .definitions
            .as_deref_mut()
            .and_then(serde_json::Value::as_object_mut);
        own.into_iter()
            .chain(schema_definitions(self.input.as_deref_mut()))
            .collect()
    }
}

/// The server's `$defs` and each tool's schemas, in the three shapes the generator reads.
fn definition_scopes(
    response: &mut serde_json::Value,
) -> (Option<&mut serde_json::Value>, Vec<ToolDefinitions<'_>>) {
    let single_tool = response
        .as_object()
        .is_some_and(|object| !object.contains_key("result"));
    let (server, tools) = match response {
        _ if single_tool => (None, vec![response]),
        serde_json::Value::Object(object) => match object.get_mut("result") {
            Some(serde_json::Value::Object(result)) => {
                let mut server = None;
                let mut tools = Vec::new();
                for (key, value) in result.iter_mut() {
                    match (key.as_str(), value) {
                        ("$defs", value) => server = Some(value),
                        ("tools", serde_json::Value::Array(list)) => {
                            tools = list.iter_mut().collect()
                        }
                        _ => {}
                    }
                }
                (server, tools)
            }
            _ => (None, Vec::new()),
        },
        serde_json::Value::Array(tools) => (None, tools.iter_mut().collect()),
        _ => (None, Vec::new()),
    };
    let tools = tools
        .into_iter()
        .filter_map(serde_json::Value::as_object_mut)
        .map(|tool| {
            let name = tool
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();
            let input_key = if tool.contains_key("parameters") {
                "parameters"
            } else {
                "inputSchema"
            };
            let mut definitions = ToolDefinitions {
                name,
                definitions: None,
                input: None,
                output: None,
            };
            for (key, value) in tool.iter_mut() {
                match key.as_str() {
                    "$defs" => definitions.definitions = Some(value),
                    "outputSchema" => definitions.output = Some(value),
                    key if key == input_key => definitions.input = Some(value),
                    _ => {}
                }
            }
            definitions
        })
        .collect();
    (server, tools)
}

/// The `$defs` map of an input or output schema, inside its `json` wrapper when it has one.
fn schema_definitions(
    schema: Option<&mut serde_json::Value>,
) -> Option<&mut serde_json::Map<String, serde_json::Value>> {
    let schema = schema?;
    let schema = if schema.get("json").is_some() {
        schema.get_mut("json")?
    } else {
        schema
    };
    schema.get_mut("$defs")?.as_object_mut()
}

/// The definition name each `#/$defs/` reference in a value names.
fn collect_reference_names(value: &serde_json::Value, names: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(name) = object
                .get("$ref")
                .and_then(serde_json::Value::as_str)
                .and_then(|reference| reference.strip_prefix("#/$defs/"))
            {
                names.insert(name.to_string());
            }
            for child in object.values() {
                collect_reference_names(child, names);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_reference_names(child, names);
            }
        }
        _ => {}
    }
}

/// The names one `$defs` map declares, and the name given to each one renamed.
#[derive(Default)]
struct DefinitionScope {
    names: BTreeSet<String>,
    renamed: BTreeMap<String, String>,
}

impl DefinitionScope {
    /// Rename each definition the generator refuses, or that `refused` names, to a name that no
    /// definition or reference in the server uses.
    fn rename(
        definitions: Option<&mut serde_json::Map<String, serde_json::Value>>,
        names: &mut ArgumentNames,
        refused: impl Fn(&str) -> bool,
    ) -> Self {
        let mut scope = Self::default();
        let Some(definitions) = definitions else {
            return scope;
        };
        let refused = |name: &str| {
            cedar_identifier(name) != name || RESERVED_TYPE_NAMES.contains(&name) || refused(name)
        };
        scope.names = definitions.keys().cloned().collect();
        if !scope.names.iter().any(|name| refused(name)) {
            return scope;
        }
        *definitions = std::mem::take(definitions)
            .into_iter()
            .map(|(name, definition)| {
                if !refused(&name) {
                    return (name, definition);
                }
                let identifier = names.identifier_for(&name);
                scope.renamed.insert(name, identifier.clone());
                (identifier, definition)
            })
            .collect();
        scope
    }

    /// The name of the definition `name` resolves to in this scope, or `None` when it declares
    /// none by that name.
    fn resolve(&self, name: &str) -> Option<String> {
        self.names.contains(name).then(|| {
            self.renamed
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.to_string())
        })
    }
}

/// Point each `#/$defs/` reference in `value` at the name of the definition it resolves to in
/// `scopes`, innermost first, reading it decoded only when it names no definition as written.
fn rewrite_definition_references(
    value: &mut serde_json::Value,
    scopes: &[&DefinitionScope],
) -> bool {
    let resolve = |name: &str| scopes.iter().find_map(|scope| scope.resolve(name));
    match value {
        serde_json::Value::Object(object) => {
            let mut changed = false;
            if let Some(serde_json::Value::String(reference)) = object.get_mut("$ref")
                && let Some(name) = reference.strip_prefix("#/$defs/")
                && let Some(target) = resolve(name)
                    .or_else(|| decoded_reference(name).and_then(|decoded| resolve(&decoded)))
                && target != name
            {
                *reference = format!("#/$defs/{target}");
                changed = true;
            }
            for child in object.values_mut() {
                changed |= rewrite_definition_references(child, scopes);
            }
            changed
        }
        serde_json::Value::Array(values) => {
            let mut changed = false;
            for child in values {
                changed |= rewrite_definition_references(child, scopes);
            }
            changed
        }
        _ => false,
    }
}

/// `name` with its URI percent escapes and then its JSON Pointer escapes decoded, or `None` when
/// it has none or does not decode.
fn decoded_reference(name: &str) -> Option<String> {
    if !name.contains(['%', '~']) {
        return None;
    }
    let mut bytes = Vec::with_capacity(name.len());
    let mut rest = name.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            let digits = tail.get(..2)?;
            let digit = |byte: u8| char::from(byte).to_digit(16);
            bytes.push(u8::try_from(digit(digits[0])? * 16 + digit(digits[1])?).ok()?);
            rest = &tail[2..];
        } else {
            bytes.push(byte);
            rest = tail;
        }
    }
    let decoded = String::from_utf8(bytes).ok()?;
    Some(decoded.replace("~1", "/").replace("~0", "~"))
}

/// Move the object element of each array definition, below any nested arrays, into a definition
/// of its own: the generator names that element after the array definition and refuses the clash.
fn give_array_elements_definitions(
    definitions: &mut serde_json::Map<String, serde_json::Value>,
    names: &mut ArgumentNames,
) -> bool {
    let mut elements = Vec::new();
    for (name, definition) in definitions.iter_mut() {
        if let Some(element) = array_object_element(definition) {
            let element_name = names.identifier_for(&format!("{name}_item"));
            let reference = serde_json::json!({ "$ref": format!("#/$defs/{element_name}") });
            elements.push((element_name, std::mem::replace(element, reference)));
        }
    }
    let changed = !elements.is_empty();
    definitions.extend(elements);
    changed
}

/// The object schema an array schema's elements have, below any nested arrays, when the generator
/// reads it as the array's element type.
fn array_object_element(schema: &mut serde_json::Value) -> Option<&mut serde_json::Value> {
    if schema.get("type").and_then(serde_json::Value::as_str) != Some("array")
        || schema.get("prefixItems").is_some()
    {
        return None;
    }
    let items = schema.get_mut("items").filter(|items| items.is_object())?;
    match items.get("type").and_then(serde_json::Value::as_str) {
        Some("object") => Some(items),
        Some("array") => array_object_element(items),
        _ => None,
    }
}

/// Make opaque, as [`make_unsupported_schema_references_opaque`] does, each reference that closes
/// a cycle among one scope's definitions, which Cedar refuses as a recursive common type.
fn make_definition_cycles_opaque(
    definitions: &mut serde_json::Map<String, serde_json::Value>,
) -> bool {
    #[derive(Clone, Copy, PartialEq)]
    enum Visit {
        New,
        Open,
        Done,
    }
    let index = definitions
        .keys()
        .enumerate()
        .map(|(position, name)| (name.clone(), position))
        .collect::<BTreeMap<_, _>>();
    let references = definitions
        .values_mut()
        .map(|definition| {
            let mut targets = Vec::new();
            for_each_common_type_reference(definition, 0, &mut |reference, _| {
                targets.push(
                    reference
                        .get("$ref")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|reference| reference.strip_prefix("#/$defs/"))
                        .and_then(|name| index.get(name).copied()),
                );
            });
            targets
        })
        .collect::<Vec<_>>();
    let mut cut = references
        .iter()
        .map(|targets| vec![false; targets.len()])
        .collect::<Vec<_>>();
    let mut visit = vec![Visit::New; references.len()];
    let mut any_cut = false;
    for root in 0..references.len() {
        if visit[root] != Visit::New {
            continue;
        }
        visit[root] = Visit::Open;
        let mut path = vec![(root, 0)];
        while let Some((definition, next)) = path.last_mut() {
            let (definition, edge) = (*definition, *next);
            let Some(target) = references[definition].get(edge) else {
                visit[definition] = Visit::Done;
                path.pop();
                continue;
            };
            *next += 1;
            match target.map(|target| (target, visit[target])) {
                Some((_, Visit::Open)) => {
                    cut[definition][edge] = true;
                    any_cut = true;
                }
                Some((target, Visit::New)) => {
                    visit[target] = Visit::Open;
                    path.push((target, 0));
                }
                _ => {}
            }
        }
    }
    if any_cut {
        for (definition, cut) in definitions.values_mut().zip(&cut) {
            let mut edge = 0;
            for_each_common_type_reference(definition, 0, &mut |reference, _| {
                if cut[edge] {
                    reference.clear();
                }
                edge += 1;
            });
        }
    }
    any_cut
}

/// Call `visit`, in a fixed order, on each `$ref` object that the generator reads from `schema`
/// into a Cedar common type without passing through an entity type.
fn for_each_common_type_reference(
    schema: &mut serde_json::Value,
    depth: usize,
    visit: &mut impl FnMut(&mut serde_json::Map<String, serde_json::Value>, usize),
) {
    let serde_json::Value::Object(object) = schema else {
        return;
    };
    let (object_kind, array_kind) = match object.get("type") {
        Some(serde_json::Value::String(kind)) => (kind == "object", kind == "array"),
        Some(serde_json::Value::Array(kinds)) => (
            kinds.iter().any(|kind| kind == "object"),
            kinds.iter().any(|kind| kind == "array"),
        ),
        Some(_) => return,
        None => {
            match ["anyOf", "oneOf"]
                .into_iter()
                .find(|key| object.contains_key(*key))
            {
                Some(key) => {
                    if let Some(serde_json::Value::Array(members)) = object.get_mut(key) {
                        for member in members {
                            for_each_common_type_reference(member, depth + 1, visit);
                        }
                    }
                }
                None if object.get("$ref").is_some_and(serde_json::Value::is_string) => {
                    visit(object, depth)
                }
                None => {}
            }
            return;
        }
    };
    if object_kind
        && object
            .get("additionalProperties")
            .is_none_or(|schema| schema.is_boolean() || schema.is_null())
        && let Some(serde_json::Value::Object(properties)) = object.get_mut("properties")
    {
        for property in properties.values_mut() {
            for_each_common_type_reference(property, depth + 1, visit);
        }
    }
    if array_kind {
        let items = object.get("items");
        let (prefix, element) = match object.get("prefixItems") {
            Some(serde_json::Value::Array(prefix)) => (
                items.and_then(serde_json::Value::as_bool) == Some(false),
                prefix.iter().all(|member| Some(member) == items),
            ),
            _ => (false, true),
        };
        if prefix && let Some(serde_json::Value::Array(members)) = object.get_mut("prefixItems") {
            for member in members {
                for_each_common_type_reference(member, depth + 1, visit);
            }
        }
        if element && let Some(items) = object.get_mut("items") {
            for_each_common_type_reference(items, depth + 1, visit);
        }
    }
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

/// Declare the Box-owned `output.reply` on every generated tool action's context, and move the
/// generator's `output` (the tool's `<tool>Output` type, from its `outputSchema`) under it as
/// `output.structured`, so a tool output field never collides with a Box field.
fn declare_reply_output(value: &mut serde_json::Value, tools_with_output: &BTreeSet<String>) {
    let Some(actions) = value
        .get_mut("actions")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for (name, action) in actions.iter_mut() {
        if let Some(attributes) = action
            .pointer_mut("/appliesTo/context/attributes")
            .and_then(serde_json::Value::as_object_mut)
        {
            let generated = attributes.remove("output");
            let mut output = serde_json::json!({
                "reply": { "type": "String" }
            });
            if let Some(mut structured) = generated.filter(|_| tools_with_output.contains(name)) {
                structured["required"] = serde_json::Value::Bool(false);
                output["structured"] = structured;
            }
            attributes.insert(
                "output".to_string(),
                serde_json::json!({
                    "type": "Record",
                    "required": false,
                    "attributes": output
                }),
            );
        }
    }
}

/// The action names (as generated) of tools that declare an `outputSchema`.
fn tools_declaring_output(tools_list: &str) -> BTreeSet<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(tools_list) else {
        return BTreeSet::new();
    };
    value
        .pointer("/result/tools")
        .or_else(|| value.get("tools"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|tool| {
            tool.get("outputSchema")
                .is_some_and(serde_json::Value::is_object)
        })
        .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
        .map(|name| name.to_string())
        .collect()
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

    #[test]
    fn an_output_schema_cedar_cannot_read_drops_only_that_tools_output() {
        for unreadable in [
            r#"{"type":"object","properties":{"if":{"type":"string"}}}"#,
            r##"{"type":"object","properties":{"a":{"$ref":"#/$defs/Missing"}}}"##,
            r#"{"type":"object","properties":{"a b":{"type":"string"}}}"#,
            r#"{"type":"object","properties":{"__cedar":{"type":"string"}}}"#,
        ] {
            let tools = format!(
                r#"{{"result":{{"tools":[
                    {{"name":"read","inputSchema":{{"type":"object","properties":{{"q":{{"type":"string"}}}}}},
                      "outputSchema":{{"type":"object","properties":{{"verified":{{"type":"boolean"}}}}}}}},
                    {{"name":"broken","inputSchema":{{"type":"object","properties":{{"q":{{"type":"string"}}}}}},
                      "outputSchema":{unreadable}}}]}}}}"#
            );
            let schema = generate_mcp_schema("desk", &tools)
                .unwrap_or_else(|error| panic!("{unreadable}: {error:?}"));
            assert!(schema.contains(r#"action "broken""#), "{unreadable}");
            let action = |name: &str| {
                let start = schema
                    .find(&format!("action \"{name}\""))
                    .expect("the action is declared");
                schema[start..]
                    .split("};")
                    .next()
                    .unwrap_or_default()
                    .to_string()
            };
            assert!(
                action("read").contains("structured?: readOutput"),
                "a readable output is kept: {unreadable}\n{schema}"
            );
            assert!(
                !action("broken").contains("structured"),
                "the unreadable output is dropped: {unreadable}\n{schema}"
            );
        }
    }

    #[test]
    fn an_output_schema_definition_is_left_for_the_generator_to_read_or_drop() {
        for definitions in [
            serde_json::json!({"zone-record": {"type": "object", "properties": {"a": {"type": "string"}}}}),
            serde_json::json!({"zone_record": {"type": "array", "items": {"type": "object", "properties": {"a": {"type": "string"}}}}}),
        ] {
            let tools = serde_json::json!({"result": {"tools": [
                {"name": "read", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
                 "outputSchema": {"type": "object", "properties": {"verified": {"type": "boolean"}}}},
                {"name": "broken", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
                 "outputSchema": {
                     "type": "object",
                     "properties": {"r": {"$ref": format!("#/$defs/{}", definitions.as_object().and_then(|map| map.keys().next()).expect("one definition"))}},
                     "$defs": definitions.clone()
                 }}
            ]}})
            .to_string();
            assert!(
                matches!(make_definitions_generable(&tools), Cow::Borrowed(_)),
                "{definitions}"
            );
            let schema = generate_mcp_schema("desk", &tools)
                .unwrap_or_else(|error| panic!("{definitions}: {error:?}"));
            assert!(schema.contains("structured?: readOutput"), "{schema}");
            assert!(
                !schema.contains("structured?: brokenOutput"),
                "{definitions}\n{schema}"
            );
        }
        let cycle = serde_json::json!({"result": {"tools": [
            {"name": "read", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
             "outputSchema": {
                 "type": "object",
                 "properties": {"r": {"$ref": "#/$defs/Group"}},
                 "$defs": {"Group": {"type": "object", "properties": {"up": {"$ref": "#/$defs/Group"}}}}
             }}
        ]}})
        .to_string();
        assert!(matches!(
            make_definitions_generable(&cycle),
            Cow::Borrowed(_)
        ));
        let refused = generate_mcp_schema("desk", &cycle)
            .and_then(|schema| validate_mcp_schema_composition(&[("desk", &schema)]));
        assert!(refused.is_err(), "an output cycle stays refused, as before");
    }

    #[test]
    fn a_renamed_definition_avoids_an_output_definition_name_so_no_tool_loses_its_output() {
        let tools = serde_json::json!({"result": {"tools": [
            {"name": "t", "inputSchema": {"type": "object", "properties": {"s": {"type": "string"}}},
             "outputSchema": {
                 "type": "object",
                 "properties": {"s": {"type": "string"}},
                 "$defs": {"k_x": {"type": "object", "properties": {"o": {"type": "string"}}}}
             }},
            {"name": "t_Output", "inputSchema": {"type": "object", "properties": {"a": {"$ref": "#/$defs/k-x"}}},
             "$defs": {"k-x": {"type": "object", "properties": {"q": {"type": "string"}}}}}
        ]}})
        .to_string();
        let schema = generate_mcp_schema("cf", &tools).unwrap_or_else(|error| panic!("{error:?}"));
        validate_mcp_schema_composition(&[("cf", &schema)])
            .unwrap_or_else(|error| panic!("{error:?}\n{schema}"));
        assert!(schema.contains("a?: cf::t_Output_k_x_2"), "{schema}");
        assert!(schema.contains("structured?: tOutput"), "{schema}");
    }

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
    fn a_composed_schema_yields_each_server_fragment_and_no_other_namespace() {
        let alpha = generate_mcp_schema("alpha", TOOLS).expect("alpha generates");
        let beta =
            generate_mcp_schema("beta", &shared_type_tools("string")).expect("beta generates");
        let composed = crate::schema::composed_action_schema(&[], &[alpha, beta])
            .expect("the schemas compose");

        let recovered = mcp_schemas_in(&composed.source, SCHEMA_SRC);
        assert_eq!(
            recovered
                .iter()
                .map(|(namespace, _)| namespace.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        let fragments = recovered
            .into_iter()
            .map(|(_, fragment)| fragment)
            .collect::<Vec<_>>();
        let recomposed = crate::schema::composed_action_schema(&[], &fragments)
            .expect("the recovered fragments compose");
        let actions = |schema: &Schema| {
            schema
                .actions()
                .map(ToString::to_string)
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(actions(&recomposed.cedar), actions(&composed.cedar));
        assert!(
            mcp_schemas_in(SCHEMA_SRC, SCHEMA_SRC).is_empty(),
            "Box is not a server"
        );
        assert!(mcp_schemas_in("not a schema", SCHEMA_SRC).is_empty());
    }

    #[test]
    fn a_previous_build_of_the_box_actions_is_not_read_as_a_server() {
        let stored = format!(
            "namespace Box {{ entity Agent; action \"retired:action\" appliesTo {{ principal: [Agent], resource: [Agent] }}; }}\n{}",
            generate_mcp_schema("alpha", TOOLS).expect("alpha generates")
        );
        let recovered = mcp_schemas_in(&stored, SCHEMA_SRC);
        assert_eq!(
            recovered
                .iter()
                .map(|(namespace, _)| namespace.as_str())
                .collect::<Vec<_>>(),
            ["alpha"]
        );
        let base = format!(
            "{SCHEMA_SRC}\n{}",
            generate_mcp_schema("alpha", TOOLS).expect("alpha generates")
        );
        assert!(
            mcp_schemas_in(&stored, &base).is_empty(),
            "a namespace this build declares is never read as a server"
        );
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

    fn validates(schema: &Schema, action: &str, condition: &str) -> bool {
        let policy: PolicySet = format!(
            r#"permit (
                principal == Box::Agent::"self",
                action == {action},
                resource == Box::Resource::"unused"
            ) when {{ {condition} }};"#
        )
        .parse()
        .expect("valid policy");
        Validator::new(schema.clone())
            .validate(&policy, ValidationMode::Strict)
            .validation_passed()
    }

    /// The attribute names of one generated record type.
    fn attributes(generated: &str, namespace: &str, record: &str) -> Vec<String> {
        let (fragment, _) =
            SchemaFragment::from_cedarschema_str(generated).expect("the fragment parses");
        let json = fragment.to_json_value().expect("the fragment converts");
        json.pointer(&format!("/{namespace}/commonTypes/{record}/attributes"))
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("{record} is a record\n{generated}"))
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn an_argument_name_that_is_not_a_cedar_identifier_keeps_its_exact_name() {
        let tools = serde_json::json!({
            "result": {
                "tools": [
                    {
                        "name": "get_zone",
                        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
                    },
                    {
                        "name": "list_records",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "zone-id": {"type": "string"},
                                "a b": {"type": "string"},
                                "$filter": {"type": "string"},
                                "1st": {"type": "integer"},
                                "if": {"type": "boolean"},
                                "__cedar": {"type": "string"},
                                "x__cedar": {"type": "string"},
                                "filter": {
                                    "type": "object",
                                    "properties": {"x-api-key": {"type": "string"}},
                                    "required": ["x-api-key"]
                                },
                                "shared": {"$ref": "#/$defs/Shared"}
                            },
                            "required": ["zone-id"]
                        }
                    }
                ],
                "$defs": {
                    "Shared": {"type": "object", "properties": {"a.b": {"type": "string"}}}
                }
            }
        });
        let generated =
            generate_mcp_schema("cf", &tools.to_string()).expect("the schema generates");
        let (schema, warnings) =
            Schema::from_cedarschema_str(&format!("{SCHEMA_SRC}\n{generated}"))
                .expect("the schema composes");
        assert_eq!(warnings.count(), 0);

        let records = r#"cf::Action::"list_records""#;
        for condition in [
            r#"context.input["zone-id"] == "abc""#,
            r#"context.input has "a b" && context.input["a b"] == "abc""#,
            r#"context.input has "$filter" && context.input["$filter"] == "abc""#,
            r#"context.input has "1st" && context.input["1st"] > 1"#,
            r#"context.input has "if" && context.input["if"]"#,
            r#"context.input has "__cedar" && context.input["__cedar"] == "abc""#,
            r#"context.input has "x__cedar" && context.input["x__cedar"] == "abc""#,
            r#"context.input has filter && context.input.filter["x-api-key"] == "abc""#,
            r#"context.input has shared && context.input.shared has "a.b"
                && context.input.shared["a.b"] == "abc""#,
        ] {
            assert!(
                validates(&schema, records, condition),
                "{condition}\n{generated}"
            );
        }
        assert_eq!(
            attributes(&generated, "cf", "list_recordsInput"),
            [
                "$filter", "1st", "__cedar", "a b", "filter", "if", "shared", "x__cedar", "zone-id"
            ]
        );
        assert_eq!(
            attributes(&generated, "cf", "list_records_Input_filter"),
            ["x-api-key"]
        );
        assert_eq!(attributes(&generated, "cf", "Shared"), ["a.b"]);
        assert_eq!(attributes(&generated, "cf", "get_zoneInput"), ["q"]);
    }

    #[test]
    fn an_argument_name_below_each_schema_keyword_keeps_its_exact_name() {
        let tools = serde_json::json!({"result": {"tools": [{
            "name": "send",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "headers": {
                        "type": "array",
                        "items": {"type": "object", "properties": {"x-name": {"type": "string"}}}
                    },
                    "target": {
                        "anyOf": [
                            {"type": "object", "properties": {"zone-id": {"type": "string"}}},
                            {"type": "string"}
                        ]
                    },
                    "pair": {
                        "type": "array",
                        "prefixItems": [
                            {"type": "object", "properties": {"first-key": {"type": "string"}}}
                        ],
                        "items": false
                    },
                    "labels": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "properties": {"label-value": {"type": "string"}}
                        }
                    },
                    "x__cedar": {"type": "object", "properties": {"q": {"type": "string"}}}
                }
            }
        }]}});
        let generated =
            generate_mcp_schema("cf", &tools.to_string()).expect("the schema generates");
        for name in ["x-name", "zone-id", "first-key", "label-value"] {
            assert!(
                generated.contains(&format!("\"{name}\"?: String")),
                "{name}\n{generated}"
            );
        }
        assert!(
            generated.contains("type send_Input_x__cedar = {"),
            "an identifier that already parses keeps the type name it had before\n{generated}"
        );
    }

    #[test]
    fn restoring_argument_names_never_renames_a_field_box_adds() {
        // An identifier map that names Box's own fields, as it would if Box added a field whose
        // name an argument identifier can take (for example `reply_text` beside `reply-text`).
        let exact = BTreeMap::from([
            ("zone_id".to_string(), "zone-id".to_string()),
            ("reply".to_string(), "re-ply".to_string()),
            ("structured".to_string(), "struc-tured".to_string()),
        ]);
        let mut namespace = serde_json::json!({
            "commonTypes": {
                "lookupInput": {
                    "type": "Record",
                    "attributes": {"zone_id": {"type": "String", "required": false}}
                },
                "lookupOutput": {
                    "type": "Record",
                    "attributes": {"q": {"type": "String", "required": false}}
                }
            },
            "entityTypes": {},
            "actions": {"lookup": {"appliesTo": {
                "principalTypes": ["Agent"],
                "resourceTypes": ["Resource"],
                "context": {"type": "Record", "attributes": {
                    "input": {"type": "EntityOrCommon", "name": "lookupInput"},
                    "output": {"type": "EntityOrCommon", "name": "lookupOutput"}
                }}
            }}}
        });

        finish_namespace(
            &mut namespace,
            "cf",
            &BTreeSet::from(["lookup".to_string()]),
            &exact,
        );

        let output = namespace
            .pointer("/actions/lookup/appliesTo/context/attributes/output/attributes")
            .and_then(serde_json::Value::as_object)
            .expect("Box declares the reply output");
        assert_eq!(
            output.keys().collect::<Vec<_>>(),
            ["reply", "structured"],
            "{namespace:#}"
        );
        assert!(
            namespace
                .pointer("/commonTypes/lookupInput/attributes/zone-id")
                .is_some(),
            "the argument keeps its exact name\n{namespace:#}"
        );
    }

    #[test]
    fn no_argument_identifier_can_take_a_name_box_or_the_generator_adds() {
        let names = ArgumentNames::for_response(&serde_json::json!({"result": {"tools": []}}));
        for field in ["input", "output", "reply", "structured"] {
            assert!(names.taken.contains(field), "{field} is reserved");
        }
    }

    #[test]
    fn an_argument_spelled_like_a_generated_field_keeps_every_field() {
        let tools = serde_json::json!({"result": {"tools": [{
            "name": "lookup",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "in-put": {"type": "string"},
                    "out-put": {"type": "string"},
                    "re-ply": {"type": "string"},
                    "struc-tured": {"type": "string"},
                    "type-Choice0": {"type": "string"},
                    "proj-0": {"type": "string"},
                    "either": {"type": ["string", "integer"]}
                }
            },
            "outputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
        }]}});
        let generated =
            generate_mcp_schema("cf", &tools.to_string()).expect("the schema generates");
        let (schema, warnings) =
            Schema::from_cedarschema_str(&format!("{SCHEMA_SRC}\n{generated}"))
                .expect("the schema composes");
        assert_eq!(warnings.count(), 0);
        assert_eq!(
            attributes(&generated, "cf", "lookupInput"),
            [
                "either",
                "in-put",
                "out-put",
                "proj-0",
                "re-ply",
                "struc-tured",
                "type-Choice0"
            ]
        );
        let lookup = r#"cf::Action::"lookup""#;
        for condition in [
            r#"context.input has "in-put" && context.input["in-put"] == "x""#,
            r#"context.input has either && context.input.either has typeChoice0
                && context.input.either.typeChoice0 == "x""#,
            r#"context has output && context.output.reply == "result"
                && context.output has structured && context.output.structured has q"#,
        ] {
            assert!(
                validates(&schema, lookup, condition),
                "{condition}\n{generated}"
            );
        }
    }

    #[test]
    fn many_names_on_one_base_each_keep_their_exact_name() {
        let names = (0x4e00_u32..0x4e00 + 2_000)
            .filter_map(char::from_u32)
            .map(String::from)
            .collect::<Vec<_>>();
        let properties = names
            .iter()
            .map(|name| (name.clone(), serde_json::json!({"type": "string"})))
            .collect::<serde_json::Map<_, _>>();
        let tools = serde_json::json!({"result": {"tools": [{
            "name": "wide",
            "inputSchema": {"type": "object", "properties": properties}
        }]}});
        let generated =
            generate_mcp_schema("cf", &tools.to_string()).expect("the schema generates");
        let mut expected = names;
        expected.sort();
        assert_eq!(attributes(&generated, "cf", "wideInput"), expected);
    }

    #[test]
    fn a_properties_object_outside_an_input_schema_is_not_an_argument_list() {
        let tools = serde_json::json!({"result": {
            "tools": [{
                "name": "lookup",
                "_meta": {"properties": {"zone-id": true, "zone_id": true}},
                "annotations": {"properties": {"zone-id": 1, "zone_id": 2}},
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "zone-id": {
                            "type": "string",
                            "default": {"properties": {"a-b": 1, "a_b": 2}},
                            "x-vendor": {"properties": {"c-d": 1, "c_d": 2}}
                        },
                        "tool-local": {"$ref": "#/$defs/ToolLocal"},
                        "input-local": {"$ref": "#/$defs/InputLocal"}
                    },
                    "$defs": {
                        "InputLocal": {"type": "object", "properties": {"i-j": {"type": "string"}}}
                    }
                },
                "$defs": {
                    "ToolLocal": {"type": "object", "properties": {"g-h": {"type": "string"}}}
                },
                "outputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
            }],
            "_meta": {"properties": {"e-f": 1, "e_f": 2}}
        }});
        let generated =
            generate_mcp_schema("cf", &tools.to_string()).expect("the schema generates");
        assert_eq!(
            attributes(&generated, "cf", "lookupInput"),
            ["input-local", "tool-local", "zone-id"]
        );
        assert_eq!(attributes(&generated, "cf", "lookupOutput"), ["q"]);
        let (schema, warnings) =
            Schema::from_cedarschema_str(&format!("{SCHEMA_SRC}\n{generated}"))
                .expect("the schema composes");
        assert_eq!(warnings.count(), 0);
        for condition in [
            r#"context.input has "tool-local" && context.input["tool-local"] has "g-h"
                && context.input["tool-local"]["g-h"] == "x""#,
            r#"context.input has "input-local" && context.input["input-local"] has "i-j"
                && context.input["input-local"]["i-j"] == "x""#,
        ] {
            assert!(
                validates(&schema, r#"cf::Action::"lookup""#, condition),
                "{condition}\n{generated}"
            );
        }
    }

    #[test]
    fn two_arguments_of_one_object_that_normalize_to_one_identifier_keep_their_exact_names() {
        for (properties, record, names) in [
            (
                serde_json::json!({"zone-id": {"type": "string"}, "zone_id": {"type": "string"}}),
                "list_recordsInput",
                vec!["zone-id", "zone_id"],
            ),
            (
                serde_json::json!({"zone-id": {"type": "string"}, "zone.id": {"type": "string"}}),
                "list_recordsInput",
                vec!["zone-id", "zone.id"],
            ),
            (
                serde_json::json!({"名前": {"type": "string"}, "住所": {"type": "string"}}),
                "list_recordsInput",
                vec!["住所", "名前"],
            ),
            (
                serde_json::json!({"filter": {"type": "object", "properties": {
                    "zone-id": {"type": "string"}, "zone_id": {"type": "string"}
                }, "required": ["zone-id", "zone_id"]}}),
                "list_records_Input_filter",
                vec!["zone-id", "zone_id"],
            ),
        ] {
            let tools = serde_json::json!({"result": {"tools": [
                {
                    "name": "get_zone",
                    "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
                },
                {
                    "name": "list_records",
                    "inputSchema": {"type": "object", "properties": properties}
                }
            ]}});
            let generated = generate_mcp_schema("cf", &tools.to_string())
                .unwrap_or_else(|error| panic!("{names:?}: {error}"));
            let (schema, warnings) =
                Schema::from_cedarschema_str(&format!("{SCHEMA_SRC}\n{generated}"))
                    .expect("the schema composes");
            assert_eq!(warnings.count(), 0);
            assert_eq!(attributes(&generated, "cf", record), names, "{generated}");
            assert_eq!(attributes(&generated, "cf", "get_zoneInput"), ["q"]);
            if record == "list_recordsInput" {
                for name in &names {
                    assert!(
                        validates(
                            &schema,
                            r#"cf::Action::"list_records""#,
                            &format!(
                                r#"context.input has "{name}" && context.input["{name}"] == "x""#
                            )
                        ),
                        "{name}\n{generated}"
                    );
                }
            }
        }
    }

    #[test]
    fn one_identifier_in_two_tools_keeps_each_exact_name() {
        let tools = serde_json::json!({"result": {"tools": [
            {
                "name": "hyphen",
                "inputSchema": {"type": "object", "properties": {"zone-id": {"type": "string"}}}
            },
            {
                "name": "underscore",
                "inputSchema": {"type": "object", "properties": {
                    "zone_id": {"type": "string"},
                    "zone_id_2": {"type": "string"}
                }}
            },
            {
                "name": "dot",
                "inputSchema": {"type": "object", "properties": {"zone.id": {"type": "string"}}}
            }
        ]}});
        let generated =
            generate_mcp_schema("cf", &tools.to_string()).expect("the schema generates");
        let (schema, warnings) =
            Schema::from_cedarschema_str(&format!("{SCHEMA_SRC}\n{generated}"))
                .expect("the schema composes");
        assert_eq!(warnings.count(), 0);

        let hyphen = r#"cf::Action::"hyphen""#;
        let underscore = r#"cf::Action::"underscore""#;
        let dot = r#"cf::Action::"dot""#;
        assert!(validates(&schema, hyphen, r#"context.input has "zone-id""#));
        assert!(validates(
            &schema,
            underscore,
            "context.input has zone_id_2"
        ));
        assert!(validates(&schema, dot, r#"context.input has "zone.id""#));
        assert_eq!(attributes(&generated, "cf", "hyphenInput"), ["zone-id"]);
        assert_eq!(
            attributes(&generated, "cf", "underscoreInput"),
            ["zone_id", "zone_id_2"]
        );
        assert_eq!(attributes(&generated, "cf", "dotInput"), ["zone.id"]);
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
    fn a_union_argument_accepts_each_member_and_refuses_a_non_member() {
        let tools = r#"
        {
            "result": {
                "tools": [{
                    "name": "ask",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "repoName": {
                                "anyOf": [
                                    {"type": "string"},
                                    {"type": "array", "items": {"type": "string"}}
                                ]
                            },
                            "limit": {"type": ["string", "integer", "null"]},
                            "note": {"type": ["string", "null"]},
                            "since": {
                                "anyOf": [
                                    {"type": "string", "format": "date-time"},
                                    {"type": "null"}
                                ]
                            },
                            "at": {
                                "anyOf": [
                                    {"type": "string", "format": "date-time"},
                                    {"type": "string"}
                                ]
                            },
                            "host": {
                                "anyOf": [
                                    {"type": "string", "format": "ipv4"},
                                    {"type": "integer"}
                                ]
                            },
                            "link": {
                                "anyOf": [
                                    {"type": "string", "format": "uri"},
                                    {"type": "string"}
                                ]
                            },
                            "filter": {
                                "type": "object",
                                "properties": {
                                    "labels": {
                                        "type": "array",
                                        "items": {
                                            "oneOf": [
                                                {"type": "boolean"},
                                                {
                                                    "type": "object",
                                                    "properties": {"name": {"type": "string"}},
                                                    "required": ["name"]
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        },
                        "required": ["repoName"]
                    }
                }]
            }
        }
        "#;
        let generated = generate_mcp_schema("wiki", tools).expect("schema generates");
        assert!(generated.contains("note?: String"), "{generated}");
        let schema = crate::schema::action_schema(&[generated]).expect("schema composes");
        let identity = crate::schema::ActionIdentity::mcp_tool("wiki", "ask");
        let action = identity.cedar_uid().expect("tool action");
        let decided = |arguments: serde_json::Value| {
            let conformed = schema
                .tool_inputs
                .conform(&action, &arguments)?
                .expect("the tool declares its input");
            let request = crate::Request::McpCall {
                server: "wiki",
                method: "tools/call",
                tool: Some("ask"),
                prompt: None,
                uri: None,
                arguments: Some(&conformed),
            };
            crate::schema::to_cedar_request(
                &crate::Principal::agent(),
                &request,
                &identity,
                &schema.cedar,
            )?;
            Ok::<_, crate::PolicyError>(conformed)
        };

        for (arguments, read) in [
            (
                serde_json::json!({"repoName": "strands-agents/box"}),
                serde_json::json!({"repoName": {"typeChoice0": "strands-agents/box"}}),
            ),
            (
                serde_json::json!({"repoName": ["a/b", "c/d"]}),
                serde_json::json!({"repoName": {"typeChoice1": ["a/b", "c/d"]}}),
            ),
            (
                serde_json::json!({"repoName": "a/b", "limit": 5, "note": "n"}),
                serde_json::json!({
                    "repoName": {"typeChoice0": "a/b"},
                    "limit": {"typeChoice1": 5},
                    "note": "n"
                }),
            ),
            (
                serde_json::json!({
                    "repoName": "a/b",
                    "since": "2025-01-01T00:00:00Z",
                    "at": "2025-01-01",
                    "host": "10.0.0.1"
                }),
                serde_json::json!({
                    "repoName": {"typeChoice0": "a/b"},
                    "since": {"typeChoice0": "2025-01-01T00:00:00Z"},
                    "at": {"typeChoice0": "2025-01-01", "typeChoice1": "2025-01-01"},
                    "host": {"typeChoice0": "10.0.0.1"}
                }),
            ),
            (
                serde_json::json!({"repoName": "a/b", "at": "next tuesday", "host": 7}),
                serde_json::json!({
                    "repoName": {"typeChoice0": "a/b"},
                    "at": {"typeChoice1": "next tuesday"},
                    "host": {"typeChoice1": 7}
                }),
            ),
            (
                serde_json::json!({"repoName": "a/b", "link": "https://example.com"}),
                serde_json::json!({
                    "repoName": {"typeChoice0": "a/b"},
                    "link": {
                        "typeChoice0": "https://example.com",
                        "typeChoice1": "https://example.com"
                    }
                }),
            ),
            (
                serde_json::json!({
                    "repoName": "a/b",
                    "filter": {"labels": [true, {"name": "bug"}]}
                }),
                serde_json::json!({
                    "repoName": {"typeChoice0": "a/b"},
                    "filter": {"labels": [{"typeChoice0": true}, {"typeChoice1": {"name": "bug"}}]}
                }),
            ),
        ] {
            assert_eq!(
                decided(arguments.clone()).expect("a union member is accepted"),
                read,
                "{arguments}"
            );
        }

        for arguments in [
            serde_json::json!({"repoName": 7}),
            serde_json::json!({"repoName": ["a/b", 7]}),
            serde_json::json!({"repoName": {"typeChoice0": "a/b"}}),
            serde_json::json!({"repoName": "a/b", "limit": true}),
            serde_json::json!({"repoName": "a/b", "since": "not a date"}),
            serde_json::json!({"repoName": "a/b", "host": "10.0.0.1\")"}),
            serde_json::json!({"repoName": "a/b", "filter": {"labels": ["bug"]}}),
            serde_json::json!({"repoName": "a/b", "filter": {"labels": [{"title": "bug"}]}}),
        ] {
            let refusal = decided(arguments.clone()).expect_err("a non-member is refused");
            assert!(
                refusal
                    .to_string()
                    .contains("no member of the declared union"),
                "{arguments}: {refusal}"
            );
        }
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

    /// The schema generated for server `cf`, after it composes with the Box schema.
    fn composed(tools: &serde_json::Value) -> (String, Schema) {
        let generated = generate_mcp_schema("cf", &tools.to_string())
            .unwrap_or_else(|error| panic!("the schema generates: {error}"));
        validate_mcp_schema_composition(&[("cf", &generated)])
            .unwrap_or_else(|error| panic!("the schema composes: {error}\n{generated}"));
        let (schema, warnings) =
            Schema::from_cedarschema_str(&format!("{SCHEMA_SRC}\n{generated}"))
                .expect("the schema parses");
        assert_eq!(warnings.count(), 0);
        (generated, schema)
    }

    /// A server with a healthy tool and a tool `read` whose `p` argument refers to `name`.
    fn referring_tools(name: &str, definitions: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"result": {
            "tools": [
                {"name": "get_zone", "inputSchema": {"type": "object", "properties": {"zone_id": {"type": "string"}}}},
                {"name": "read", "inputSchema": {
                    "type": "object",
                    "properties": {"p": {"$ref": format!("#/$defs/{name}")}}
                }}
            ],
            "$defs": definitions
        }})
    }

    const READ: &str = r#"cf::Action::"read""#;

    #[test]
    fn a_server_definition_name_that_is_not_a_cedar_identifier_generates() {
        let tools = serde_json::json!({"result": {
            "tools": [
                {"name": "get_zone", "inputSchema": {"type": "object", "properties": {"zone_id": {"type": "string"}}}},
                {"name": "read", "inputSchema": {"type": "object", "properties": {
                    "record": {"$ref": "#/$defs/zone-record"},
                    "batch": {"$ref": "#/$defs/record batch"}
                }}}
            ],
            "$defs": {
                "zone-record": {"type": "object", "properties": {"name": {"type": "string"}}},
                "record batch": {"type": "object", "properties": {"first": {"$ref": "#/$defs/zone-record"}}}
            }
        }});
        let (generated, schema) = composed(&tools);

        assert!(generated.contains("type zone_record = "), "{generated}");
        for condition in [
            r#"context.input has record && context.input.record has name && context.input.record.name == "x""#,
            r#"context.input has batch && context.input.batch has first && context.input.batch.first has name && context.input.batch.first.name == "x""#,
        ] {
            assert!(
                validates(&schema, READ, condition),
                "{condition}\n{generated}"
            );
        }
        assert!(validates(
            &schema,
            r#"cf::Action::"get_zone""#,
            r#"context.input has zone_id && context.input.zone_id == "z""#
        ));
    }

    #[test]
    fn a_tool_definition_name_that_is_not_a_cedar_identifier_generates() {
        let tools = serde_json::json!({"result": {"tools": [
            {
                "name": "read",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "account": {"$ref": "#/$defs/iam_create-account"},
                        "owner": {"$ref": "#/$defs/owner-ref"}
                    },
                    "$defs": {"owner-ref": {"type": "object", "properties": {"id": {"type": "integer"}}}}
                },
                "$defs": {
                    "iam_create-account": {"type": "object", "properties": {
                        "name": {"type": "string"},
                        "admin": {"$ref": "#/$defs/admin-user"}
                    }},
                    "admin-user": {"type": "object", "properties": {"id": {"type": "integer"}}}
                }
            },
            {
                "name": "wrapped",
                "inputSchema": {"json": {
                    "type": "object",
                    "properties": {"zone": {"$ref": "#/$defs/zone-ref"}},
                    "$defs": {"zone-ref": {"type": "object", "properties": {"id": {"type": "string"}}}}
                }}
            }
        ]}});
        let (generated, schema) = composed(&tools);

        for condition in [
            r#"context.input has account && context.input.account has name && context.input.account.name == "x""#,
            "context.input has owner && context.input.owner has id && context.input.owner.id == 1",
            "context.input has account && context.input.account has admin && context.input.account.admin has id && context.input.account.admin.id == 1",
        ] {
            assert!(
                validates(&schema, READ, condition),
                "{condition}\n{generated}"
            );
        }
        assert!(validates(
            &schema,
            r#"cf::Action::"wrapped""#,
            r#"context.input has zone && context.input.zone has id && context.input.zone.id == "z""#
        ));
    }

    #[test]
    fn two_definition_names_that_normalize_alike_both_generate() {
        let tools = serde_json::json!({"result": {
            "tools": [{"name": "read", "inputSchema": {"type": "object", "properties": {
                "a": {"$ref": "#/$defs/zone-record"},
                "b": {"$ref": "#/$defs/zone.record"},
                "c": {"$ref": "#/$defs/zone_record"},
                "d": {"$ref": "#/$defs/名前"},
                "e": {"$ref": "#/$defs/住所"}
            }}}],
            "$defs": {
                "zone-record": {"type": "object", "properties": {"name": {"type": "string"}}},
                "zone.record": {"type": "object", "properties": {"id": {"type": "integer"}}},
                "zone_record": {"type": "object", "properties": {"tag": {"type": "boolean"}}},
                "名前": {"type": "string"},
                "住所": {"type": "integer"}
            }
        }});
        let (generated, schema) = composed(&tools);

        for condition in [
            r#"context.input has a && context.input.a has name && context.input.a.name == "x""#,
            "context.input has b && context.input.b has id && context.input.b.id == 1",
            "context.input has c && context.input.c has tag && context.input.c.tag",
            r#"context.input has d && context.input.d == "x""#,
            "context.input has e && context.input.e == 1",
        ] {
            assert!(
                validates(&schema, READ, condition),
                "{condition}\n{generated}"
            );
        }
        for condition in [
            "context.input has a && context.input.a.id == 1",
            r#"context.input has c && context.input.c.name == "x""#,
            "context.input has d && context.input.d == 1",
        ] {
            assert!(
                !validates(&schema, READ, condition),
                "{condition}\n{generated}"
            );
        }
    }

    #[test]
    fn a_renamed_definition_keeps_the_shadowing_of_every_reference() {
        let tools = serde_json::json!({"result": {
            "tools": [{"name": "read", "inputSchema": {
                "type": "object",
                "properties": {
                    "server": {"$ref": "#/$defs/zone-record"},
                    "local": {"$ref": "#/$defs/zone_record"},
                    "shadowed": {"$ref": "#/$defs/zone-id"},
                    "named": {"$ref": "#/$defs/zone-name"}
                },
                "$defs": {
                    "zone_record": {"type": "integer"},
                    "zone-id": {"type": "integer"},
                    "zone_name": {"type": "integer"}
                }
            }}],
            "$defs": {
                "zone-record": {"type": "string"},
                "zone-id": {"type": "string"},
                "zone-name": {"type": "string"}
            }
        }});
        let (generated, schema) = composed(&tools);

        for condition in [
            r#"context.input has server && context.input.server == "x""#,
            "context.input has local && context.input.local == 1",
            "context.input has shadowed && context.input.shadowed == 1",
            r#"context.input has named && context.input.named == "x""#,
        ] {
            assert!(
                validates(&schema, READ, condition),
                "{condition}\n{generated}"
            );
        }
        for condition in [
            "context.input has server && context.input.server == 1",
            r#"context.input has shadowed && context.input.shadowed == "x""#,
            "context.input has named && context.input.named == 1",
        ] {
            assert!(
                !validates(&schema, READ, condition),
                "{condition}\n{generated}"
            );
        }

        let tools = serde_json::json!({"result": {
            "tools": [
                {"name": "read", "inputSchema": {
                    "type": "object",
                    "properties": {"own": {"$ref": "#/$defs/datetime"}},
                    "$defs": {"datetime": {"type": "object", "properties": {"b": {"type": "integer"}}, "required": ["b"]}}
                }},
                {"name": "other", "inputSchema": {
                    "type": "object",
                    "properties": {"server": {"$ref": "#/$defs/datetime"}}
                }}
            ],
            "$defs": {"datetime": {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}}
        }});
        let (generated, schema) = composed(&tools);
        let other = r#"cf::Action::"other""#;
        assert!(
            validates(
                &schema,
                READ,
                "context.input has own && context.input.own.b == 1"
            ),
            "a definition only the server scope renames keeps its shadowing\n{generated}"
        );
        assert!(!validates(
            &schema,
            READ,
            r#"context.input has own && context.input.own.a == "x""#
        ));
        assert!(
            validates(
                &schema,
                other,
                r#"context.input has server && context.input.server.a == "x""#
            ),
            "{generated}"
        );
    }

    #[test]
    fn a_reference_that_names_no_definition_names_none_after_a_rename() {
        let tools = referring_tools(
            "zone_record",
            serde_json::json!({"zone-record": {"type": "string"}}),
        );
        assert!(
            generate_mcp_schema("cf", &tools.to_string()).is_err(),
            "the rename never gives a definition the name of a dangling reference"
        );
    }

    #[test]
    fn a_definition_named_like_a_reserved_or_built_in_type_generates() {
        let field = serde_json::json!({"type": "object", "properties": {"x": {"type": "string"}}});
        let everywhere = [
            "if",
            "__cedar",
            "String",
            "Long",
            "Bool",
            "Boolean",
            "Set",
            "Record",
            "Entity",
            "Extension",
        ];
        let server_level = [
            "ipaddr",
            "decimal",
            "datetime",
            "duration",
            "readInput",
            "readOutput",
        ];
        let condition =
            r#"context.input has p && context.input.p has x && context.input.p.x == "v""#;
        for name in everywhere.iter().chain(&server_level) {
            let (generated, schema) = composed(&referring_tools(
                name,
                serde_json::json!({ *name: field.clone() }),
            ));
            assert!(validates(&schema, READ, condition), "{name}\n{generated}");
        }
        for name in everywhere {
            let tools = serde_json::json!({"result": {"tools": [{"name": "read", "inputSchema": {
                "type": "object",
                "properties": {"p": {"$ref": format!("#/$defs/{name}")}},
                "$defs": { name: field.clone() }
            }}]}});
            let (generated, schema) = composed(&tools);
            assert!(validates(&schema, READ, condition), "{name}\n{generated}");
        }
        let tools = serde_json::json!({"result": {"tools": [{"name": "read", "inputSchema": {
            "type": "object",
            "properties": {"p": {"$ref": "#/$defs/ipaddr"}},
            "$defs": {"ipaddr": field.clone()}
        }}]}});
        let (generated, _) = composed(&tools);
        assert!(
            generated.contains("type read_Input_ipaddr = "),
            "a name Cedar accepts in a tool's scope keeps it\n{generated}"
        );
    }

    #[test]
    fn an_unreferenced_definition_name_that_is_not_an_identifier_generates() {
        let tools = serde_json::json!({"result": {
            "tools": [{
                "name": "create_account",
                "inputSchema": {"type": "object", "$defs": {"create-account": {}}},
                "$defs": {"account-id": {"type": "string"}}
            }],
            "$defs": {"zone-record": {"type": "object"}}
        }});
        composed(&tools);
    }

    #[test]
    fn an_escaped_or_nested_definition_reference_resolves_to_its_definition() {
        let tools = serde_json::json!({"result": {
            "tools": [{"name": "read", "inputSchema": {"type": "object", "properties": {
                "slash": {"$ref": "#/$defs/a~1b"},
                "tilde": {"$ref": "#/$defs/a~0b"},
                "space": {"$ref": "#/$defs/zone%20record"},
                "literal": {"$ref": "#/$defs/x~1y"},
                "ordered": {"$ref": "#/$defs/p~01q"},
                "nested": {"$ref": "#/$defs/outer-def"}
            }}}],
            "$defs": {
                "a/b": {"type": "object", "properties": {"x": {"type": "string"}}},
                "a~b": {"type": "object", "properties": {"y": {"type": "integer"}}},
                "zone record": {"type": "object", "properties": {"z": {"type": "boolean"}}},
                "x~1y": {"type": "object", "properties": {"w": {"type": "string"}}},
                "x/y": {"type": "object", "properties": {"w": {"type": "integer"}}},
                "p~1q": {"type": "object", "properties": {"u": {"type": "string"}}},
                "p/q": {"type": "object", "properties": {"u": {"type": "integer"}}},
                "outer-def": {"type": "object", "properties": {"inner": {"$ref": "#/$defs/inner-def"}}},
                "inner-def": {"type": "object", "properties": {"leaf": {"$ref": "#/$defs/a~1b"}}}
            }
        }});
        let (generated, schema) = composed(&tools);

        for condition in [
            r#"context.input has slash && context.input.slash has x && context.input.slash.x == "v""#,
            "context.input has tilde && context.input.tilde has y && context.input.tilde.y == 1",
            "context.input has space && context.input.space has z && context.input.space.z",
            r#"context.input has literal && context.input.literal has w && context.input.literal.w == "v""#,
            r#"context.input has ordered && context.input.ordered has u && context.input.ordered.u == "v""#,
            r#"context.input has nested && context.input.nested has inner && context.input.nested.inner has leaf && context.input.nested.inner.leaf has x && context.input.nested.inner.leaf.x == "v""#,
        ] {
            assert!(
                validates(&schema, READ, condition),
                "{condition}\n{generated}"
            );
        }
        assert!(
            !validates(
                &schema,
                READ,
                "context.input has literal && context.input.literal has w && context.input.literal.w == 1"
            ),
            "a reference that names a definition literally keeps naming it\n{generated}"
        );
    }

    #[test]
    fn an_array_definition_of_objects_generates_at_every_level() {
        let element = serde_json::json!({
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"]
        });
        let tools = serde_json::json!({"result": {
            "tools": [{
                "name": "read",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rows": {"$ref": "#/$defs/rows"},
                        "cells": {"$ref": "#/$defs/cells"},
                        "entries": {"$ref": "#/$defs/entry-list"},
                        "tags": {"$ref": "#/$defs/tags"}
                    },
                    "$defs": {"entry-list": {"type": "array", "items": element.clone()}}
                },
                "$defs": {"cells": {"type": "array", "items": {
                    "type": "object",
                    "additionalProperties": {"type": "string"}
                }}}
            }],
            "$defs": {
                "rows": {"type": "array", "items": element.clone()},
                "tags": {"type": "array", "items": {"type": "object", "additionalProperties": true}}
            }
        }});
        let (generated, schema) = composed(&tools);

        for condition in [
            r#"context.input has rows && context.input.rows.contains({key: "x"})"#,
            r#"context.input has entries && context.input.entries.contains({key: "x"})"#,
            "context.input has cells && context.input.cells.isEmpty()",
            "context.input has tags && context.input.tags.isEmpty()",
        ] {
            assert!(
                validates(&schema, READ, condition),
                "{condition}\n{generated}"
            );
        }
        assert!(
            !validates(
                &schema,
                READ,
                "context.input has rows && context.input.rows.contains({key: 1})"
            ),
            "the element keeps its field types\n{generated}"
        );
    }

    #[test]
    fn an_array_of_arrays_definition_generates_beside_a_definition_named_like_its_element() {
        let tools = serde_json::json!({"result": {
            "tools": [{"name": "read", "inputSchema": {"type": "object", "properties": {
                "grid": {"$ref": "#/$defs/grid"},
                "label": {"$ref": "#/$defs/grid_item"}
            }}}],
            "$defs": {
                "grid": {"type": "array", "items": {"type": "array", "items": {
                    "type": "object",
                    "properties": {"v": {"type": "integer"}},
                    "required": ["v"]
                }}},
                "grid_item": {"type": "string"}
            }
        }});
        let (generated, schema) = composed(&tools);

        for condition in [
            "context.input has grid && context.input.grid.contains([{v: 1}])",
            r#"context.input has label && context.input.label == "x""#,
        ] {
            assert!(
                validates(&schema, READ, condition),
                "{condition}\n{generated}"
            );
        }
    }

    #[test]
    fn a_cycle_through_each_keyword_the_parser_follows_generates() {
        let string = serde_json::json!({"type": "string"});
        let cycles = [
            serde_json::json!({"A": {"type": "object", "properties": {"a": {"$ref": "#/$defs/A"}}}}),
            serde_json::json!({"A": {"type": "array", "items": {"$ref": "#/$defs/A"}}}),
            serde_json::json!({"A": {"type": "array", "prefixItems": [{"$ref": "#/$defs/A"}], "items": false}}),
            serde_json::json!({"A": {"anyOf": [{"$ref": "#/$defs/A"}, string.clone()]}}),
            serde_json::json!({"A": {"oneOf": [{"$ref": "#/$defs/A"}, string.clone()]}}),
            serde_json::json!({"A": {"type": ["object", "string"], "properties": {"a": {"$ref": "#/$defs/A"}}}}),
            serde_json::json!({"A": {"$ref": "#/$defs/A"}}),
            serde_json::json!({"A": {"$ref": "#/$defs/B"}, "B": {"$ref": "#/$defs/A"}}),
            serde_json::json!({
                "A": {"type": "object", "properties": {"b": {"$ref": "#/$defs/B"}}},
                "B": {"type": "array", "items": {"$ref": "#/$defs/A"}}
            }),
        ];
        for definitions in cycles {
            let (generated, _) = composed(&referring_tools("A", definitions.clone()));
            assert!(
                generated.contains("entity Unknown"),
                "{definitions}\n{generated}"
            );
            for tool in [
                serde_json::json!({"name": "read", "inputSchema": {
                    "type": "object",
                    "properties": {"p": {"$ref": "#/$defs/A"}},
                    "$defs": definitions.clone()
                }}),
                serde_json::json!({"name": "read", "$defs": definitions.clone(), "inputSchema": {
                    "type": "object",
                    "properties": {"p": {"$ref": "#/$defs/A"}}
                }}),
                serde_json::json!({"name": "read", "inputSchema": {"json": {
                    "type": "object",
                    "properties": {"p": {"$ref": "#/$defs/A"}},
                    "$defs": definitions.clone()
                }}}),
            ] {
                composed(&serde_json::json!({"result": {"tools": [tool]}}));
            }
        }
    }

    #[test]
    fn a_reference_the_parser_does_not_follow_into_a_common_type_stays_typed() {
        for definitions in [
            serde_json::json!({"A": {"type": "object", "additionalProperties": {"$ref": "#/$defs/A"}}}),
            serde_json::json!({"A": {"type": "object", "properties": {"x": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "properties": {"y": {"$ref": "#/$defs/A"}}
            }}}}),
            serde_json::json!({"A": {"allOf": [{"$ref": "#/$defs/A"}]}}),
            serde_json::json!({"A": {"not": {"$ref": "#/$defs/A"}}}),
            serde_json::json!({"A": {"type": "object", "patternProperties": {"x": {"$ref": "#/$defs/A"}}}}),
            serde_json::json!({"A": {"type": "string", "$ref": "#/$defs/A"}}),
            serde_json::json!({"A": {"anyOf": [{"type": "string"}], "oneOf": [{"$ref": "#/$defs/A"}]}}),
            serde_json::json!({"A": {"type": "array", "prefixItems": [{"$ref": "#/$defs/A"}], "items": {"type": "string"}}}),
            serde_json::json!({"A": {"type": "array", "prefixItems": [{"type": "string"}], "items": {"$ref": "#/$defs/A"}}}),
        ] {
            let tools = referring_tools("A", definitions.clone()).to_string();
            assert!(
                matches!(make_definitions_generable(&tools), Cow::Borrowed(_)),
                "{definitions}"
            );
            composed(&serde_json::from_str(&tools).expect("the tools parse"));
        }
    }

    #[test]
    fn fields_above_a_cut_reference_keep_their_types() {
        let tools = referring_tools(
            "Group",
            serde_json::json!({"Group": {"type": "object", "properties": {
                "name": {"type": "string"},
                "owner": {"type": "object", "properties": {"id": {"type": "integer"}}},
                "parent": {"$ref": "#/$defs/Group"}
            }}}),
        );
        let (generated, schema) = composed(&tools);

        for condition in [
            r#"context.input has p && context.input.p has name && context.input.p.name == "x""#,
            "context.input has p && context.input.p has owner && context.input.p.owner has id && context.input.p.owner.id == 1",
        ] {
            assert!(
                validates(&schema, READ, condition),
                "{condition}\n{generated}"
            );
        }
        assert!(
            !validates(
                &schema,
                READ,
                r#"context.input has p && context.input.p has parent && context.input.p.parent.name == "x""#
            ),
            "a rule that reads below the cut is refused at validation\n{generated}"
        );
    }

    #[test]
    fn a_definition_list_that_would_nest_too_deep_is_left_unchanged() {
        let deep = |length: usize| {
            let definitions = (0..length)
                .map(|index| {
                    (
                        format!("link-{index}"),
                        serde_json::json!({"type": "object", "properties": {
                            "next": {"$ref": format!("#/$defs/link-{}", (index + 1) % length)}
                        }}),
                    )
                })
                .collect::<serde_json::Map<_, _>>();
            referring_tools("link-0", serde_json::Value::Object(definitions)).to_string()
        };
        assert!(matches!(
            make_definitions_generable(&deep(MAXIMUM_DEFINITION_DEPTH / 4)),
            Cow::Owned(_)
        ));
        let tools = deep(MAXIMUM_DEFINITION_DEPTH);
        assert!(
            matches!(make_definitions_generable(&tools), Cow::Borrowed(_)),
            "a list whose definitions would nest deeper than the limit keeps its refusal"
        );
        assert!(generate_mcp_schema("cf", &tools).is_err());
        let mut nested = serde_json::json!({"type": "string"});
        for _ in 0..=MAXIMUM_DEFINITION_DEPTH / 2 {
            nested = serde_json::json!({"type": "object", "properties": {"inner": nested}});
        }
        let tools = referring_tools(
            "deep-rows",
            serde_json::json!({ "deep-rows": {"type": "array", "items": nested} }),
        );
        assert!(
            matches!(
                make_definitions_generable(&tools.to_string()),
                Cow::Borrowed(_)
            ),
            "the nesting inside one definition counts too"
        );

        let length = MAXIMUM_DEFINITION_DEPTH / 2 + 4;
        let mut definitions = (0..length)
            .map(|index| {
                let next = if index + 1 < length {
                    serde_json::json!({"$ref": format!("#/$defs/Link{}", index + 1)})
                } else {
                    serde_json::json!({"type": "string"})
                };
                (
                    format!("Link{index}"),
                    serde_json::json!({"type": "object", "properties": {"next": next}}),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        definitions.insert(
            "zone-record".to_string(),
            serde_json::json!({"type": "string"}),
        );
        let mut tools = referring_tools("Link0", serde_json::Value::Object(definitions));
        tools["result"]["tools"][0]["inputSchema"]["properties"]["zone"] =
            serde_json::json!({"$ref": "#/$defs/zone-record"});
        assert!(
            matches!(
                make_definitions_generable(&tools.to_string()),
                Cow::Owned(_)
            ),
            "a rename adds no nesting, so a deep list that needs only renames is fixed"
        );
        composed(&tools);
    }

    #[test]
    fn a_catalog_with_only_plain_definitions_is_left_unchanged() {
        let tools = serde_json::json!({"result": {
            "tools": [{
                "name": "read",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "a": {"$ref": "#/$defs/Shared"},
                        "b": {"$ref": "#/$defs/Local"},
                        "c": {"$ref": "#/$defs/Tree"},
                        "d": {"$ref": "#/$defs/ipaddr"},
                        "e": {"$ref": "#/$defs/Pair"},
                        "f": {"$ref": "#/$defs/Matrix"},
                        "g": {"$ref": "#/$defs/Top"}
                    },
                    "$defs": {
                        "Local": {"type": "array", "items": {"type": "string"}},
                        "ipaddr": {"type": "string"}
                    }
                },
                "$defs": {"Pair": {"type": "array", "prefixItems": [{"type": "object"}], "items": false}}
            }],
            "$defs": {
                "Shared": {"anyOf": [{"type": "string"}, {"type": "object", "properties": {"x": {"type": "string"}}}]},
                "Tree": {"type": "object", "additionalProperties": {"$ref": "#/$defs/Tree"}},
                "Matrix": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}},
                "Unknown": {"type": "object", "properties": {"x": {"type": "string"}}},
                "Top": {"type": "object", "properties": {"l": {"$ref": "#/$defs/Left"}, "r": {"$ref": "#/$defs/Right"}}},
                "Left": {"type": "object", "properties": {"b": {"$ref": "#/$defs/Bottom"}}},
                "Right": {"type": "object", "properties": {"b": {"$ref": "#/$defs/Bottom"}}},
                "Bottom": {"type": "object", "properties": {"x": {"type": "string"}}}
            }
        }})
        .to_string();
        assert!(matches!(
            make_definitions_generable(&tools),
            Cow::Borrowed(_)
        ));
        composed(&serde_json::from_str(&tools).expect("the tools parse"));
    }

    #[test]
    fn three_definition_problems_in_one_server_leave_the_healthy_tool_its_catalog() {
        let tools = serde_json::json!({"result": {"tools": [
            {"name": "get_zone", "inputSchema": {"type": "object",
                "properties": {"zone_id": {"type": "string"}}}},
            {"name": "create_account", "inputSchema": {"type": "object",
                "$defs": {"create-account": {}}}},
            {"name": "bulk_write", "inputSchema": {"type": "object",
                "$defs": {"rows": {"type": "array", "items": {"type": "object"}}}}},
            {"name": "validate_rule", "inputSchema": {"type": "object",
                "$defs": {"Group": {"type": "array", "items": {"$ref": "#/$defs/Group"}}}}}
        ]}});
        let (generated, schema) = composed(&tools);
        assert!(validates(
            &schema,
            r#"cf::Action::"get_zone""#,
            r#"context.input has zone_id && context.input.zone_id == "z""#
        ));
        for tool in ["create_account", "bulk_write", "validate_rule"] {
            assert!(
                generated.contains(&format!("action \"{tool}\"")),
                "{generated}"
            );
        }
    }

    #[test]
    fn many_definitions_on_one_base_and_a_long_cycle_generate() {
        let count = 1_000_u32;
        let cycle = 24;
        let names = (0x4e00_u32..0x4e00 + count)
            .filter_map(char::from_u32)
            .map(|character| format!("x{character}"))
            .collect::<Vec<_>>();
        let mut definitions = names
            .iter()
            .map(|name| (name.clone(), serde_json::json!({"type": "string"})))
            .collect::<serde_json::Map<_, _>>();
        for index in 0..cycle {
            definitions.insert(
                format!("link-{index}"),
                serde_json::json!({"type": "object", "properties": {
                    "next": {"$ref": format!("#/$defs/link-{}", (index + 1) % cycle)}
                }}),
            );
        }
        let properties = names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    format!("p{index}"),
                    serde_json::json!({"$ref": format!("#/$defs/{name}")}),
                )
            })
            .chain((0..count).map(|index| {
                (
                    format!("q{index}"),
                    serde_json::json!({"$ref": "#/$defs/link-0"}),
                )
            }))
            .collect::<serde_json::Map<_, _>>();
        let tools = serde_json::json!({"result": {
            "tools": [{"name": "read", "inputSchema": {"type": "object", "properties": properties}}],
            "$defs": definitions
        }});
        let (generated, schema) = composed(&tools);
        assert!(validates(
            &schema,
            READ,
            r#"context.input has p0 && context.input.p0 == "x""#
        ));
        assert!(validates(
            &schema,
            READ,
            "context.input has q999 && context.input.q999 has next && context.input.q999.next has next"
        ));

        assert!(
            generated.contains(&format!("type x__{count} = String;")),
            "{}",
            generated.len()
        );
    }
}
