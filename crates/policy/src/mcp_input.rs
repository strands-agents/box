//! The declared input type of each MCP tool action, and the placement of a union member in it.

use std::collections::HashMap;
use std::sync::OnceLock;

use cedar_policy::EntityUid;
use serde_json::{Map, Value};

use crate::error::PolicyError;

const UNION_MEMBER_PREFIX: &str = "typeChoice";

const EXTENSION_TYPES: [&str; 4] = ["datetime", "decimal", "duration", "ipaddr"];

/// The input record type of each MCP tool action in one composed schema, resolved on first use.
#[derive(Debug, Default)]
pub(crate) struct ToolInputs {
    source: Option<String>,
    tool_actions: Vec<EntityUid>,
    resolved: OnceLock<Result<ResolvedInputs, String>>,
}

impl ToolInputs {
    /// Hold the composed schema source, when it declares a union, for the tool actions it names.
    pub(crate) fn new<'a>(
        source: &str,
        tool_actions: impl IntoIterator<Item = &'a EntityUid>,
    ) -> Self {
        let declares_union = source.contains(UNION_MEMBER_PREFIX);
        Self {
            source: declares_union.then(|| source.to_string()),
            tool_actions: if declares_union {
                tool_actions.into_iter().cloned().collect()
            } else {
                Vec::new()
            },
            resolved: OnceLock::new(),
        }
    }

    /// The arguments of one tool call with each union member placed in its `typeChoice` record,
    /// or `None` when the tool's input declares no union.
    pub(crate) fn conform(
        &self,
        action: &EntityUid,
        arguments: &Value,
    ) -> Result<Option<Value>, PolicyError> {
        let Some(source) = &self.source else {
            return Ok(None);
        };
        let resolved = self
            .resolved
            .get_or_init(|| ResolvedInputs::from_schema(source, &self.tool_actions))
            .as_ref()
            .map_err(|error| PolicyError::Schema(error.clone()))?;
        resolved.conform(action, arguments)
    }
}

/// The resolved input types of the tool actions whose input declares a union.
#[derive(Debug)]
struct ResolvedInputs {
    inputs: HashMap<EntityUid, Value>,
    common_types: HashMap<String, Value>,
}

impl ResolvedInputs {
    fn from_schema(source: &str, tool_actions: &[EntityUid]) -> Result<Self, String> {
        let (schema, _) = cedar_policy::schema_str_to_json_with_resolved_types(source)
            .map_err(|error| error.to_string())?;
        let mut common_types = HashMap::new();
        if let Some(namespaces) = schema.as_object() {
            for (namespace, fragment) in namespaces {
                let Some(types) = fragment.get("commonTypes").and_then(Value::as_object) else {
                    continue;
                };
                for (name, ty) in types {
                    let qualified = if namespace.is_empty() {
                        name.clone()
                    } else {
                        format!("{namespace}::{name}")
                    };
                    common_types.insert(qualified, ty.clone());
                }
            }
        }
        let mut resolved = Self {
            inputs: HashMap::new(),
            common_types,
        };
        resolved.inputs = tool_actions
            .iter()
            .filter_map(|action| {
                let (namespace, tool) = crate::schema::mcp_tool_action(action)?;
                let input = schema
                    .get(&namespace)?
                    .get("actions")?
                    .get(&tool)?
                    .pointer("/appliesTo/context/attributes/input")?;
                resolved
                    .contains_union(input)
                    .then(|| (action.clone(), input.clone()))
            })
            .collect();
        Ok(resolved)
    }

    fn contains_union(&self, ty: &Value) -> bool {
        let ty = self.resolve(ty);
        union_members(ty).is_some()
            || ty
                .get("attributes")
                .and_then(Value::as_object)
                .is_some_and(|attributes| attributes.values().any(|ty| self.contains_union(ty)))
            || ty.get("element").is_some_and(|ty| self.contains_union(ty))
    }

    fn conform(&self, action: &EntityUid, arguments: &Value) -> Result<Option<Value>, PolicyError> {
        let Some(input) = self.inputs.get(action) else {
            return Ok(None);
        };
        self.conform_value(arguments, input).map(Some)
    }

    fn resolve<'a>(&'a self, ty: &'a Value) -> &'a Value {
        let mut ty = ty;
        for _ in 0..=self.common_types.len() {
            match ty
                .get("type")
                .and_then(Value::as_str)
                .and_then(|name| self.common_types.get(name))
            {
                Some(common) => ty = common,
                None => break,
            }
        }
        ty
    }

    fn conform_value(&self, value: &Value, ty: &Value) -> Result<Value, PolicyError> {
        let ty = self.resolve(ty);
        if let Some(members) = union_members(ty) {
            return self.union_value(value, members).ok_or_else(|| {
                PolicyError::Schema(format!(
                    "invalid MCP tool arguments: {} matches no member of the declared union",
                    shown(value)
                ))
            });
        }
        match (ty.get("type").and_then(Value::as_str), value) {
            (Some("Record"), Value::Object(fields)) => {
                let attributes = ty.get("attributes").and_then(Value::as_object);
                fields
                    .iter()
                    .map(|(name, field)| {
                        let field = match attributes.and_then(|attributes| attributes.get(name)) {
                            Some(attribute) => self.conform_value(field, attribute)?,
                            None => field.clone(),
                        };
                        Ok((name.clone(), field))
                    })
                    .collect::<Result<Map<_, _>, _>>()
                    .map(Value::Object)
            }
            (Some("Set"), Value::Array(items)) => match ty.get("element") {
                Some(element) => items
                    .iter()
                    .map(|item| self.conform_value(item, element))
                    .collect::<Result<Vec<_>, _>>()
                    .map(Value::Array),
                None => Ok(value.clone()),
            },
            _ => Ok(value.clone()),
        }
    }

    fn member_value(&self, value: &Value, ty: &Value) -> Option<Value> {
        let ty = self.resolve(ty);
        if let Some(members) = union_members(ty) {
            return self.union_value(value, members);
        }
        match (ty.get("type").and_then(Value::as_str)?, value) {
            ("String", Value::String(_)) | ("Bool" | "Boolean", Value::Bool(_)) => {
                Some(value.clone())
            }
            ("Long", Value::Number(number)) if number.is_i64() => Some(value.clone()),
            ("Extension", Value::String(text)) => {
                let name = ty.get("name").and_then(Value::as_str)?;
                extension_accepts(name, text).then(|| value.clone())
            }
            (name, Value::String(text)) if EXTENSION_TYPES.contains(&name) => {
                extension_accepts(name, text).then(|| value.clone())
            }
            ("Set", Value::Array(items)) => {
                let element = ty.get("element")?;
                items
                    .iter()
                    .map(|item| self.member_value(item, element))
                    .collect::<Option<Vec<_>>>()
                    .map(Value::Array)
            }
            ("Record", Value::Object(fields)) => {
                let attributes = ty.get("attributes").and_then(Value::as_object);
                let empty = Map::new();
                let attributes = attributes.unwrap_or(&empty);
                let required_present = attributes.iter().all(|(name, attribute)| {
                    attribute.get("required").and_then(Value::as_bool) == Some(false)
                        || fields.contains_key(name)
                });
                if !required_present {
                    return None;
                }
                fields
                    .iter()
                    .map(|(name, field)| {
                        self.member_value(field, attributes.get(name)?)
                            .map(|field| (name.clone(), field))
                    })
                    .collect::<Option<Map<_, _>>>()
                    .map(Value::Object)
            }
            _ => None,
        }
    }

    fn union_value(&self, value: &Value, members: Vec<(&String, &Value)>) -> Option<Value> {
        let placed = members
            .into_iter()
            .filter_map(|(name, member)| {
                self.member_value(value, member)
                    .map(|member_value| (name.clone(), member_value))
            })
            .collect::<Map<_, _>>();
        (!placed.is_empty()).then_some(Value::Object(placed))
    }
}

/// The members of a `typeChoice` record in declaration order, or `None` for any other record.
fn union_members(ty: &Value) -> Option<Vec<(&String, &Value)>> {
    let attributes = ty.get("attributes")?.as_object()?;
    let mut members = attributes
        .iter()
        .map(|(name, member)| Some((union_member_index(name)?, name, member)))
        .collect::<Option<Vec<_>>>()?;
    if members.is_empty() {
        return None;
    }
    members.sort_by_key(|(index, _, _)| *index);
    Some(
        members
            .into_iter()
            .map(|(_, name, member)| (name, member))
            .collect(),
    )
}

fn union_member_index(name: &str) -> Option<u64> {
    let digits = name.strip_prefix(UNION_MEMBER_PREFIX)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn shown(value: &Value) -> String {
    const LIMIT: usize = 80;
    let text = value.to_string();
    match text.char_indices().nth(LIMIT) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}

/// Whether Cedar's constructor for the extension type `name` accepts `text`.
fn extension_accepts(name: &str, text: &str) -> bool {
    if !EXTENSION_TYPES.contains(&name)
        || text
            .chars()
            .any(|character| character == '"' || character == '\\' || character.is_control())
    {
        return false;
    }
    let constructor = if name == "ipaddr" { "ip" } else { name };
    let Ok(expression) = format!("{constructor}(\"{text}\")").parse::<cedar_policy::Expression>()
    else {
        return false;
    };
    let Ok(uid) = r#"Box::Agent::"conform""#.parse::<EntityUid>() else {
        return false;
    };
    let Ok(request) = cedar_policy::Request::new(
        uid.clone(),
        uid.clone(),
        uid,
        cedar_policy::Context::empty(),
        None,
    ) else {
        return false;
    };
    cedar_policy::eval_expression(&request, &cedar_policy::Entities::empty(), &expression).is_ok()
}
