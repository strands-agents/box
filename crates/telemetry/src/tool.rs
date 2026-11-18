//! An MCP tool call's flattened argument and output fields, as a tool-call record carries them.
//!
//! The values are raw. Only a target whose `include` names `tool_calls` receives a tool-call
//! record, so the operator's choice of target is what decides who sees them.

use std::collections::HashMap;

use opentelemetry::Key;
use opentelemetry::logs::AnyValue;

use crate::record::bounded;

/// The attribute that carries a call's flattened arguments.
pub(crate) const ARGUMENTS: &str = "strands.box.tool.arguments";

/// The attribute that carries a call's flattened `structuredContent`.
pub(crate) const OUTPUT: &str = "strands.box.tool.output";

/// The attributes that name the call's server and tool.
pub(crate) const SERVER: &str = "strands.box.tool.server";
pub(crate) const NAME: &str = "strands.box.tool.name";

/// The most flattened fields one record carries, matching the shell's argument cap.
const MAXIMUM_FIELDS: usize = 64;

/// The attributes that say how many argument or output fields were left out, beside their maps.
///
/// Outside the map, because a map key is a data path, and data can spell any path.
pub(crate) const ARGUMENTS_OMITTED: &str = "strands.box.tool.arguments_omitted";
pub(crate) const OUTPUT_OMITTED: &str = "strands.box.tool.output_omitted";

/// Scalar fields flattened out of one JSON value, as dotted paths.
///
/// An object's member is `parent.member` and an array's element is `parent.N`, the paths a rule
/// writes after `context.input.` or `output.structured.`.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ToolFields {
    fields: Vec<(String, Scalar)>,
    omitted: usize,
}

/// One flattened value, keeping its JSON type so `true` and `"true"` stay apart.
#[derive(Debug, Clone, PartialEq)]
enum Scalar {
    Text(String),
    Boolean(bool),
    Integer(i64),
    Double(f64),
    /// A JSON `null`, written as an empty array, which no flattened value can otherwise be.
    Null,
}

impl Scalar {
    fn of(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::String(text) => Self::Text(bounded(text)),
            serde_json::Value::Bool(flag) => Self::Boolean(*flag),
            serde_json::Value::Number(number) => {
                if let Some(integer) = number.as_i64() {
                    Self::Integer(integer)
                } else if number.is_f64() {
                    Self::Double(number.as_f64().unwrap_or_default())
                } else {
                    // An integer beyond `i64` keeps its digits exactly, as text.
                    Self::Text(number.to_string())
                }
            }
            serde_json::Value::Null => Self::Null,
            // Objects and arrays are flattened before a scalar is read.
            other => Self::Text(bounded(&other.to_string())),
        }
    }

    fn value(&self) -> AnyValue {
        match self {
            Self::Text(text) => AnyValue::from(text.clone()),
            Self::Boolean(flag) => AnyValue::Boolean(*flag),
            Self::Integer(integer) => AnyValue::Int(*integer),
            Self::Double(double) => AnyValue::Double(*double),
            Self::Null => AnyValue::ListAny(Box::default()),
        }
    }
}

impl ToolFields {
    /// Flatten `value`'s scalars; a value that is not an object has no field names.
    pub(crate) fn of(value: &serde_json::Value) -> Self {
        let mut fields = Self::default();
        if let serde_json::Value::Object(members) = value {
            for (name, member) in members {
                fields.flatten(name, member);
            }
        }
        fields
    }

    fn flatten(&mut self, path: &str, value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(members) => {
                for (name, member) in members {
                    self.flatten(&format!("{path}.{name}"), member);
                }
            }
            serde_json::Value::Array(elements) => {
                for (index, element) in elements.iter().enumerate() {
                    self.flatten(&format!("{path}.{index}"), element);
                }
            }
            scalar => {
                // A key that holds a `.` can spell a nested path; keep the first.
                if self.fields.len() >= MAXIMUM_FIELDS
                    || self.fields.iter().any(|(known, _)| known == path)
                {
                    self.omitted += 1;
                    return;
                }
                self.fields.push((bounded(path), Scalar::of(scalar)));
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn paths(&self) -> Vec<&str> {
        self.fields.iter().map(|(path, _)| path.as_str()).collect()
    }

    pub(crate) fn attribute(&self) -> AnyValue {
        let map: HashMap<Key, AnyValue> = self
            .fields
            .iter()
            .map(|(path, value)| (Key::from(path.clone()), value.value()))
            .collect();
        AnyValue::Map(Box::new(map))
    }

    /// How many fields were left out, or `None` when none were.
    pub(crate) fn omitted(&self) -> Option<i64> {
        (self.omitted > 0).then(|| i64::try_from(self.omitted).unwrap_or(i64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_values_flatten_to_the_paths_a_rule_spells() {
        let fields = ToolFields::of(&json!({
            "user_name": "alice",
            "profile": {"email": "a@example.com", "tags": ["x", "y"]},
            "count": 3,
            "admin": false,
            "note": null
        }));
        let mut paths = fields.paths();
        paths.sort_unstable();
        assert_eq!(
            paths,
            [
                "admin",
                "count",
                "note",
                "profile.email",
                "profile.tags.0",
                "profile.tags.1",
                "user_name"
            ]
        );
    }

    #[test]
    fn a_key_is_kept_as_the_tool_wrote_it() {
        let fields = ToolFields::of(&json!({
            "members": {"alice@example.com": "admin"},
            "a.b": 1,
            "a": {"b": 2}
        }));
        let mut paths = fields.paths();
        paths.sort_unstable();
        assert_eq!(paths, ["a.b", "members.alice@example.com"]);
        assert_eq!(
            fields.omitted, 1,
            "a second field on one path is counted, not copied"
        );
    }

    #[test]
    fn a_non_object_flattens_to_nothing() {
        assert_eq!(ToolFields::of(&json!("text")), ToolFields::default());
        assert_eq!(ToolFields::of(&json!([1, 2])), ToolFields::default());
    }

    #[test]
    fn more_than_the_cap_counts_what_was_left_out() {
        let many: serde_json::Map<String, serde_json::Value> = (0..70)
            .map(|index| (format!("k{index:02}"), json!(index)))
            .collect();
        let fields = ToolFields::of(&serde_json::Value::Object(many));
        assert_eq!(fields.paths().len(), MAXIMUM_FIELDS);
        assert_eq!(fields.omitted, 6);
    }
}
