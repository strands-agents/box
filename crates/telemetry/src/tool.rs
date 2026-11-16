//! An MCP tool call's flattened argument and output fields, and the per-target list that reveals them.
//!
//! A tool-call record carries every field's path and value. Each target's exporter then replaces
//! every value whose server, tool, and path its list does not name with [`REDACTED`], so one record
//! reaches a target that asked for a field with its value and every other target without it. The
//! paths always remain, so a reader sees which fields a call had and can choose which to reveal.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use opentelemetry::Key;
use opentelemetry::logs::AnyValue;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;

use crate::record::{REDACTED, bounded};

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

/// What stands in for an object key that is not a plain name.
const UNNAMED: &str = "*";

/// The longest object key the record copies.
const MAXIMUM_KEY_CHARS: usize = 64;

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
                fields.flatten(segment(name), member);
            }
        }
        fields
    }

    fn flatten(&mut self, path: &str, value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(members) => {
                for (name, member) in members {
                    self.flatten(&format!("{path}.{}", segment(name)), member);
                }
            }
            serde_json::Value::Array(elements) => {
                for (index, element) in elements.iter().enumerate() {
                    self.flatten(&format!("{path}.{index}"), element);
                }
            }
            scalar => {
                // Two keys that are not plain names share one path; keep the first.
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

/// One object key as a path segment: the key itself when it is a plain name, else [`UNNAMED`].
///
/// A tool can use data as a key, such as an email address, and a key is never redacted, so only a
/// name of letters, digits, `_`, `-`, and `$` is copied. No list can name `*`, so a value under an
/// unnamed key is always redacted.
fn segment(name: &str) -> &str {
    let plain = !name.is_empty()
        && name.chars().count() <= MAXIMUM_KEY_CHARS
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-$".contains(character));
    if plain { name } else { UNNAMED }
}

/// Whether `path` is one a target may name: dotted plain names and array indexes.
pub fn is_field_path(path: &str) -> bool {
    !path.is_empty()
        && path
            .split('.')
            .all(|part| !part.is_empty() && part != UNNAMED && segment(part) == part)
}

/// The fields of one server's tool that a target receives in clear text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolFieldList {
    /// Argument paths, as `context.input.` spells them.
    pub arguments: BTreeSet<String>,
    /// Output paths, as `output.structured.` spells them.
    pub output: BTreeSet<String>,
}

/// Which fields of which tools one target receives in clear text, keyed by `(server, tool)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ToolFieldAllowlist {
    pub(crate) tools: BTreeMap<(String, String), ToolFieldList>,
}

impl ToolFieldAllowlist {
    /// Replace every value this list does not name with [`REDACTED`], in place.
    ///
    /// It runs on the encoded request, before the request is written or sent.
    pub(crate) fn redact(&self, request: &mut ExportLogsServiceRequest) {
        for resource in &mut request.resource_logs {
            for scope in &mut resource.scope_logs {
                for record in &mut scope.log_records {
                    let text = |key: &str| {
                        record
                            .attributes
                            .iter()
                            .find(|attribute| attribute.key == key)
                            .and_then(|attribute| attribute.value.as_ref())
                            .and_then(|value| match &value.value {
                                Some(ProtoValue::StringValue(text)) => Some(text.clone()),
                                _ => None,
                            })
                    };
                    // A record that does not name its tool reveals nothing, rather than everything.
                    let list = match (text(SERVER), text(NAME)) {
                        (Some(server), Some(tool)) => self.tools.get(&(server, tool)),
                        _ => None,
                    };
                    for attribute in &mut record.attributes {
                        let allowed = match attribute.key.as_str() {
                            ARGUMENTS => list.map(|list| &list.arguments),
                            OUTPUT => list.map(|list| &list.output),
                            _ => continue,
                        };
                        let Some(ProtoValue::KvlistValue(fields)) = attribute
                            .value
                            .as_mut()
                            .and_then(|value| value.value.as_mut())
                        else {
                            continue;
                        };
                        for field in &mut fields.values {
                            if allowed.is_some_and(|allowed| allowed.contains(&field.key)) {
                                continue;
                            }
                            if let Some(value) = field.value.as_mut() {
                                value.value = Some(ProtoValue::StringValue(REDACTED.to_string()));
                            }
                        }
                        // A map emits in no fixed order; sort so two runs read the same.
                        fields
                            .values
                            .sort_by(|left, right| left.key.cmp(&right.key));
                    }
                }
            }
        }
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
    fn a_key_that_is_not_a_plain_name_is_not_copied() {
        let fields = ToolFields::of(&json!({
            "members": {"alice@example.com": "admin", "bob@example.com": "staff"},
            "user_name": "carol"
        }));
        let text = format!("{fields:?}");
        assert!(!text.contains("example.com"), "{text}");
        let mut paths = fields.paths();
        paths.sort_unstable();
        assert_eq!(paths, ["members.*", "user_name"]);
        assert_eq!(
            fields.omitted, 1,
            "the second unnamed key is counted, not copied"
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

    /// A record that does not name its server and tool reveals nothing, whatever the list says.
    #[test]
    fn a_record_without_its_tool_reveals_nothing() {
        use opentelemetry_proto::tonic::common::v1::{AnyValue as Proto, KeyValue, KeyValueList};
        use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
        let field = |key: &str, value: &str| KeyValue {
            key: key.to_string(),
            value: Some(Proto {
                value: Some(ProtoValue::StringValue(value.to_string())),
            }),
            ..KeyValue::default()
        };
        let mut request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord {
                        attributes: vec![KeyValue {
                            key: ARGUMENTS.to_string(),
                            value: Some(Proto {
                                value: Some(ProtoValue::KvlistValue(KeyValueList {
                                    values: vec![field("user_name", "ada")],
                                })),
                            }),
                            ..KeyValue::default()
                        }],
                        ..LogRecord::default()
                    }],
                    ..ScopeLogs::default()
                }],
                ..ResourceLogs::default()
            }],
        };
        let mut list = ToolFieldAllowlist::default();
        list.tools.insert(
            ("desk".to_string(), "lookup".to_string()),
            ToolFieldList {
                arguments: ["user_name".to_string()].into(),
                output: BTreeSet::new(),
            },
        );
        list.redact(&mut request);
        let text = format!("{request:?}");
        assert!(!text.contains("ada"), "{text}");
        assert!(text.contains(REDACTED), "{text}");
    }

    #[test]
    fn only_a_dotted_plain_path_may_be_named() {
        for good in ["user_name", "profile.email", "items.0", "a-b.$c"] {
            assert!(is_field_path(good), "{good}");
        }
        for bad in ["", ".", "a..b", "*", "members.*", "a b", "a@b", "x/y"] {
            assert!(!is_field_path(bad), "{bad}");
        }
    }
}
