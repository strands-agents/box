//! The tool pack file as its author writes it.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};

/// One `*.pack.toml` document.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackFile {
    /// Read by `Pack::parse` before the document deserializes.
    #[serde(rename = "format")]
    pub(crate) _format: serde::de::IgnoredAny,
    #[serde(default)]
    pub(crate) version: Option<toml::Value>,
    pub(crate) pack: String,
    pub(crate) program: String,
    #[serde(default)]
    pub(crate) effects: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) global: GlobalSpec,
    #[serde(default)]
    pub(crate) shell: BTreeMap<String, ShellActionSpec>,
}

/// The `[global]` table: options that come before the command words.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GlobalSpec {
    #[serde(default)]
    pub(crate) options: BTreeMap<String, OptionSpec>,
}

/// One `[shell.<action>]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShellActionSpec {
    pub(crate) usage: String,
    #[serde(default)]
    pub(crate) aliases: Vec<String>,
    #[serde(default)]
    pub(crate) adds: Vec<String>,
    #[serde(default)]
    pub(crate) options: BTreeMap<String, OptionSpec>,
    #[serde(default)]
    pub(crate) operands: BTreeMap<String, OperandSpec>,
}

/// One `options.<name>` entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OptionSpec {
    #[serde(deserialize_with = "one_or_many")]
    pub(crate) flag: Vec<String>,
    #[serde(default)]
    pub(crate) value: ValueSpec,
    #[serde(default)]
    pub(crate) repeated: bool,
    #[serde(default, deserialize_with = "one_or_many")]
    pub(crate) like: Vec<String>,
    #[serde(default)]
    pub(crate) adds: Vec<String>,
    #[serde(default)]
    pub(crate) removes: Vec<String>,
    #[serde(default)]
    pub(crate) when: Vec<WhenSpec>,
    #[serde(default)]
    pub(crate) anywhere: bool,
}

/// One `operands.<name>` entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperandSpec {
    #[serde(default, deserialize_with = "one_or_many")]
    pub(crate) like: Vec<String>,
    #[serde(default)]
    pub(crate) adds: Vec<String>,
    #[serde(default)]
    pub(crate) removes: Vec<String>,
    #[serde(default)]
    pub(crate) when: Vec<WhenSpec>,
    #[serde(default)]
    pub(crate) rest: bool,
}

/// One `when` entry on an option or an operand.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WhenSpec {
    #[serde(deserialize_with = "one_or_many")]
    pub(crate) like: Vec<String>,
    #[serde(default)]
    pub(crate) adds: Vec<String>,
    #[serde(default)]
    pub(crate) removes: Vec<String>,
}

/// Read one string or a list of strings as a list.
fn one_or_many<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    })
}

/// Whether an option takes a value.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ValueSpec {
    #[default]
    None,
    Required,
    Optional,
    Many,
}
