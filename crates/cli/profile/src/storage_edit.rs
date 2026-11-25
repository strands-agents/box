//! The parts of a JSON or TOML file that a `[[storage.files]]` copy keeps, and the values it sets.

use serde_json::{Map, Value};
use toml_edit::{DocumentMut, InlineTable, Item, Table};

use crate::mcp::Format;

/// A list of keys, one for each level of a file.
pub type KeyPath = Vec<String>;

/// One `[[storage.files.set]]` row: the value a copy holds at `key` after each run. The value is
/// a string, a number, a boolean, or a list of those.
#[derive(Debug, Clone, PartialEq)]
pub struct Setting {
    pub key: KeyPath,
    pub value: toml::Value,
}

/// How a row changes the file it copies.
#[derive(Debug, Clone, PartialEq)]
pub struct Edit {
    pub kind: Format,
    /// The paths that reach storage, or `None` to keep the whole file.
    pub keep: Option<Vec<KeyPath>>,
    pub set: Vec<Setting>,
    /// Each run adds each `keep` value that the copy lacks.
    pub fill: bool,
    /// The kept paths whose different saved and source values produce a warning.
    pub warn_if_different: Vec<KeyPath>,
}

/// What `keep` takes from one host file, by key path.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Kept {
    pub kept: Vec<KeyPath>,
    pub dropped: Vec<KeyPath>,
    pub missing: Vec<KeyPath>,
}

/// A `set` row that cannot apply: the path whose value is in the way, and what that value is.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Blocked {
    pub(crate) at: KeyPath,
    pub(crate) what: &'static str,
}

/// Why a file cannot be edited.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Failure {
    /// The text is not the row's `kind`.
    Parse(String),
    /// The `set` row at this index meets a value that is not a table.
    Set(usize, Blocked),
}

impl Edit {
    /// What `keep` takes from `host`.
    pub(crate) fn kept(&self, host: &str) -> Result<Kept, Failure> {
        self.first_copy(host).map(|(_, kept)| kept)
    }

    /// The text of the first copy of `host`: the `keep` paths, then each `set` row.
    pub(crate) fn first_copy(&self, host: &str) -> Result<(String, Kept), Failure> {
        let mut document = Document::parse(self.kind, host)?;
        let kept = match &self.keep {
            Some(keep) => document.keep(keep),
            None => Kept::default(),
        };
        document.set(&self.set)?;
        Ok((document.text(), kept))
    }

    /// `copy` with each `keep` value of `host` that it lacks, and the paths added, or `None` when
    /// it lacks none. A value already in `copy` stays, and a path whose parent in `copy` is not a
    /// table is not added.
    pub(crate) fn fill(
        &self,
        copy: &str,
        host: &str,
    ) -> Result<Option<(String, Vec<KeyPath>)>, Failure> {
        let mut copied = Document::parse(self.kind, copy)?;
        let Some(keep) = &self.keep else {
            return Ok(None);
        };
        let mut host = Document::parse(self.kind, host)?;
        host.keep(keep);
        let mut added = Vec::new();
        for path in keep {
            if copied.add_from(&host, path) {
                added.push(path.clone());
            }
        }
        if added.is_empty() {
            return Ok(None);
        }
        Ok(Some((copied.text(), added)))
    }

    /// `copy` with each `set` row applied, or `None` when it already holds each value.
    pub(crate) fn rewrite(&self, copy: &str) -> Result<Option<String>, Failure> {
        let mut document = Document::parse(self.kind, copy)?;
        document.set(&self.set)?;
        let text = document.text();
        Ok((text != copy).then_some(text))
    }

    /// A new file that holds only the `set` values, or `None` when the row sets nothing.
    pub(crate) fn fresh(&self) -> Result<Option<String>, Failure> {
        if self.set.is_empty() {
            return Ok(None);
        }
        let empty = match self.kind {
            Format::Json => "{}",
            Format::Toml => "",
        };
        let mut document = Document::parse(self.kind, empty)?;
        document.set(&self.set)?;
        Ok(Some(document.text()))
    }
}

/// `path` joined with dots, with each key that is not a bare word in quotes.
pub fn shown(path: &[String]) -> String {
    path.iter()
        .map(|key| {
            if !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                key.clone()
            } else {
                format!("{key:?}")
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

enum Document {
    Json(Value),
    Toml(DocumentMut),
}

impl Document {
    fn parse(kind: Format, text: &str) -> Result<Self, Failure> {
        match kind {
            Format::Json => serde_json::from_str(text)
                .map(Self::Json)
                .map_err(|error| Failure::Parse(format!("not JSON: {error}"))),
            Format::Toml => text
                .parse::<DocumentMut>()
                .map(Self::Toml)
                .map_err(|error| {
                    let first = error.to_string();
                    let first = first.lines().next().unwrap_or_default().to_string();
                    Failure::Parse(format!("not TOML: {first}"))
                }),
        }
    }

    fn keep(&mut self, keep: &[KeyPath]) -> Kept {
        let mut kept = Kept::default();
        match self {
            Self::Json(value) => {
                let kept_value = match value {
                    Value::Object(map) => json_keep(map, keep, &mut Vec::new(), &mut kept),
                    _ => Map::new(),
                };
                *value = Value::Object(kept_value);
            }
            Self::Toml(document) => {
                toml_keep(document.as_table_mut(), keep, &mut Vec::new(), &mut kept);
                toml_bare_table(document.as_table_mut());
                document.set_trailing("");
            }
        }
        kept.missing = keep
            .iter()
            .filter(|path| !kept.kept.iter().any(|done| path.starts_with(done)))
            .cloned()
            .collect();
        kept
    }

    fn add_from(&mut self, source: &Self, path: &[String]) -> bool {
        match (self, source) {
            (Self::Json(copy), Self::Json(Value::Object(source))) => {
                json_at(source, path).is_some_and(|value| json_add(copy, path, value))
            }
            (Self::Toml(copy), Self::Toml(source)) => {
                let value = path
                    .iter()
                    .try_fold(source.as_item(), |item, key| item.get(key));
                value.is_some_and(|value| toml_add(copy.as_item_mut(), path, value))
            }
            _ => false,
        }
    }

    fn set(&mut self, set: &[Setting]) -> Result<(), Failure> {
        for (index, setting) in set.iter().enumerate() {
            match self {
                Self::Json(value) => json_set(value, &setting.key, 0, &setting.value),
                Self::Toml(document) => {
                    toml_set(document.as_item_mut(), &setting.key, 0, &setting.value)
                }
            }
            .map_err(|blocked| Failure::Set(index, blocked))?;
        }
        Ok(())
    }

    fn text(&self) -> String {
        match self {
            Self::Json(value) => {
                let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
                text.push('\n');
                text
            }
            Self::Toml(document) => document.to_string(),
        }
    }
}

/// Whether some `keep` path lies strictly below `path`.
fn leads_to(keep: &[KeyPath], path: &[String]) -> bool {
    keep.iter()
        .any(|kept| kept.len() > path.len() && kept.starts_with(path))
}

/// The entries of `map` at `at` that `keep` names, with the parents they need.
fn json_keep(
    map: &Map<String, Value>,
    keep: &[KeyPath],
    at: &mut KeyPath,
    kept: &mut Kept,
) -> Map<String, Value> {
    let mut out = Map::new();
    for (key, value) in map {
        at.push(key.clone());
        if keep.contains(at) {
            kept.kept.push(at.clone());
            out.insert(key.clone(), value.clone());
        } else if let (true, Value::Object(inner)) = (leads_to(keep, at), value) {
            let inner = json_keep(inner, keep, at, kept);
            if !inner.is_empty() {
                out.insert(key.clone(), Value::Object(inner));
            }
        } else {
            kept.dropped.push(at.clone());
        }
        at.pop();
    }
    out
}

/// Remove each entry of `table` at `at` that `keep` does not name, and each table it empties.
fn toml_keep(
    table: &mut dyn toml_edit::TableLike,
    keep: &[KeyPath],
    at: &mut KeyPath,
    kept: &mut Kept,
) {
    let keys: Vec<String> = table.iter().map(|(key, _)| key.to_string()).collect();
    for key in keys {
        at.push(key.clone());
        if keep.contains(at) {
            kept.kept.push(at.clone());
        } else if let (true, Some(inner)) = (
            leads_to(keep, at),
            table.get_mut(&key).and_then(Item::as_table_like_mut),
        ) {
            toml_keep(inner, keep, at, kept);
            if inner.is_empty() {
                table.remove(&key);
            }
        } else {
            kept.dropped.push(at.clone());
            table.remove(&key);
        }
        at.pop();
    }
}

/// Remove each comment and the layout around each key and value in `table`.
fn toml_bare_table(table: &mut toml_edit::Table) {
    table.decor_mut().clear();
    for (mut key, item) in table.iter_mut() {
        key.leaf_decor_mut().clear();
        key.dotted_decor_mut().clear();
        toml_bare_item(item);
    }
}

fn toml_bare_item(item: &mut Item) {
    match item {
        Item::None => {}
        Item::Table(table) => toml_bare_table(table),
        Item::ArrayOfTables(tables) => tables.iter_mut().for_each(toml_bare_table),
        Item::Value(value) => toml_bare_value(value),
    }
}

fn toml_bare_value(value: &mut toml_edit::Value) {
    value.decor_mut().clear();
    match value {
        toml_edit::Value::Array(array) => {
            array.set_trailing("");
            array.set_trailing_comma(false);
            array.iter_mut().for_each(toml_bare_value);
            array.fmt();
        }
        toml_edit::Value::InlineTable(table) => {
            table.set_trailing("");
            table.set_trailing_comma(false);
            for (mut key, value) in table.iter_mut() {
                key.leaf_decor_mut().clear();
                key.dotted_decor_mut().clear();
                toml_bare_value(value);
            }
            table.fmt();
        }
        _ => {}
    }
}

/// The value of `map` at `path`, if each level holds it.
fn json_at<'a>(map: &'a Map<String, Value>, path: &[String]) -> Option<&'a Value> {
    let (last, parents) = path.split_last()?;
    let mut map = map;
    for key in parents {
        map = map.get(key)?.as_object()?;
    }
    map.get(last)
}

/// Add `value` at `path` in `document` when the path is absent, creating each missing table, and
/// whether it was added.
fn json_add(document: &mut Value, path: &[String], value: &Value) -> bool {
    let Some((last, parents)) = path.split_last() else {
        return false;
    };
    let mut current = document;
    for key in parents {
        let Value::Object(map) = current else {
            return false;
        };
        current = map
            .entry(key.clone())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    let Value::Object(map) = current else {
        return false;
    };
    if map.contains_key(last) {
        return false;
    }
    map.insert(last.clone(), value.clone());
    true
}

fn toml_add(document: &mut Item, path: &[String], value: &Item) -> bool {
    let Some((name, rest)) = path.split_first() else {
        return false;
    };
    let inline = matches!(document, Item::Value(toml_edit::Value::InlineTable(_)));
    let Some(table) = document.as_table_like_mut() else {
        return false;
    };
    if rest.is_empty() {
        if table.contains_key(name) {
            return false;
        }
        let mut value = value.clone();
        toml_bare_item(&mut value);
        if inline {
            value.make_value();
        }
        table.insert(name, value);
        return true;
    }
    if table.get(name).is_none() {
        let child = if inline {
            Item::Value(toml_edit::Value::InlineTable(InlineTable::new()))
        } else {
            let mut child = Table::new();
            child.set_implicit(true);
            Item::Table(child)
        };
        table.insert(name, child);
    }
    table
        .get_mut(name)
        .is_some_and(|child| toml_add(child, rest, value))
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "a table",
    }
}

fn json_set(
    value: &mut Value,
    key: &[String],
    depth: usize,
    text: &toml::Value,
) -> Result<(), Blocked> {
    let Value::Object(map) = value else {
        return Err(Blocked {
            at: key[..depth].to_vec(),
            what: json_kind(value),
        });
    };
    let name = &key[depth];
    if depth + 1 < key.len() {
        let child = map
            .entry(name.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        return json_set(child, key, depth + 1, text);
    }
    match map.get_mut(name) {
        Some(held @ Value::Object(_)) => Err(Blocked {
            at: key.to_vec(),
            what: json_kind(held),
        }),
        Some(held) => {
            *held = json_value(text);
            Ok(())
        }
        None => {
            map.insert(name.clone(), json_value(text));
            Ok(())
        }
    }
}

/// A `set` value as JSON. `lang` admits only strings, finite numbers, booleans, and lists of those.
fn json_value(value: &toml::Value) -> Value {
    match value {
        toml::Value::String(text) => Value::String(text.clone()),
        toml::Value::Integer(number) => Value::from(*number),
        toml::Value::Float(number) => Value::from(*number),
        toml::Value::Boolean(flag) => Value::Bool(*flag),
        toml::Value::Array(items) => Value::Array(items.iter().map(json_value).collect()),
        toml::Value::Datetime(date) => Value::String(date.to_string()),
        toml::Value::Table(_) => Value::Null,
    }
}

fn toml_kind(item: &Item) -> &'static str {
    match item {
        Item::None => "nothing",
        Item::Table(_) | Item::Value(toml_edit::Value::InlineTable(_)) => "a table",
        Item::ArrayOfTables(_) | Item::Value(toml_edit::Value::Array(_)) => "a list",
        Item::Value(toml_edit::Value::String(_)) => "a string",
        Item::Value(toml_edit::Value::Integer(_) | toml_edit::Value::Float(_)) => "a number",
        Item::Value(toml_edit::Value::Boolean(_)) => "a boolean",
        Item::Value(toml_edit::Value::Datetime(_)) => "a date",
    }
}

fn toml_set(
    item: &mut Item,
    key: &[String],
    depth: usize,
    text: &toml::Value,
) -> Result<(), Blocked> {
    let inline = matches!(item, Item::Value(toml_edit::Value::InlineTable(_)));
    let what = toml_kind(item);
    let Some(table) = item.as_table_like_mut() else {
        return Err(Blocked {
            at: key[..depth].to_vec(),
            what,
        });
    };
    let name = key[depth].as_str();
    if depth + 1 < key.len() {
        if table.get(name).is_none() {
            let child = if inline {
                Item::Value(toml_edit::Value::InlineTable(InlineTable::new()))
            } else {
                let mut child = Table::new();
                child.set_implicit(true);
                Item::Table(child)
            };
            table.insert(name, child);
        }
        let child = table.get_mut(name).ok_or(Blocked {
            at: key[..=depth].to_vec(),
            what: "nothing",
        })?;
        return toml_set(child, key, depth + 1, text);
    }
    match table.get_mut(name) {
        Some(Item::Value(held)) if !matches!(held, toml_edit::Value::InlineTable(_)) => {
            let decor = held.decor().clone();
            let mut value = toml_value(text);
            *value.decor_mut() = decor;
            *held = value;
            Ok(())
        }
        Some(Item::ArrayOfTables(_)) => {
            table.remove(name);
            table.insert(name, Item::Value(toml_value(text)));
            Ok(())
        }
        Some(held) => Err(Blocked {
            at: key.to_vec(),
            what: toml_kind(held),
        }),
        None => {
            table.insert(name, Item::Value(toml_value(text)));
            Ok(())
        }
    }
}

/// A `set` value as a `toml_edit` value.
fn toml_value(value: &toml::Value) -> toml_edit::Value {
    match value {
        toml::Value::String(text) => text.as_str().into(),
        toml::Value::Integer(number) => (*number).into(),
        toml::Value::Float(number) => (*number).into(),
        toml::Value::Boolean(flag) => (*flag).into(),
        toml::Value::Datetime(date) => date.to_string().into(),
        toml::Value::Array(items) => {
            toml_edit::Value::Array(items.iter().map(toml_value).collect())
        }
        toml::Value::Table(_) => InlineTable::new().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(keys: &[&str]) -> KeyPath {
        keys.iter().map(|key| (*key).to_string()).collect()
    }

    fn edit(kind: Format, keep: Option<&[&[&str]]>, set: &[(&[&str], &str)]) -> Edit {
        Edit {
            kind,
            keep: keep.map(|keep| keep.iter().map(|keys| path(keys)).collect()),
            set: set
                .iter()
                .map(|(key, value)| Setting {
                    key: path(key),
                    value: (*value).into(),
                })
                .collect(),
            fill: false,
            warn_if_different: Vec::new(),
        }
    }

    const TRUST: &[&str] = &["projects", "/Users/me/my.app", "trust_level"];

    #[test]
    fn a_json_set_adds_a_missing_level_and_keeps_the_order_of_the_rest() {
        let host = r#"{
  "model": "gpt-5.6",
  "projects": {
    "/Users/me/other": { "trust_level": "untrusted" }
  }
}"#;
        let (text, _) = edit(Format::Json, None, &[(TRUST, "trusted")])
            .first_copy(host)
            .expect("an edit");
        assert_eq!(
            text,
            r#"{
  "model": "gpt-5.6",
  "projects": {
    "/Users/me/other": {
      "trust_level": "untrusted"
    },
    "/Users/me/my.app": {
      "trust_level": "trusted"
    }
  }
}
"#
        );
    }

    #[test]
    fn a_json_set_replaces_a_value_where_it_stands() {
        let copy = r#"{"projects":{"/Users/me/my.app":{"trust_level":"untrusted","notes":"x"}}}"#;
        let text = edit(Format::Json, None, &[(TRUST, "trusted")])
            .rewrite(copy)
            .expect("an edit")
            .expect("a change");
        assert_eq!(
            text,
            r#"{
  "projects": {
    "/Users/me/my.app": {
      "trust_level": "trusted",
      "notes": "x"
    }
  }
}
"#
        );
    }

    #[test]
    fn a_toml_set_adds_a_table_and_keeps_comments_and_layout() {
        let host = "# My settings. Comments stay.\nmodel = \"gpt-5.6\"\n\n\
                    [projects.\"/Users/me/other\"]\ntrust_level = \"untrusted\"\n";
        let (text, _) = edit(Format::Toml, None, &[(TRUST, "trusted")])
            .first_copy(host)
            .expect("an edit");
        assert_eq!(
            text,
            "# My settings. Comments stay.\nmodel = \"gpt-5.6\"\n\n\
             [projects.\"/Users/me/other\"]\ntrust_level = \"untrusted\"\n\n\
             [projects.\"/Users/me/my.app\"]\ntrust_level = \"trusted\"\n"
        );
    }

    #[test]
    fn a_toml_set_replaces_a_value_and_keeps_its_comment() {
        let copy = "[projects.\"/Users/me/my.app\"]\n\
                    trust_level = \"untrusted\"   # set by me\nnotes = \"x\"\n";
        let text = edit(Format::Toml, None, &[(TRUST, "trusted")])
            .rewrite(copy)
            .expect("an edit")
            .expect("a change");
        assert_eq!(
            text,
            "[projects.\"/Users/me/my.app\"]\n\
             trust_level = \"trusted\"   # set by me\nnotes = \"x\"\n"
        );
    }

    #[test]
    fn a_toml_set_writes_into_an_inline_table() {
        let copy = "projects = { other = { trust_level = \"untrusted\" } }\n";
        let text = edit(
            Format::Toml,
            None,
            &[(&["projects", "mine", "trust_level"], "trusted")],
        )
        .rewrite(copy)
        .expect("an edit")
        .expect("a change");
        let parsed: toml::Table = toml::from_str(&text).expect("TOML");
        assert_eq!(
            parsed["projects"]["mine"]["trust_level"].as_str(),
            Some("trusted")
        );
        assert_eq!(
            parsed["projects"]["other"]["trust_level"].as_str(),
            Some("untrusted")
        );
    }

    #[test]
    fn a_set_that_already_holds_its_value_changes_nothing() {
        let copy = "{\n  \"shellPath\": \"/box/bin/bash\"\n}\n";
        let edit = edit(Format::Json, None, &[(&["shellPath"], "/box/bin/bash")]);
        assert_eq!(edit.rewrite(copy).expect("an edit"), None);
    }

    #[test]
    fn a_set_stops_at_a_parent_that_is_not_a_table_and_at_a_key_that_holds_one_and_replaces_a_list()
    {
        for kind in [Format::Json, Format::Toml] {
            let (string_parent, table_key, list_key) = match kind {
                Format::Json => (
                    r#"{"projects": "none"}"#,
                    r#"{"projects": {"/Users/me/my.app": {"trust_level": {"a": "b"}}}}"#,
                    r#"{"projects": {"/Users/me/my.app": {"trust_level": ["a"]}}}"#,
                ),
                Format::Toml => (
                    "projects = \"none\"\n",
                    "[projects.\"/Users/me/my.app\".trust_level]\na = \"b\"\n",
                    "[projects.\"/Users/me/my.app\"]\ntrust_level = [\"a\"]\n",
                ),
            };
            let edit = edit(kind, None, &[(&["x"], "y"), (TRUST, "trusted")]);
            assert_eq!(
                edit.rewrite(string_parent),
                Err(Failure::Set(
                    1,
                    Blocked {
                        at: path(&["projects"]),
                        what: "a string"
                    }
                )),
                "{kind:?}"
            );
            assert_eq!(
                edit.rewrite(table_key),
                Err(Failure::Set(
                    1,
                    Blocked {
                        at: path(TRUST),
                        what: "a table"
                    }
                )),
                "{kind:?}"
            );
            let replaced = edit
                .rewrite(list_key)
                .expect("a list is replaced")
                .expect("a change");
            assert!(replaced.contains("trusted"), "{kind:?}: {replaced}");
        }
    }

    fn typed(kind: Format, set: &[(&[&str], toml::Value)]) -> Edit {
        Edit {
            kind,
            keep: None,
            set: set
                .iter()
                .map(|(key, value)| Setting {
                    key: path(key),
                    value: value.clone(),
                })
                .collect(),
            fill: false,
            warn_if_different: Vec::new(),
        }
    }

    fn values() -> Vec<(&'static [&'static str], toml::Value)> {
        vec![
            (&["onboarded"][..], toml::Value::Boolean(true)),
            (&["retries"][..], toml::Value::Integer(3)),
            (&["ratio"][..], toml::Value::Float(0.5)),
            (
                &["dirs"][..],
                toml::Value::Array(vec!["/w".into(), toml::Value::Array(vec![1.into()])]),
            ),
        ]
    }

    #[test]
    fn a_json_set_writes_a_number_a_boolean_and_a_list_and_replaces_a_list() {
        let host = "{\n  \"dirs\": [\"/old\"],\n  \"model\": \"o3\"\n}\n";
        let (text, _) = typed(Format::Json, &values())
            .first_copy(host)
            .expect("an edit");
        assert_eq!(
            text,
            "{\n  \"dirs\": [\n    \"/w\",\n    [\n      1\n    ]\n  ],\n  \"model\": \"o3\",\n  \
             \"onboarded\": true,\n  \"retries\": 3,\n  \"ratio\": 0.5\n}\n"
        );
        assert_eq!(typed(Format::Json, &values()).rewrite(&text), Ok(None));
    }

    #[test]
    fn a_toml_set_writes_a_number_a_boolean_and_a_list_and_keeps_a_comment() {
        let host = "dirs = [\"/old\"] # where\nmodel = \"o3\"\n";
        let (text, _) = typed(Format::Toml, &values())
            .first_copy(host)
            .expect("an edit");
        assert_eq!(
            text,
            "dirs = [\"/w\", [1]] # where\nmodel = \"o3\"\nonboarded = true\nretries = 3\nratio = 0.5\n"
        );
        assert_eq!(typed(Format::Toml, &values()).rewrite(&text), Ok(None));
    }

    #[test]
    fn a_file_that_is_not_its_kind_is_refused() {
        let json = edit(Format::Json, None, &[(&["a"], "b")]);
        assert!(matches!(json.rewrite("a = 1"), Err(Failure::Parse(_))));
        assert!(matches!(
            json.rewrite("// a comment\n{}"),
            Err(Failure::Parse(_))
        ));
        let toml = edit(Format::Toml, None, &[(&["a"], "b")]);
        assert!(matches!(toml.rewrite("{\"a\": 1}"), Err(Failure::Parse(_))));
    }

    const CLAUDE: &str = r#"{
  "model": "opus",
  "theme": "dark",
  "env": { "ANTHROPIC_API_KEY": "sk-..." },
  "apiKeyHelper": "~/bin/get-key.sh",
  "permissions": {
    "allow": ["Bash(npm test)"],
    "additionalDirectories": ["../shared"]
  }
}"#;

    const KEEP: &[&[&str]] = &[
        &["model"],
        &["theme"],
        &["outputStyle"],
        &["permissions", "additionalDirectories"],
    ];

    #[test]
    fn keep_copies_only_the_named_paths_and_reports_the_rest() {
        let (text, kept) = edit(Format::Json, Some(KEEP), &[])
            .first_copy(CLAUDE)
            .expect("an edit");
        assert_eq!(
            text,
            r#"{
  "model": "opus",
  "theme": "dark",
  "permissions": {
    "additionalDirectories": [
      "../shared"
    ]
  }
}
"#
        );
        assert_eq!(
            kept,
            Kept {
                kept: vec![
                    path(&["model"]),
                    path(&["theme"]),
                    path(&["permissions", "additionalDirectories"]),
                ],
                dropped: vec![
                    path(&["env"]),
                    path(&["apiKeyHelper"]),
                    path(&["permissions", "allow"]),
                ],
                missing: vec![path(&["outputStyle"])],
            }
        );
    }

    #[test]
    fn keep_in_toml_removes_the_rest_and_an_emptied_table() {
        let host = "# prefs\nmodel = \"o3\"   # mine\napi_key = \"sk\"\n\n\
                    [shell]\npath = \"/bin/zsh\"\n\n[secrets]\ntoken = \"t\"\n";
        let (text, kept) = edit(
            Format::Toml,
            Some(&[&["model"], &["secrets", "absent"]]),
            &[],
        )
        .first_copy(host)
        .expect("an edit");
        assert_eq!(text, "model = \"o3\"\n");
        assert_eq!(
            kept.dropped,
            vec![
                path(&["api_key"]),
                path(&["shell"]),
                path(&["secrets", "token"])
            ]
        );
        assert_eq!(kept.missing, vec![path(&["secrets", "absent"])]);
    }

    #[test]
    fn keep_in_toml_copies_no_comment() {
        let host = "# api_key = \"sk-1\"\nmodel = \"o3\" # sk-2\n\
                    list = [\"a\", # sk-3\n  \"b\", # sk-4\n]\n\
                    inline = { a = \"x\" } # sk-5\n\
                    shell.path = \"/bin/zsh\" # sk-6\napi_key = \"sk\"\n\n\
                    # sk-7\n[prefs] # sk-8\n# sk-9\ntheme = \"dark\" # sk-10\n\n\
                    [auth]\n# sk-11\ntoken = \"t\"\n# sk-12\n";
        let keep: &[&[&str]] = &[
            &["model"],
            &["list"],
            &["inline"],
            &["shell", "path"],
            &["prefs"],
        ];
        let (text, _) = edit(Format::Toml, Some(keep), &[(&["shellPath"], "/b")])
            .first_copy(host)
            .expect("an edit");
        assert!(!text.contains("sk-"), "{text}");
        let parsed: toml::Table = text.parse().expect("TOML");
        let expected: toml::Table = "model = \"o3\"\nlist = [\"a\", \"b\"]\n\
                                     inline = { a = \"x\" }\nshell.path = \"/bin/zsh\"\n\
                                     shellPath = \"/b\"\n[prefs]\ntheme = \"dark\"\n"
            .parse()
            .expect("TOML");
        assert_eq!(parsed, expected);
    }

    #[test]
    fn keep_in_toml_writes_each_inline_table_in_its_bare_form() {
        let host = "empty = {   }\ninline = {  a = \"x\" ,b = {c=1}  }  # note\n\
                    list = [ {  d = 2  } , { } ]\n";
        let keep: &[&[&str]] = &[&["empty"], &["inline"], &["list"]];
        let (text, _) = edit(Format::Toml, Some(keep), &[])
            .first_copy(host)
            .expect("an edit");
        assert_eq!(
            text,
            "empty = {}\ninline = { a = \"x\", b = { c = 1 } }\nlist = [{ d = 2 }, {}]\n"
        );

        let host = "inline = {\n  a = \"x\", # sk-1\n  b = 1,\n  # sk-2\n}\n";
        let (text, _) = edit(Format::Toml, Some(&[&["inline"]]), &[])
            .first_copy(host)
            .expect("an edit");
        assert_eq!(text, "inline = { a = \"x\", b = 1 }\n");
    }

    #[test]
    fn keep_then_set_adds_a_key_outside_keep() {
        let (text, _) = edit(Format::Json, Some(&[&["model"]]), &[(&["shellPath"], "/b")])
            .first_copy(CLAUDE)
            .expect("an edit");
        assert_eq!(
            text,
            "{\n  \"model\": \"opus\",\n  \"shellPath\": \"/b\"\n}\n"
        );
    }

    #[test]
    fn a_toml_set_keeps_dotted_keys_and_writes_into_them() {
        let copy = "# prefs\nshell.path = \"/bin/zsh\"   # mine\nshell.login = \"yes\"\n";
        let replaced = edit(Format::Toml, None, &[(&["shell", "path"], "/box/bin/bash")])
            .rewrite(copy)
            .expect("an edit")
            .expect("a change");
        assert_eq!(
            replaced,
            "# prefs\nshell.path = \"/box/bin/bash\"   # mine\nshell.login = \"yes\"\n"
        );
        let added = edit(Format::Toml, None, &[(&["shell", "args", "first"], "-l")])
            .rewrite(copy)
            .expect("an edit")
            .expect("a change");
        let parsed: toml::Table = toml::from_str(&added).expect("TOML");
        assert_eq!(parsed["shell"]["args"]["first"].as_str(), Some("-l"));
        assert_eq!(parsed["shell"]["path"].as_str(), Some("/bin/zsh"));
        assert!(added.starts_with("# prefs\nshell.path = \"/bin/zsh\"   # mine\n"));
    }

    #[test]
    fn an_array_of_tables_is_kept_whole_stops_a_set_below_it_and_is_replaced() {
        let host = "model = \"o3\"\n\n[[profiles]]\nname = \"a\"\n\n[[profiles]]\nname = \"b\"\n";
        let (text, kept) = edit(Format::Toml, Some(&[&["profiles"]]), &[])
            .first_copy(host)
            .expect("an edit");
        assert_eq!(
            text,
            "[[profiles]]\nname = \"a\"\n\n[[profiles]]\nname = \"b\"\n"
        );
        assert_eq!(kept.dropped, vec![path(&["model"])]);
        let (_, below) = edit(Format::Toml, Some(&[&["profiles", "name"]]), &[])
            .first_copy(host)
            .expect("an edit");
        assert_eq!(below.dropped, vec![path(&["model"]), path(&["profiles"])]);
        assert_eq!(below.missing, vec![path(&["profiles", "name"])]);
        let blocked = edit(Format::Toml, None, &[(&["profiles", "name"], "x")]).rewrite(host);
        assert_eq!(
            blocked,
            Err(Failure::Set(
                0,
                Blocked {
                    at: path(&["profiles"]),
                    what: "a list"
                }
            ))
        );
        let replaced = edit(Format::Toml, None, &[(&["profiles"], "x")])
            .rewrite(host)
            .expect("an edit");
        assert_eq!(
            replaced,
            Some("model = \"o3\"\nprofiles = \"x\"\n".to_string())
        );
    }

    #[test]
    fn keep_with_a_path_and_its_prefix_keeps_the_whole_prefix() {
        let host = r#"{"permissions": {"allow": ["a"], "deny": ["b"]}, "env": {}}"#;
        let (text, kept) = edit(
            Format::Json,
            Some(&[&["permissions"], &["permissions", "allow"]]),
            &[],
        )
        .first_copy(host)
        .expect("an edit");
        let parsed: Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(
            parsed,
            serde_json::json!({"permissions": {"allow": ["a"], "deny": ["b"]}})
        );
        assert_eq!(kept.kept, vec![path(&["permissions"])]);
        assert!(kept.missing.is_empty());
    }

    #[test]
    fn keep_copies_an_empty_table_it_names() {
        let (json, _) = edit(Format::Json, Some(&[&["env"]]), &[])
            .first_copy(r#"{"env": {}, "model": "opus"}"#)
            .expect("an edit");
        assert_eq!(json, "{\n  \"env\": {}\n}\n");
        let (toml, kept) = edit(Format::Toml, Some(&[&["env"]]), &[])
            .first_copy("model = \"o3\"\n\n[env]\n")
            .expect("an edit");
        assert_eq!(toml, "[env]\n");
        assert_eq!(kept.kept, vec![path(&["env"])]);
    }

    #[test]
    fn a_path_is_shown_with_dots_and_each_odd_key_in_quotes() {
        assert_eq!(
            shown(&path(TRUST)),
            "projects.\"/Users/me/my.app\".trust_level"
        );
        assert_eq!(shown(&path(&["shellPath"])), "shellPath");
    }

    fn filling(keep: &[&[&str]]) -> Edit {
        Edit {
            fill: true,
            ..edit(Format::Json, Some(keep), &[])
        }
    }

    #[test]
    fn a_fill_adds_each_kept_value_the_copy_lacks_and_replaces_none() {
        let host = r#"{"hasCompletedOnboarding": true, "theme": "light", "oauthAccount": {"emailAddress": "me"},
            "projects": {"/w": {"hasTrustDialogAccepted": true, "allowedTools": ["Bash"]}, "/other": {"hasTrustDialogAccepted": true}}}"#;
        let copy = r#"{"theme": "dark", "projects": {"/w": {"lastCost": 1}}, "mcpServers": {}}"#;
        let (text, added) = filling(&[
            &["hasCompletedOnboarding"],
            &["theme"],
            &["projects", "/w", "hasTrustDialogAccepted"],
            &["copyOnSelect"],
        ])
        .fill(copy, host)
        .expect("a fill")
        .expect("a change");
        assert_eq!(
            added,
            vec![
                path(&["hasCompletedOnboarding"]),
                path(&["projects", "/w", "hasTrustDialogAccepted"])
            ]
        );
        let filled: Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(
            filled,
            serde_json::json!({
                "theme": "dark",
                "projects": {"/w": {"lastCost": 1, "hasTrustDialogAccepted": true}},
                "mcpServers": {},
                "hasCompletedOnboarding": true,
            })
        );
    }

    #[test]
    fn a_fill_that_adds_nothing_changes_nothing_and_skips_a_parent_that_is_not_a_table() {
        let host = r#"{"theme": "light", "projects": {"/w": {"hasTrustDialogAccepted": true}}}"#;
        let copy = r#"{"theme": "dark", "projects": "not a table"}"#;
        let fill = filling(&[&["theme"], &["projects", "/w", "hasTrustDialogAccepted"]]);
        assert_eq!(fill.fill(copy, host), Ok(None));
        assert!(matches!(fill.fill("{", host), Err(Failure::Parse(_))));
        assert!(matches!(fill.fill(copy, "{"), Err(Failure::Parse(_))));
    }

    #[test]
    fn a_toml_fill_preserves_saved_values_layout_and_skips_blocked_parents() {
        let mut fill = edit(
            Format::Toml,
            Some(&[
                &["model"],
                &["nested", "new"],
                &["nested", "missing", "deep"],
                &["absent", "new"],
                &["blocked", "new"],
                &["extra"],
            ]),
            &[],
        );
        fill.fill = true;
        let host = "model = \"host\"\nnested.new = \"added\" # secret comment\n\
                    nested.missing.deep = true\nabsent.new = true\n\
                    blocked.new = true\nextra = { list = [1, 2] }\n";
        let copy = "# keep this comment\nmodel = \"saved\" # keep this too\n\
                    nested = { old = true }\nblocked = false\n";
        let (text, added) = fill.fill(copy, host).expect("a fill").expect("new keys");
        assert!(text.starts_with("# keep this comment\nmodel = \"saved\" # keep this too\n"));
        assert!(!text.contains("secret comment"));
        let parsed: toml::Table = text.parse().expect("TOML");
        assert_eq!(parsed["nested"]["new"].as_str(), Some("added"));
        assert_eq!(parsed["nested"]["old"].as_bool(), Some(true));
        assert_eq!(parsed["nested"]["missing"]["deep"].as_bool(), Some(true));
        assert_eq!(parsed["absent"]["new"].as_bool(), Some(true));
        assert_eq!(parsed["blocked"].as_bool(), Some(false));
        assert_eq!(parsed["extra"]["list"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            added,
            [
                path(&["nested", "new"]),
                path(&["nested", "missing", "deep"]),
                path(&["absent", "new"]),
                path(&["extra"])
            ]
        );
        assert_eq!(fill.fill(&text, host), Ok(None));
    }
}
