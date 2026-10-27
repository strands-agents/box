//! Golden tests: each corpus row is one command line and the action, fields, and effects it gives.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::Pack;
use super::grammar::{FieldValue, Parsed, ShellGrammar};

const PACKS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/packs");
const NONE: &str = "—";

struct Row {
    line: usize,
    command: String,
    expected: Parsed,
}

fn corpus_files() -> Vec<PathBuf> {
    let directory = Path::new(PACKS).join("corpus");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| entry.expect("a corpus entry").path())
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "{} holds no corpus", directory.display());
    paths
}

/// Split a command line into words, as a POSIX shell does for `'…'` and `"…"` with no escapes.
fn words(command: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut quote = None;
    for character in command.chars() {
        match (quote, character) {
            (Some(open), character) if character == open => quote = None,
            (Some(_), character) => word.get_or_insert_default().push(character),
            (None, '\'' | '"') => {
                quote = Some(character);
                word.get_or_insert_default();
            }
            (None, character) if character.is_whitespace() => words.extend(word.take()),
            (None, character) => word.get_or_insert_default().push(character),
        }
    }
    if quote.is_some() {
        return Err("has an unclosed quote".to_string());
    }
    words.extend(word);
    Ok(words)
}

fn field_values(cell: &str) -> Result<BTreeMap<String, FieldValue>, String> {
    if cell == NONE {
        return Ok(BTreeMap::new());
    }
    let table: toml::Table =
        toml::from_str(&format!("fields = {{ {cell} }}")).map_err(|error| error.to_string())?;
    let Some(toml::Value::Table(fields)) = table.get("fields") else {
        return Err("the fields are not a table".to_string());
    };
    fields
        .iter()
        .map(|(name, value)| {
            let value = match value {
                toml::Value::Boolean(value) => FieldValue::Bool(*value),
                toml::Value::String(value) => FieldValue::String(value.clone()),
                toml::Value::Array(values) => {
                    let mut set = values
                        .iter()
                        .map(|value| value.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                        .ok_or(format!("{name} holds a value that is not a string"))?;
                    set.sort();
                    FieldValue::Set(set)
                }
                other => return Err(format!("{name} = {other} is not a field value")),
            };
            Ok((name.clone(), value))
        })
        .collect()
}

fn effects(cell: &str) -> BTreeSet<String> {
    if cell == NONE {
        return BTreeSet::new();
    }
    cell.split(',')
        .map(|effect| effect.trim().to_string())
        .collect()
}

fn rows(text: &str) -> Result<Vec<Row>, String> {
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let place = index + 1;
        if !line.starts_with("| `") {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        let [command, action, fields, effect_cell, _note] = cells.as_slice() else {
            return Err(format!("line {place}: a row has five cells"));
        };
        let command = command
            .strip_prefix('`')
            .and_then(|command| command.strip_suffix('`'))
            .ok_or(format!(
                "line {place}: the command line is not in backticks"
            ))?;
        let expected = if *action == "unmodeled" {
            if *fields != NONE || *effect_cell != NONE {
                return Err(format!(
                    "line {place}: an unmodeled row has fields or effects"
                ));
            }
            Parsed::Unmodeled
        } else {
            Parsed::Action {
                action: action.to_string(),
                fields: field_values(fields).map_err(|error| format!("line {place}: {error}"))?,
                effects: effects(effect_cell),
            }
        };
        rows.push(Row {
            line: place,
            command: command.to_string(),
            expected,
        });
    }
    Ok(rows)
}

/// Drop each field that holds its default: `false`, or an empty set.
fn without_defaults(parsed: Parsed) -> Parsed {
    match parsed {
        Parsed::Action {
            action,
            mut fields,
            effects,
        } => {
            fields.retain(|_, value| match value {
                FieldValue::Bool(value) => *value,
                FieldValue::Set(values) => !values.is_empty(),
                FieldValue::String(_) => true,
            });
            Parsed::Action {
                action,
                fields,
                effects,
            }
        }
        Parsed::Unmodeled => Parsed::Unmodeled,
    }
}

fn show(parsed: &Parsed) -> String {
    match parsed {
        Parsed::Unmodeled => "unmodeled".to_string(),
        Parsed::Action {
            action,
            fields,
            effects,
        } => {
            let fields: Vec<String> = fields
                .iter()
                .map(|(name, value)| match value {
                    FieldValue::Bool(value) => format!("{name} = {value}"),
                    FieldValue::String(value) => format!("{name} = {value:?}"),
                    FieldValue::Set(values) => format!("{name} = {values:?}"),
                })
                .collect();
            let effects: Vec<&str> = effects.iter().map(String::as_str).collect();
            format!("{action} | {} | {}", fields.join(", "), effects.join(", "))
        }
    }
}

#[test]
fn every_corpus_row_parses_to_its_action_fields_and_effects() {
    let mut failures = Vec::new();
    let mut count = 0;
    for path in corpus_files() {
        let file = path.file_name().unwrap_or_default().display().to_string();
        let Some(stem) = file.strip_suffix(".corpus.md") else {
            failures.push(format!("{file}: is not named `<pack>.corpus.md`"));
            continue;
        };
        let pack_path = Path::new(PACKS)
            .join("valid")
            .join(format!("{stem}.pack.toml"));
        let pack = Pack::load(&pack_path).expect("the corpus pack loads");
        let grammar = ShellGrammar::compile(&pack).expect("the corpus pack compiles");
        let text = std::fs::read_to_string(&path).expect("the corpus file reads");
        let rows = match rows(&text) {
            Ok(rows) => rows,
            Err(error) => {
                failures.push(format!("{file}: {error}"));
                continue;
            }
        };
        for row in rows {
            count += 1;
            let at = format!("{file}:{} `{}`", row.line, row.command);
            let argv = match words(&row.command) {
                Ok(words) => words,
                Err(error) => {
                    failures.push(format!("{at}: {error}"));
                    continue;
                }
            };
            if argv.first() != Some(&pack.program) {
                failures.push(format!("{at}: does not start with `{}`", pack.program));
                continue;
            }
            let parsed = without_defaults(grammar.parse(&argv[1..]));
            if parsed != row.expected {
                failures.push(format!(
                    "{at}\n  expected: {}\n  but got:  {}",
                    show(&row.expected),
                    show(&parsed)
                ));
            }
        }
    }

    assert!(count > 0, "the corpus holds no row");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
