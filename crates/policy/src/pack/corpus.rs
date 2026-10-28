//! Golden tests: each corpus case is one argv and the action, fields, and effects it gives.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::Pack;
use super::grammar::{FieldValue, Parsed, ShellGrammar};

const PACKS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/packs");

/// One `<pack>.corpus.toml` file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    case: Vec<Case>,
}

/// One `[[case]]`: an argv, and what the shell grammar reads it as.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    argv: Vec<String>,
    action: String,
    #[serde(default)]
    fields: toml::Table,
    #[serde(default)]
    effects: BTreeSet<String>,
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

fn field_values(fields: &toml::Table) -> Result<BTreeMap<String, FieldValue>, String> {
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

fn expected(case: &Case) -> Result<Parsed, String> {
    if case.action == "unmodeled" {
        if !case.fields.is_empty() || !case.effects.is_empty() {
            return Err("an unmodeled case has fields or effects".to_string());
        }
        return Ok(Parsed::Unmodeled);
    }
    Ok(Parsed::Action {
        action: case.action.clone(),
        fields: field_values(&case.fields)?,
        effects: case.effects.clone(),
    })
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
fn every_corpus_case_parses_to_its_action_fields_and_effects() {
    let mut failures = Vec::new();
    let mut count = 0;
    for path in corpus_files() {
        let file = path.file_name().unwrap_or_default().display().to_string();
        if file.ends_with(".pack.toml") {
            continue;
        }
        let Some(stem) = file.strip_suffix(".corpus.toml") else {
            failures.push(format!("{file}: is not named `<pack>.corpus.toml`"));
            continue;
        };
        let beside = path.with_file_name(format!("{stem}.pack.toml"));
        let pack_path = if beside.exists() {
            beside
        } else {
            Path::new(PACKS)
                .join("valid")
                .join(format!("{stem}.pack.toml"))
        };
        let pack = Pack::load(&pack_path).expect("the corpus pack loads");
        let grammar = ShellGrammar::compile(&pack).expect("the corpus pack compiles");
        let text = std::fs::read_to_string(&path).expect("the corpus file reads");
        let corpus: Corpus = match toml::from_str(&text) {
            Ok(corpus) => corpus,
            Err(error) => {
                failures.push(format!("{file}: {error}"));
                continue;
            }
        };
        for (index, case) in corpus.case.iter().enumerate() {
            count += 1;
            let at = format!("{file} case {} {:?}", index + 1, case.argv);
            let expected = match expected(case) {
                Ok(expected) => expected,
                Err(error) => {
                    failures.push(format!("{at}: {error}"));
                    continue;
                }
            };
            if case.argv.first() != Some(&pack.program) {
                failures.push(format!("{at}: does not start with `{}`", pack.program));
                continue;
            }
            let parsed = without_defaults(grammar.parse(&case.argv[1..]));
            if parsed != expected {
                failures.push(format!(
                    "{at}\n  expected: {}\n  but got:  {}",
                    show(&expected),
                    show(&parsed)
                ));
            }
        }
    }

    assert!(count > 0, "the corpus holds no case");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
