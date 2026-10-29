//! Golden tests: each corpus case is one argv and the action, fields, and effects it gives, and
//! the generated schema types the event that the parser builds from it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use cedar_policy::{Context, EntityUid, Request};

use super::Pack;
use super::grammar::{FieldKind, FieldValue, Parsed};
use super::model::UNMODELED_ACTION;
use super::schema::pack_action_schema;
use crate::dogwood::{check_against, service_schema};
use crate::schema::ActionSchema;
use crate::spelling::Operator;

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

/// A parse result as the corpus writes it: names as strings, and only non-default fields.
#[derive(Debug, PartialEq, Eq)]
enum Reading {
    Action {
        action: String,
        fields: BTreeMap<String, FieldValue>,
        effects: BTreeSet<String>,
    },
    Unmodeled,
}

fn expected(case: &Case) -> Result<Reading, String> {
    if case.action == "unmodeled" {
        if !case.fields.is_empty() || !case.effects.is_empty() {
            return Err("an unmodeled case has fields or effects".to_string());
        }
        return Ok(Reading::Unmodeled);
    }
    Ok(Reading::Action {
        action: case.action.clone(),
        fields: field_values(&case.fields)?,
        effects: case.effects.clone(),
    })
}

/// Read `parsed` by name, and drop each field that holds its default: `false`, or an empty set.
fn reading(parsed: Parsed) -> Reading {
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
            Reading::Action {
                action: action.as_str().to_string(),
                fields,
                effects: effects
                    .iter()
                    .map(|effect| effect.as_str().to_string())
                    .collect(),
            }
        }
        Parsed::Unmodeled => Reading::Unmodeled,
    }
}

/// Whether the action and each effect of `parsed` are ones that `pack` declares.
fn declared_by(parsed: &Parsed, pack: &Pack) -> bool {
    match parsed {
        Parsed::Action {
            action, effects, ..
        } => {
            pack.actions.contains_key(action)
                && effects
                    .iter()
                    .all(|effect| pack.effects.contains_key(effect))
        }
        Parsed::Unmodeled => true,
    }
}

fn show(reading: &Reading) -> String {
    match reading {
        Reading::Unmodeled => "unmodeled".to_string(),
        Reading::Action {
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

/// The pack that a corpus file reads with: the pack beside it, or the valid fixture of its name.
fn corpus_pack(path: &Path, stem: &str) -> Pack {
    let beside = path.with_file_name(format!("{stem}.pack.toml"));
    let pack_path = if beside.exists() {
        beside
    } else {
        Path::new(PACKS)
            .join("valid")
            .join(format!("{stem}.pack.toml"))
    };
    Pack::load(&pack_path).expect("the corpus pack loads")
}

/// Each corpus file, the pack it reads with, and its cases.
fn corpora() -> Vec<(String, Pack, Vec<Case>)> {
    corpus_files()
        .into_iter()
        .filter_map(|path| {
            let file = path.file_name().unwrap_or_default().display().to_string();
            let stem = file.strip_suffix(".corpus.toml")?.to_string();
            let text = std::fs::read_to_string(&path).expect("the corpus file reads");
            let corpus: Corpus = toml::from_str(&text).expect("the corpus file is well formed");
            Some((file, corpus_pack(&path, &stem), corpus.case))
        })
        .collect()
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
        let pack = corpus_pack(&path, stem);
        let grammar = pack.grammar();
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
            let parsed = grammar.parse(&case.argv[1..]);
            if !declared_by(&parsed, &pack) {
                failures.push(format!("{at}: gives a name that the pack does not declare"));
            }
            let parsed = reading(parsed);
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

/// A Cedar string literal of `value`.
fn literal(value: &str) -> String {
    format!("{value:?}")
}

/// The Cedar condition that holds exactly when a field holds the value that a case gives it.
fn field_condition(
    name: &str,
    kind: FieldKind,
    value: Option<&toml::Value>,
) -> Result<String, String> {
    let at = format!("context.input.{name}");
    Ok(match (kind, value) {
        (FieldKind::Bool, None) => format!("{at} == false"),
        (FieldKind::Bool, Some(toml::Value::Boolean(value))) => format!("{at} == {value}"),
        (FieldKind::String, None) => format!("!(context.input has {name})"),
        (FieldKind::String, Some(toml::Value::String(value))) => {
            format!("context.input has {name} && {at} == {}", literal(value))
        }
        (FieldKind::Set, None) => format!("{at}.isEmpty()"),
        (FieldKind::Set, Some(toml::Value::Array(values))) => {
            let values = values
                .iter()
                .map(|value| value.as_str().map(literal))
                .collect::<Option<Vec<_>>>()
                .ok_or(format!("{name} holds a value that is not a string"))?;
            if values.is_empty() {
                format!("{at}.isEmpty()")
            } else {
                format!("{at} == [{}]", values.join(", "))
            }
        }
        (kind, Some(value)) => return Err(format!("{name} = {value} is not a {kind:?} field")),
    })
}

/// A condition that reads a field of `kind` as a type it does not have.
fn mistyped_condition(name: &str, kind: FieldKind) -> String {
    match kind {
        FieldKind::Bool => format!("context.input.{name}.contains(\"\")"),
        FieldKind::String => {
            format!("context.input has {name} && context.input.{name}.contains(\"\")")
        }
        FieldKind::Set => format!("context.input.{name} like \"*\""),
    }
}

/// The `context.input` record of one parse, in the shape that the generated schema declares.
fn input_record(pack: &Pack, argv: &[String], parsed: &Parsed) -> serde_json::Value {
    let effect_type = format!("{}::Effect", pack.namespace());
    let mut args = argv[1..].to_vec();
    args.sort();
    args.dedup();
    let mut record = serde_json::Map::new();
    record.insert("program".to_string(), serde_json::json!(pack.program));
    let program_path = format!("/usr/bin/{}", pack.program);
    record.insert("program_path".to_string(), serde_json::json!(program_path));
    record.insert("cwd".to_string(), serde_json::json!("/work"));
    record.insert("args".to_string(), serde_json::json!(args));
    let (fields, effects) = match parsed {
        Parsed::Action {
            fields, effects, ..
        } => (Some(fields), effects.iter().collect()),
        Parsed::Unmodeled => (None, Vec::new()),
    };
    if !pack.effects.is_empty() {
        let effects: Vec<serde_json::Value> = effects
            .into_iter()
            .map(|effect| {
                serde_json::json!({ "__entity": { "type": effect_type, "id": effect.as_str() } })
            })
            .collect();
        record.insert("effects".to_string(), serde_json::json!(effects));
    }
    for (name, value) in fields.into_iter().flatten() {
        let value = match value {
            FieldValue::Bool(value) => serde_json::json!(value),
            FieldValue::String(value) => serde_json::json!(value),
            FieldValue::Set(values) => serde_json::json!(values),
        };
        record.insert(name.clone(), value);
    }
    serde_json::Value::Object(record)
}

/// The verdict of a Dogwood authorizer on the event of `request`, and the index of each rule
/// that determined it.
fn verdict(
    authorizer: &mut dogwood_language::Authorizer,
    request: &Request,
) -> Result<(bool, BTreeSet<usize>), String> {
    let event =
        dogwood_language::Event::from_request(request).map_err(|error| error.to_string())?;
    let response = authorizer
        .is_authorized(&event)
        .ok_or("the request event takes no decision")?;
    let errors: Vec<&str> = response.diagnostics().errors().collect();
    if !errors.is_empty() {
        return Err(format!("the decision has errors: {}", errors.join("; ")));
    }
    Ok((
        response.allowed(),
        response
            .diagnostics()
            .reason()
            .map(|rule| rule.rule_index)
            .collect(),
    ))
}

/// The indexes of the rules that a refusal of `source` names, or `None` when it loads.
fn refused_rules(source: &str, pack: &Pack) -> Option<BTreeSet<usize>> {
    let schema = pack_action_schema(std::slice::from_ref(pack), &[]).expect("the schema composes");
    let refused = check_against(source, schema, &Operator::unanchored(), true, &[]).err()?;
    Some(
        refused
            .findings
            .iter()
            .flat_map(|finding| finding.rules())
            .map(|rule| rule.position() - 1)
            .collect(),
    )
}

/// The conjunction of `conditions`, nested as a balanced tree to stay within the evaluation depth.
fn all_of(conditions: &[String]) -> String {
    match conditions {
        [] => "true".to_string(),
        [condition] => condition.clone(),
        _ => {
            let (left, right) = conditions.split_at(conditions.len() / 2);
            format!("({}) && ({})", all_of(left), all_of(right))
        }
    }
}

/// A rule over one action of `pack`.
fn rule(namespace: &str, action: &str, condition: &str) -> String {
    format!(
        "permit (principal, action == {namespace}::Action::{}, resource)\nwhen {{ {condition} }};\n",
        literal(action)
    )
}

/// The event of one case, and the conditions that hold exactly for its values.
struct Event {
    at: String,
    action: String,
    request: Request,
    conditions: Vec<String>,
}

/// The event that the parser builds from `case`, typed by the generated schema of `pack`.
fn event(
    pack: &Pack,
    schema: &ActionSchema,
    case: &Case,
) -> Result<(String, Request, Vec<String>), String> {
    let namespace = pack.namespace();
    let parsed = pack.grammar().parse(&case.argv[1..]);
    let action = match &parsed {
        Parsed::Action { action, .. } => action.as_str(),
        Parsed::Unmodeled => UNMODELED_ACTION,
    };
    if action != case.action {
        return Err(format!("parses as {action}, not {}", case.action));
    }
    let fields: Vec<(&str, FieldKind)> = pack
        .grammar()
        .action_fields()
        .find(|(name, _)| name.as_str() == action)
        .map(|(_, fields)| fields)
        .unwrap_or_default();
    if let Some(name) = case
        .fields
        .keys()
        .find(|name| !fields.iter().any(|(field, _)| field == name))
    {
        return Err(format!("the schema of {action} has no field {name}"));
    }
    if let Some(effect) = case
        .effects
        .iter()
        .find(|effect| !pack.effects.contains_key(effect.as_str()))
    {
        return Err(format!("the schema has no effect {effect}"));
    }

    let uid: EntityUid = format!("{namespace}::Action::{}", literal(action))
        .parse()
        .map_err(|error| format!("{error}"))?;
    let principal: EntityUid = r#"Box::Agent::"self""#
        .parse()
        .map_err(|error| format!("{error}"))?;
    let resource: EntityUid = r#"Box::Resource::"unused""#
        .parse()
        .map_err(|error| format!("{error}"))?;
    let input = input_record(pack, &case.argv, &parsed);
    let context = Context::from_json_value(
        serde_json::json!({ "input": input }),
        Some((&schema.cedar, &uid)),
    )
    .map_err(|error| format!("the event does not type: {error}"))?;
    let request = Request::new(principal, uid, resource, context, Some(&schema.cedar))
        .map_err(|error| format!("the event does not conform: {error}"))?;

    let mut conditions = vec![format!(
        "context.input.program == {}",
        literal(&pack.program)
    )];
    for (name, kind) in &fields {
        conditions.push(field_condition(name, *kind, case.fields.get(*name))?);
    }
    for effect in pack.effects.keys() {
        let contains = format!(
            "context.input.effects.contains({namespace}::Effect::{})",
            literal(effect.as_str())
        );
        conditions.push(if case.effects.contains(effect.as_str()) {
            contains
        } else {
            format!("!{contains}")
        });
    }
    Ok((action.to_string(), request, conditions))
}

/// Check every case of one corpus against the generated schema of `pack`.
fn check_corpus(file: &str, pack: &Pack, cases: &[Case], failures: &mut Vec<String>) {
    let namespace = pack.namespace();
    let schema = pack_action_schema(std::slice::from_ref(pack), &[]).expect("the schema composes");
    let mut events = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let at = format!("{file} case {} {:?}", index + 1, case.argv);
        match event(pack, &schema, case) {
            Ok((action, request, conditions)) => events.push(Event {
                at,
                action,
                request,
                conditions,
            }),
            Err(failure) => failures.push(format!("{at}: {failure}")),
        }
    }

    let exact: String = events
        .iter()
        .map(|event| rule(&namespace, &event.action, &all_of(&event.conditions)))
        .collect();
    if let Some(rules) = refused_rules(&exact, pack) {
        for index in rules {
            failures.push(format!(
                "{}: the rule over its values is refused",
                events[index].at
            ));
        }
        return;
    }
    let mut negations = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let mut picked = vec![0, 1, event.conditions.len() - 1];
        picked.dedup();
        for at in picked.into_iter().filter(|at| *at < event.conditions.len()) {
            let condition = format!("!({})", event.conditions[at]);
            negations.push((index, rule(&namespace, &event.action, &condition)));
        }
    }
    let negated: String = negations.iter().map(|(_, rule)| rule.as_str()).collect();
    let service = service_schema().expect("the event schema builds");
    let policy_schema = dogwood_language::PolicySchema::from_cedarschema_str(&schema.source)
        .expect("the action schema reads");
    let lower = |source: &str| {
        dogwood_language::ParsedPolicySet::parse(source, &service)
            .expect("the rules parse")
            .lower(&policy_schema)
            .expect("the rules lower")
    };
    let mut exact = dogwood_language::Authorizer::new(lower(&exact));
    let mut negated = dogwood_language::Authorizer::new(lower(&negated));
    for (index, event) in events.iter().enumerate() {
        match verdict(&mut exact, &event.request) {
            Ok((true, rules)) if rules.contains(&index) => {}
            Ok(_) => failures.push(format!(
                "{}: the rule over its values does not permit it",
                event.at
            )),
            Err(error) => failures.push(format!("{}: {error}", event.at)),
        }
        let own: BTreeSet<usize> = negations
            .iter()
            .enumerate()
            .filter(|(_, (case, _))| *case == index)
            .map(|(rule, _)| rule)
            .collect();
        match verdict(&mut negated, &event.request) {
            Ok((_, rules)) if rules.is_disjoint(&own) => {}
            Ok(_) => failures.push(format!(
                "{}: a rule that negates one of its values permits it",
                event.at
            )),
            Err(error) => failures.push(format!("{}: {error}", event.at)),
        }
    }
}

/// Check that a rule which reads any field of any action of `pack` as another type is refused.
fn check_field_types(file: &str, pack: &Pack, failures: &mut Vec<String>) {
    let namespace = pack.namespace();
    let mut probes = Vec::new();
    for (action, fields) in pack.grammar().action_fields() {
        for (name, kind) in fields {
            probes.push((
                format!("{}.{name}", action.as_str()),
                rule(&namespace, action.as_str(), &mistyped_condition(name, kind)),
            ));
        }
    }
    if let Some(effect) = pack.effects.keys().next() {
        let undeclared = format!("{}_undeclared", effect.as_str());
        probes.push((
            format!("effect {undeclared}"),
            rule(
                &namespace,
                UNMODELED_ACTION,
                &format!(
                    "context.input.effects.contains({namespace}::Effect::{})",
                    literal(&undeclared)
                ),
            ),
        ));
    }
    let source: String = probes.iter().map(|(_, rule)| rule.as_str()).collect();
    let refused = refused_rules(&source, pack).unwrap_or_default();
    for (index, (name, _)) in probes.iter().enumerate() {
        if !refused.contains(&index) {
            failures.push(format!(
                "{file}: a rule that reads {name} as another type loads"
            ));
        }
    }
}

#[test]
fn every_corpus_case_gives_an_event_that_its_generated_schema_types_and_decides() {
    let mut failures = Vec::new();
    let mut count = 0;
    for (file, pack, cases) in corpora() {
        count += cases.len();
        check_corpus(&file, &pack, &cases, &mut failures);
        check_field_types(&file, &pack, &mut failures);
    }

    assert!(count > 0, "the corpus holds no case");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
