//! Golden tests: each corpus case is one argv and the action, fields, and effects it gives, and
//! the policy engine types and decides the pack action that the parser builds from it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;

use super::grammar::{FieldKind, FieldValue, Parsed};
use super::model::UNMODELED_ACTION;
use super::schema::pack_action_schema;
use super::{Pack, PackInvocation, PendingPackResponse};
use crate::check::Refused;
use crate::dogwood::check_against;
use crate::spelling::Operator;
use crate::{
    Decision, DecisionObserver, DenyReason, GovernedBox, Policy, PolicyEngine, PolicyError,
    Principal,
};

pub(super) const PACKS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/packs");

/// One `<pack>.corpus.toml` file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Corpus {
    pub(super) case: Vec<Case>,
}

/// One `[[case]]`: an argv, and what the shell grammar reads it as.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub(super) argv: Vec<String>,
    action: String,
    #[serde(default)]
    fields: toml::Table,
    #[serde(default)]
    effects: BTreeSet<String>,
}

pub(super) fn corpus_files() -> Vec<PathBuf> {
    let directory = Path::new(PACKS).join("corpus");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| entry.expect("a corpus entry").path())
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "{} holds no corpus", directory.display());
    paths
}

/// The pack that the corpus file at `path`, named `<stem>.corpus.toml`, reads against.
pub(super) fn pack_of(path: &Path, stem: &str) -> PathBuf {
    let beside = path.with_file_name(format!("{stem}.pack.toml"));
    if beside.exists() {
        beside
    } else {
        Path::new(PACKS)
            .join("valid")
            .join(format!("{stem}.pack.toml"))
    }
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
    Pack::load(&pack_of(path, stem)).expect("the corpus pack loads")
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

/// The reason the load gives for the condition of [`mistyped_condition`], which names the
/// type that the schema gives a field of `kind`.
fn mistyped_reason(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Bool => "expected Set<__cedar::internal::Any> but saw Bool",
        FieldKind::String => "expected Set<__cedar::internal::Any> but saw String",
        FieldKind::Set => "expected String but saw Set<String>",
    }
}
/// The reason the load gives for a rule that names an effect the pack does not declare.
const UNDECLARED_EFFECT: &str = "is not declared as a valid eid";

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

/// The directory that holds the program of every corpus case.
const PROGRAM_DIRECTORY: &str = "/usr/bin";
/// The working directory of every corpus case.
const CWD: &str = "/work";

/// A policy engine over a temporary history, with the schema of each pack installed.
pub(super) struct Engine {
    engine: PolicyEngine,
    _history: tempfile::TempDir,
}

impl Engine {
    pub(super) fn open(source: &str, packs: &[Pack]) -> Result<Self, PolicyError> {
        let history = tempfile::tempdir().expect("a history directory");
        let engine = PolicyEngine::open_with_packs(
            vec![Policy {
                origin: PathBuf::from("corpus.dw"),
                text: source.to_string(),
            }],
            packs,
            &history.path().join("dogwood.redb"),
        )?;
        Ok(Self {
            engine,
            _history: history,
        })
    }

    /// Report every verdict of the engine to `observer`.
    pub(super) fn observed_by(self, observer: Arc<dyn DecisionObserver>) -> Self {
        Self {
            engine: self.engine.observed_by(observer),
            _history: self._history,
        }
    }

    pub(super) fn engine(&self) -> &PolicyEngine {
        &self.engine
    }

    /// Parse `argv` with `pack`, and decide the pack action it gives.
    pub(super) fn decide(&self, pack: &Pack, argv: &[String]) -> Decision {
        self.invoke(pack, argv).0
    }

    /// Parse `argv` with `pack`, decide its pack action, and keep the `::response` it owes.
    pub(super) fn invoke(
        &self,
        pack: &Pack,
        argv: &[String],
    ) -> (Decision, Option<PendingPackResponse>) {
        let program_path = format!("{PROGRAM_DIRECTORY}/{}", pack.program);
        let invocation =
            PackInvocation::new(pack, &pack.program, &program_path, CWD, &argv[1..], &[]);
        self.engine.decide_pack_action(
            &GovernedBox::assigned("corpus"),
            &Principal::agent(),
            &invocation,
        )
    }
}

/// Whether `decision` allows, and the `@id` of each rule that determined it.
fn verdict(decision: &Decision) -> Result<(bool, BTreeSet<String>), String> {
    if let Decision::Deny {
        reason: DenyReason::InternalFault,
        ..
    } = decision
    {
        return Err("the decision faults: the event does not type, or a rule errs".to_string());
    }
    Ok((
        decision.is_allow(),
        decision
            .attribution()
            .iter()
            .filter_map(|attribution| attribution.annotation_id.clone())
            .collect(),
    ))
}

/// Load `source` against `pack` through the strict load path, keeping the whole refusal.
fn load(source: &str, pack: &Pack) -> Result<(), Refused> {
    let schema = pack_action_schema(std::slice::from_ref(pack), &[]).map_err(Refused::from)?;
    check_against(source, schema, &Operator::unanchored(), true, &[]).map(|_| ())
}

/// Open an engine over `source` and `pack`, or describe why the strict load path refuses it.
fn open(source: &str, pack: &Pack) -> Result<Engine, String> {
    Engine::open(source, std::slice::from_ref(pack)).map_err(|error| match load(source, pack) {
        Err(refused) => describe(&refused),
        Ok(()) => format!("the engine does not open: {error}"),
    })
}

/// The message of each finding of `refused` that names rule `index`.
fn messages_for(refused: &Refused, index: usize) -> Vec<&str> {
    refused
        .findings
        .iter()
        .filter(|finding| {
            finding
                .rules()
                .iter()
                .any(|rule| rule.position() == index + 1)
        })
        .map(|finding| finding.message())
        .collect()
}

/// The refusal as one line, and the rules it names, by position.
fn describe(refused: &Refused) -> String {
    let rules: BTreeSet<usize> = refused
        .findings
        .iter()
        .flat_map(|finding| finding.rules())
        .map(|rule| rule.position())
        .collect();
    format!("{} (rules {rules:?})", refused.error)
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

/// A rule over one action of `pack`, with the `@id` `id`.
fn identified(id: &str, rule: &str) -> String {
    format!("@id({id:?})\n{rule}")
}

/// A rule over one action of `pack`.
fn rule(namespace: &str, action: &str, condition: &str) -> String {
    format!(
        "permit (principal, action == {namespace}::Action::{}, resource)\nwhen {{ {condition} }};\n",
        literal(action)
    )
}

/// The argv of one case, its action, and the conditions that hold exactly for its values.
struct Event<'a> {
    at: String,
    action: String,
    argv: &'a [String],
    conditions: Vec<String>,
}

/// The action that the parser reads `case` as, and the conditions that hold exactly for its values.
fn event(pack: &Pack, case: &Case) -> Result<(String, Vec<String>), String> {
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
    Ok((action.to_string(), conditions))
}

/// Check every case of one corpus. The engine loads a rule over the exact values of each case and
/// rules that each negate one of those values, decides the pack action of the case, and allows it by
/// its exact rule and by none of its negations.
fn check_corpus(file: &str, pack: &Pack, cases: &[Case], failures: &mut Vec<String>) {
    let namespace = pack.namespace();
    let mut events = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let at = format!("{file} case {} {:?}", index + 1, case.argv);
        match event(pack, case) {
            Ok((action, conditions)) => events.push(Event {
                at,
                action,
                argv: &case.argv,
                conditions,
            }),
            Err(failure) => failures.push(format!("{at}: {failure}")),
        }
    }

    let exact: String = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            identified(
                &format!("case-{index}"),
                &rule(&namespace, &event.action, &all_of(&event.conditions)),
            )
        })
        .collect();
    let mut negations = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let mut picked = vec![0, 1, event.conditions.len() - 1];
        picked.dedup();
        for at in picked.into_iter().filter(|at| *at < event.conditions.len()) {
            let condition = format!("!({})", event.conditions[at]);
            let id = format!("negation-{}", negations.len());
            negations.push((
                index,
                id.clone(),
                identified(&id, &rule(&namespace, &event.action, &condition)),
            ));
        }
    }
    let negated: String = negations.iter().map(|(_, _, rule)| rule.as_str()).collect();
    let engine = match Engine::open(&format!("{exact}{negated}"), std::slice::from_ref(pack)) {
        Ok(engine) => engine,
        Err(error) => {
            refused_corpus(file, pack, &events, &exact, &negated, &error, failures);
            return;
        }
    };
    for (index, event) in events.iter().enumerate() {
        let own: BTreeSet<String> = negations
            .iter()
            .filter(|(case, _, _)| *case == index)
            .map(|(_, id, _)| id.clone())
            .collect();
        match verdict(&engine.decide(pack, event.argv)) {
            Ok((allowed, rules)) => {
                if !allowed || !rules.contains(&format!("case-{index}")) {
                    failures.push(format!(
                        "{}: the rule over its values does not permit it",
                        event.at
                    ));
                }
                if !rules.is_disjoint(&own) {
                    failures.push(format!(
                        "{}: a rule that negates one of its values permits it",
                        event.at
                    ));
                }
            }
            Err(error) => failures.push(format!("{}: {error}", event.at)),
        }
    }
}

/// Report why the engine does not open over the exact and the negated rules of one corpus.
fn refused_corpus(
    file: &str,
    pack: &Pack,
    events: &[Event<'_>],
    exact: &str,
    negated: &str,
    error: &PolicyError,
    failures: &mut Vec<String>,
) {
    if let Err(refused) = load(exact, pack) {
        failures.push(format!(
            "{file}: the rules over the case values are refused: {}",
            describe(&refused)
        ));
        for (index, event) in events.iter().enumerate() {
            if !messages_for(&refused, index).is_empty() {
                failures.push(format!("{}: its rule is one that is refused", event.at));
            }
        }
    } else if let Err(refused) = load(negated, pack) {
        failures.push(format!(
            "{file}: the negated rules are refused: {}",
            describe(&refused)
        ));
    } else {
        failures.push(format!("{file}: the engine does not open: {error}"));
    }
}

/// Check that a rule which reads a field as another type, or names an undeclared effect, is refused
/// for that reason.
fn check_field_types(file: &str, pack: &Pack, failures: &mut Vec<String>) {
    let namespace = pack.namespace();
    let mut probes = Vec::new();
    for (action, fields) in pack.grammar().action_fields() {
        for (name, kind) in fields {
            probes.push((
                format!("{}.{name}", action.as_str()),
                mistyped_reason(kind),
                rule(&namespace, action.as_str(), &mistyped_condition(name, kind)),
            ));
        }
    }
    if let Some(effect) = pack.effects.keys().next() {
        let undeclared = format!("{}_undeclared", effect.as_str());
        probes.push((
            format!("effect {undeclared}"),
            UNDECLARED_EFFECT,
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
    if probes.is_empty() {
        return;
    }
    let source: String = probes.iter().map(|(_, _, rule)| rule.as_str()).collect();
    let refused = match load(&source, pack) {
        Ok(()) => {
            failures.push(format!(
                "{file}: every rule that reads a value as another type loads"
            ));
            return;
        }
        Err(refused) => refused,
    };
    for (index, (name, reason, _)) in probes.iter().enumerate() {
        let messages = messages_for(&refused, index);
        if !matches!(messages.as_slice(), [message] if message.contains(reason)) {
            failures.push(format!(
                "{file}: the probe over {name} is not refused for {reason:?}: {messages:?}; {}",
                describe(&refused)
            ));
        }
    }
}

#[test]
fn every_corpus_case_is_typed_and_decided_by_the_policy_engine() {
    let mut failures = Vec::new();
    let mut count = 0;
    for (file, pack, cases) in corpora() {
        if cases.is_empty() {
            failures.push(format!("{file}: holds no case"));
        }
        count += cases.len();
        check_corpus(&file, &pack, &cases, &mut failures);
        check_field_types(&file, &pack, &mut failures);
    }

    assert!(count > 0, "the corpus holds no case");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn a_group_permit_never_reaches_an_unmodeled_command_and_an_explicit_permit_does() {
    const GROUP_PERMIT_AND_EFFECT_FORBID: &str = r#"
        permit (principal, action in Tool::git::Action::"*", resource);
        forbid (principal, action in Tool::git::Action::"*", resource)
        when { context.input.effects.contains(Tool::git::Effect::"delete_remote_ref")
               || context.input.effects.contains(Tool::git::Effect::"run_program") };
    "#;
    const UNMODELED_PERMIT: &str =
        r#"permit (principal, action == Tool::git::Action::"unmodeled", resource);"#;
    const FORBID_THE_GROUP_AND_UNMODELED: &str = r#"
        permit (principal, action, resource);
        forbid (principal, action in [Tool::git::Action::"*", Tool::git::Action::"unmodeled"], resource);
    "#;
    const GROUP_PERMIT: &str = r#"permit (principal, action in Tool::git::Action::"*", resource);"#;
    let explicit = format!("{GROUP_PERMIT_AND_EFFECT_FORBID}{UNMODELED_PERMIT}");
    let cases: [(&str, &[&str], bool); 11] = [
        (GROUP_PERMIT, &["git", "status"], true),
        (
            GROUP_PERMIT,
            &["git", "--exec-path=/tmp/evil", "push"],
            false,
        ),
        (GROUP_PERMIT_AND_EFFECT_FORBID, &["git", "status"], true),
        (
            GROUP_PERMIT_AND_EFFECT_FORBID,
            &["git", "push", "--delete", "origin", "main"],
            false,
        ),
        (
            GROUP_PERMIT_AND_EFFECT_FORBID,
            &["git", "push", "--dele", "origin", "main"],
            false,
        ),
        (
            GROUP_PERMIT_AND_EFFECT_FORBID,
            &["git", "--exec-path=/tmp/evil", "push"],
            false,
        ),
        (&explicit, &["git", "status"], true),
        (
            &explicit,
            &["git", "push", "--dele", "origin", "main"],
            true,
        ),
        (&explicit, &["git", "--exec-path=/tmp/evil", "push"], true),
        (FORBID_THE_GROUP_AND_UNMODELED, &["git", "status"], false),
        (
            FORBID_THE_GROUP_AND_UNMODELED,
            &["git", "--exec-path=/tmp/evil", "push"],
            false,
        ),
    ];
    let pack = Pack::load(&Path::new(PACKS).join("valid").join("git.pack.toml"))
        .expect("the git pack loads");
    let mut failures = Vec::new();
    for (policy, argv, allowed) in cases {
        let engine = match open(policy, &pack) {
            Ok(engine) => engine,
            Err(refusal) => {
                failures.push(format!("{argv:?}: the policy is refused: {refusal}"));
                continue;
            }
        };
        let argv: Vec<String> = argv.iter().map(ToString::to_string).collect();
        match verdict(&engine.decide(&pack, &argv)) {
            Ok((verdict, _)) if verdict == allowed => {}
            Ok((verdict, _)) => failures.push(format!(
                "{argv:?}: allowed is {verdict}, expected {allowed}, under\n{policy}"
            )),
            Err(error) => failures.push(format!("{argv:?}: {error}")),
        }
    }

    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
