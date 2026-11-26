//! The DNS-name enrichment facts a `net:connect` request carries, and which entries the rules read.

use std::collections::{BTreeMap, BTreeSet};

use dogwood_language::PolicySchema;
use dogwood_language::temporal_ast::{AggExprKind, Condition, ConditionKind, Term};
use serde_json::Value;

use crate::check::{Finding, Refused, RuleRef, annotated_id};
use crate::error::PolicyError;
use crate::schema::{SchemaBase, action, composed_action_schema};

/// The longest name an enrichment entry takes.
const MAXIMUM_NAME: usize = 32;

/// Cedar's reserved words that the name pattern admits, which a rule could not read unquoted.
const RESERVED_WORDS: &[&str] = &[
    "true", "false", "if", "then", "else", "in", "is", "like", "has",
];

/// The `context.input` attribute that holds every entry's answer.
pub(crate) const ENRICHMENT: &str = "enrichment";
/// The attribute of one entry that says whether its source answered.
pub(crate) const ANSWERED: &str = "answered";
/// The attribute of one entry that holds the labels its source gave.
pub(crate) const LABELS: &str = "labels";

/// The validated names of the enrichment entries one box declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnrichmentNames(BTreeSet<String>);

impl EnrichmentNames {
    /// Validate each name as one a rule reads as `context.input.enrichment.<name>` with no quoting.
    pub fn new(names: impl IntoIterator<Item = String>) -> Result<Self, EnrichmentNameError> {
        let mut declared = BTreeSet::new();
        for name in names {
            let mut characters = name.chars();
            let spelled = characters
                .next()
                .is_some_and(|first| first.is_ascii_lowercase())
                && characters.all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
                })
                && name.len() <= MAXIMUM_NAME;
            if !spelled {
                return Err(EnrichmentNameError {
                    name,
                    reserved: false,
                });
            }
            if RESERVED_WORDS.contains(&name.as_str()) {
                return Err(EnrichmentNameError {
                    name,
                    reserved: true,
                });
            }
            declared.insert(name);
        }
        Ok(Self(declared))
    }

    /// Whether the box declares no entry.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Each declared name, in order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    fn contains(&self, name: &str) -> bool {
        self.0.contains(name)
    }
}

/// Why a name cannot name an enrichment entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrichmentNameError {
    name: String,
    reserved: bool,
}

impl EnrichmentNameError {
    /// The refused name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for EnrichmentNameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .write_str("is not a name a rule can read as context.input.enrichment.<name>: ")?;
        if self.reserved {
            write!(formatter, "{:?} is a Cedar reserved word", self.name)
        } else {
            write!(
                formatter,
                "use a lowercase letter, then at most {} lowercase letters, digits, or '_'",
                MAXIMUM_NAME - 1
            )
        }
    }
}

impl std::error::Error for EnrichmentNameError {}

/// The labels an unanswered entry carries.
static NO_LABELS: BTreeSet<String> = BTreeSet::new();

/// One entry's answer about one host, as `context.input.enrichment.<name>` carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrichmentAnswer {
    /// The labels of an answer, or `None` when the source gave none, so no label rides no answer.
    labels: Option<BTreeSet<String>>,
}

impl EnrichmentAnswer {
    /// An answer that carries `labels`, which may be empty.
    pub fn answered(labels: impl IntoIterator<Item = String>) -> Self {
        Self {
            labels: Some(labels.into_iter().collect()),
        }
    }

    /// No answer, which carries no label.
    #[must_use]
    pub fn unanswered() -> Self {
        Self { labels: None }
    }

    /// Whether the source answered.
    #[must_use]
    pub fn is_answered(&self) -> bool {
        self.labels.is_some()
    }

    /// The labels the answer carries, and none when the source did not answer.
    #[must_use]
    pub fn labels(&self) -> &BTreeSet<String> {
        self.labels.as_ref().unwrap_or(&NO_LABELS)
    }
}

/// The answers one `net:connect` request carries, by entry name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnrichmentFacts(BTreeMap<String, EnrichmentAnswer>);

impl EnrichmentFacts {
    /// The facts of a box that declares no entry.
    pub const NONE: Self = Self(BTreeMap::new());

    /// Each entry's answer, by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &EnrichmentAnswer)> {
        self.0.iter().map(|(name, answer)| (name.as_str(), answer))
    }

    /// Whether the facts carry no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<(String, EnrichmentAnswer)> for EnrichmentFacts {
    fn from_iter<I: IntoIterator<Item = (String, EnrichmentAnswer)>>(answers: I) -> Self {
        Self(answers.into_iter().collect())
    }
}

/// What the egress adapter asks about a destination host before policy decides its `net:connect`.
pub trait HostEnricher: Send + Sync {
    /// The answer of every declared entry about `host`, which may ask each entry's source.
    fn enrich(&self, host: &str) -> EnrichmentFacts;

    /// The answers that the latest [`Self::enrich`] on this thread returned about `host`, asking no
    /// source, since each address decision follows its host decision on one thread.
    fn recall(&self, host: &str) -> EnrichmentFacts;
}

/// Which part of one entry a rule reads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Labels,
    Answered,
}

/// Refuse `expanded` when a rule reads an entry no table declares, or reads an entry's labels while
/// no rule reads its answer, and return the declared entries that some rule reads.
pub(crate) fn read_entries(
    expanded: &[String],
    base: &SchemaBase,
) -> Result<BTreeSet<String>, Refused> {
    // A rule names an entry only by spelling `enrichment`, and with no entry declared a read of the
    // whole input reaches none, so such a policy reads nothing here.
    if base.enrichment.is_empty() && !expanded.iter().any(|rule| rule.contains(ENRICHMENT)) {
        return Ok(BTreeSet::new());
    }
    let policy_schema =
        PolicySchema::from_cedarschema_str(&composed_action_schema(base, &[])?.source)
            .map_err(|error| PolicyError::Schema(format!("dogwood action schema: {error}")))?;
    let service = crate::dogwood::service_schema()?;
    let mut undeclared: BTreeMap<Option<String>, Vec<usize>> = BTreeMap::new();
    let mut labels: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut answered: BTreeSet<String> = BTreeSet::new();
    for (ordinal, rule) in expanded.iter().enumerate() {
        let mut paths = Vec::new();
        if let Ok(parsed) = dogwood_language::ParsedPolicySet::parse(rule, &service) {
            for policy in parsed.policies() {
                for condition in policy.temporal_conditions() {
                    history_paths(condition, &mut paths);
                }
            }
        }
        // A rule that does not lower against `base`, such as one waiting for a tool schema, cannot
        // read the `net:connect` context, so only its history is read.
        let stateless = crate::dogwood::without_temporal(rule);
        if let Some(lowered) = dogwood_language::ParsedPolicySet::parse(&stateless, &service)
            .ok()
            .and_then(|parsed| parsed.lower(&policy_schema).ok())
        {
            for policy in lowered.as_cedar().policies().filter(decides_connect) {
                let est = policy.to_json().map_err(|error| {
                    PolicyError::Schema(format!(
                        "rule {} cannot be inspected at load: {error}",
                        ordinal + 1
                    ))
                })?;
                context_paths(&est["conditions"], &mut paths);
            }
        }
        for path in &paths {
            let parts = match parts_read(path, &base.enrichment) {
                Ok(parts) => parts,
                Err(name) => {
                    note(undeclared.entry(name).or_default(), ordinal);
                    continue;
                }
            };
            for (name, part) in parts {
                match part {
                    Part::Labels => note(labels.entry(name).or_default(), ordinal),
                    Part::Answered => {
                        answered.insert(name);
                    }
                }
            }
        }
    }
    let findings: Vec<Finding> = undeclared
        .iter()
        .map(|(name, rules)| undeclared_entry(name.as_deref(), rules, expanded))
        .chain(
            labels
                .iter()
                .filter(|(name, _)| !answered.contains(*name))
                .map(|(name, rules)| unanswered_labels(name, rules, expanded)),
        )
        .collect();
    if !findings.is_empty() {
        let text = findings
            .iter()
            .map(Finding::message)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Refused::new(PolicyError::Schema(text), findings));
    }
    Ok(labels.into_keys().chain(answered).collect())
}

/// Add the rule `ordinal` to `rules` once.
fn note(rules: &mut Vec<usize>, ordinal: usize) {
    if !rules.contains(&ordinal) {
        rules.push(ordinal);
    }
}

/// Whether a lowered rule's head admits `net:connect`, the one action whose input holds
/// `enrichment`, so that a tool input of that name is not read as an entry.
fn decides_connect(policy: &&cedar_policy::Policy) -> bool {
    let connect = |uid: &cedar_policy::EntityUid| {
        uid.type_name().to_string() == "Box::Action" && uid.id().unescaped() == action::NET_CONNECT
    };
    match policy.action_constraint() {
        cedar_policy::ActionConstraint::Any => true,
        cedar_policy::ActionConstraint::Eq(uid) => connect(&uid),
        cedar_policy::ActionConstraint::In(uids) => uids.iter().any(connect),
    }
}

/// Refuse a reload whose rules read other entries than the running policy's, because the box asks
/// only the sources of the entries its rules read at open, and disclosed which.
pub(crate) fn refuse_changed_reads(
    running: &BTreeSet<String>,
    reloaded: &BTreeSet<String>,
) -> Result<(), PolicyError> {
    if running == reloaded {
        return Ok(());
    }
    let tables = |names: &BTreeSet<String>| {
        if names.is_empty() {
            return "none".to_string();
        }
        names
            .iter()
            .map(|name| format!("[{ENRICHMENT}.{name}]"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(PolicyError::Schema(format!(
        "a reload cannot change which [{ENRICHMENT}.<name>] tables a rule reads: the running \
         policy reads {}, and this one reads {}; restart the box to apply it",
        tables(running),
        tables(reloaded)
    )))
}

/// The rules at `rules`, as findings reference them and as their message names them.
fn named_rules(rules: &[usize], expanded: &[String]) -> (Vec<RuleRef>, String) {
    let refs = rules
        .iter()
        .map(|ordinal| {
            RuleRef::new(
                *ordinal,
                expanded
                    .get(*ordinal)
                    .and_then(|source| annotated_id(source)),
            )
        })
        .collect();
    let named = rules
        .iter()
        .map(|ordinal| {
            let source = expanded.get(*ordinal).map_or("", String::as_str);
            format!(
                "{} (rule {})",
                crate::dogwood::parsed_rule_name(source, annotated_id(source).as_deref()),
                ordinal + 1
            )
        })
        .collect::<Vec<_>>()
        .join(" and ");
    (refs, named)
}

/// The finding for an entry, or with `None` the whole record, that `rules` read and no table
/// declares.
fn undeclared_entry(name: Option<&str>, rules: &[usize], expanded: &[String]) -> Finding {
    let (refs, named) = named_rules(rules, expanded);
    let verb = if rules.len() == 1 { "reads" } else { "read" };
    let text = match name {
        Some(name) => format!(
            "{named} {verb} context.input.{ENRICHMENT}.{name}, but the box declares no \
             [{ENRICHMENT}.{name}] table; declare the table, or read an entry the box declares"
        ),
        None => format!(
            "{named} {verb} context.input.{ENRICHMENT}, but the box declares no \
             [{ENRICHMENT}.<name>] table"
        ),
    };
    Finding::new(text).with_rules(refs)
}

/// The finding for an entry whose labels `rules` read while no rule reads its answer.
fn unanswered_labels(name: &str, rules: &[usize], expanded: &[String]) -> Finding {
    let (refs, named) = named_rules(rules, expanded);
    let verb = if rules.len() == 1 { "reads" } else { "read" };
    Finding::new(format!(
        "{named} {verb} context.input.{ENRICHMENT}.{name}.{LABELS}, but no rule reads \
         context.input.{ENRICHMENT}.{name}.{ANSWERED}; an entry with no answer then reads like a \
         host with no labels. Add a rule on {ANSWERED}, such as: forbid (principal, action == \
         Box::Action::\"{connect}\", resource) unless {{ context.input.{ENRICHMENT}.{name}.{ANSWERED} }};",
        connect = action::NET_CONNECT,
    ))
    .with_rules(refs)
}

/// The entry parts that one read of `context.<path>` reaches, or the entry it names that no table
/// declares, which is `None` for the whole record of a box that declares none.
fn parts_read(
    path: &[String],
    names: &EnrichmentNames,
) -> Result<Vec<(String, Part)>, Option<String>> {
    let both = |name: &str| {
        [Part::Labels, Part::Answered]
            .into_iter()
            .map(|part| (name.to_string(), part))
            .collect::<Vec<_>>()
    };
    let segments: Vec<&str> = path.iter().map(String::as_str).collect();
    match segments.as_slice() {
        ["input", ENRICHMENT] if names.is_empty() => Err(None),
        [] | ["input"] | ["input", ENRICHMENT] => Ok(names.iter().flat_map(both).collect()),
        ["input", ENRICHMENT, name, ..] if !names.contains(name) => Err(Some((*name).to_string())),
        ["input", ENRICHMENT, name, rest @ ..] => Ok(match rest.first() {
            None => both(name),
            Some(&LABELS) => vec![(name.to_string(), Part::Labels)],
            Some(&ANSWERED) => vec![(name.to_string(), Part::Answered)],
            Some(_) => Vec::new(),
        }),
        _ => Ok(Vec::new()),
    }
}

/// The path a node reads from `context`, when it is an attribute chain that starts there.
fn context_path(node: &Value) -> Option<Vec<String>> {
    if node.get("Var").and_then(Value::as_str) == Some("context") {
        return Some(Vec::new());
    }
    let access = node.get(".")?;
    let mut path = context_path(access.get("left")?)?;
    path.push(access.get("attr")?.as_str()?.to_string());
    Some(path)
}

/// Every read of a value from `context` in a Cedar condition, each the longest chain that reads
/// it; a `has` test reads none.
fn context_paths(node: &Value, out: &mut Vec<Vec<String>>) {
    match node {
        Value::Array(items) => items.iter().for_each(|item| context_paths(item, out)),
        Value::Object(fields) => {
            if let Some(path) = context_path(node) {
                out.push(path);
                return;
            }
            // A `has` test reads no value, so only a read inside its left side counts.
            if let Some(test) = fields.get("has") {
                if let Some(left) = test.get("left").filter(|left| context_path(left).is_none()) {
                    context_paths(left, out);
                }
                return;
            }
            fields.values().for_each(|value| context_paths(value, out));
        }
        _ => {}
    }
}

/// Every field a `net:connect` predicate names in one temporal condition, from `context`.
fn history_paths(condition: &Condition, out: &mut Vec<Vec<String>>) {
    fn term_paths(term: &Term, out: &mut Vec<Vec<String>>) {
        match term {
            Term::Agg(aggregate) => match &aggregate.kind {
                AggExprKind::Sum { body, .. } | AggExprKind::Count { body, .. } => {
                    history_paths(body, out);
                }
                AggExprKind::Call(_) => {}
            },
            Term::Array(items) => items.iter().for_each(|item| term_paths(item, out)),
            _ => {}
        }
    }
    match &condition.kind {
        ConditionKind::And { left, right }
        | ConditionKind::Or { left, right }
        | ConditionKind::Since { left, right, .. } => {
            history_paths(left, out);
            history_paths(right, out);
        }
        ConditionKind::Not { inner: body }
        | ConditionKind::Formerly { body, .. }
        | ConditionKind::Previous { body, .. }
        | ConditionKind::Exists { body, .. }
        | ConditionKind::Refine { base: body, .. } => history_paths(body, out),
        ConditionKind::Predicate(predicate) => {
            if predicate.namespace == ["Box", "Action"] && predicate.action == action::NET_CONNECT {
                out.extend(predicate.args.iter().map(|argument| argument.field_path()));
            }
            for argument in &predicate.args {
                term_paths(&argument.value, out);
            }
        }
        ConditionKind::Comparison { left, right, .. } => {
            term_paths(left, out);
            term_paths(right, out);
        }
        ConditionKind::Tp { .. } | ConditionKind::Call(_) | ConditionKind::SigilRef { .. } => {}
    }
}
