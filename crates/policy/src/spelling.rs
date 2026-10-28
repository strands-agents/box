//! Load-time judgement of the path, program, and host literals a rule compares.

use std::path::PathBuf;

use cedar_policy::{ActionConstraint, EntityUid, Policy, PolicySet};
use egress_gateway::{is_bindable_host, normalize_host};
use serde_json::Value;

use crate::PolicyError;
use crate::check::{Refused, RuleRef};
use crate::schema::action::FS_OTHER;
use crate::schema::attr::{HOST, PATH, PROGRAM, PROGRAM_PATH};

const BOX_ACTION_TYPE: &str = "Box::Action";

/// The operator a policy loads for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Operator {
    home: Option<PathBuf>,
}

impl Operator {
    /// An operator with no stated home, so no literal is judged against one.
    #[must_use]
    pub fn unanchored() -> Self {
        Self { home: None }
    }

    /// State the home a rule's path literal is spelled `~/…` under.
    #[must_use]
    pub fn anchored_at(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Every spelling of the home a literal is judged against: as stated, and canonical.
    fn homes(&self) -> Vec<String> {
        let Some(home) = &self.home else {
            return Vec::new();
        };
        let mut homes = Vec::new();
        for candidate in [Some(home.clone()), home.canonicalize().ok()]
            .into_iter()
            .flatten()
        {
            let Some(text) = candidate.to_str() else {
                continue;
            };
            let trimmed = text.trim_end_matches('/');
            let spelling = if trimmed.is_empty() { "/" } else { trimmed };
            if !homes.iter().any(|known| known == spelling) {
                homes.push(spelling.to_string());
            }
        }
        homes
    }
}

/// A load-time finding that does not refuse the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyWarning {
    /// A `like` pattern names the operator home after a wildcard, so its reach cannot be judged.
    HomeAfterWildcard {
        /// The rule, by `@id` when it has one.
        rule: String,
        /// The attribute the rule compares.
        attribute: String,
        /// The pattern as written.
        pattern: String,
    },
    /// A `program` literal holds a path separator, so it matches only that spelling of the first word.
    ProgramSpelledAsPath {
        /// The rule, by `@id` when it has one.
        rule: String,
        /// The literal or pattern as written.
        literal: String,
    },
    /// A permit's temporal clause sits beside another permit for the same principal and action.
    InertTemporalPermit {
        /// Both rules, by `@id` when each has one, and why the budget may be inert.
        finding: String,
    },
}

impl std::fmt::Display for PolicyWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HomeAfterWildcard {
                rule,
                attribute,
                pattern,
            } => write!(
                formatter,
                "{rule} compares context.input.{attribute} with the pattern \"{pattern}\", which \
                 names the operator home after a wildcard; a path under the operator home is \
                 spelled ~/…, so the pattern may match nothing"
            ),
            Self::ProgramSpelledAsPath { rule, literal } => write!(
                formatter,
                "{rule} compares context.input.program with \"{literal}\", which matches only a \
                 first word spelled that way; compare context.input.{PROGRAM_PATH} to match the \
                 resolved binary"
            ),
            Self::InertTemporalPermit { finding } => formatter.write_str(finding),
        }
    }
}

/// One literal a rule compares an input attribute with.
#[derive(Debug)]
enum Comparison {
    Equals(String),
    Like(Vec<PatternElement>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternElement {
    Wildcard,
    Literal(String),
}

enum Finding {
    Sound,
    Inert(String),
    Uncertain(String),
    ProgramPath(String),
}

/// `judge_naming` with no rule names, for the tests that read only the refusal text.
#[cfg(test)]
pub(crate) fn judge(
    policies: &PolicySet,
    operator: &Operator,
) -> Result<Vec<PolicyWarning>, PolicyError> {
    judge_naming(policies, operator, &|_| None).map_err(Refused::into_error)
}

/// Refuse every literal that no reported spelling can match; return the uncertain ones.
pub(crate) fn judge_naming(
    policies: &PolicySet,
    operator: &Operator,
    rule_of: &dyn Fn(&str) -> Option<RuleRef>,
) -> Result<Vec<PolicyWarning>, Refused> {
    let homes = operator.homes();
    let mut warnings = Vec::new();
    for policy in policies.policies() {
        let Some(scope) = Scope::of(policy) else {
            continue;
        };
        let rule = rule_name(policy);
        let est = policy.to_json().map_err(|error| {
            PolicyError::Schema(format!("{rule} cannot be inspected at load: {error}"))
        })?;
        let mut comparisons = Vec::new();
        collect(&est["conditions"], &mut comparisons);
        for (attribute, comparison) in comparisons {
            let Some(checks) = scope.checks(&attribute) else {
                continue;
            };
            let finding = match comparison {
                Comparison::Equals(literal) => judge_literal(&attribute, &literal, &homes, checks),
                Comparison::Like(elements) => judge_pattern(&attribute, &elements, &homes, checks),
            };
            match finding {
                Finding::Sound => {}
                Finding::Inert(reason) => {
                    let text = format!("{rule} {reason}");
                    let rules = rule_of(policy.id().as_ref()).into_iter().collect();
                    return Err(Refused::new(
                        PolicyError::Spelling(text.clone()),
                        vec![crate::check::Finding::new(text).with_rules(rules)],
                    ));
                }
                Finding::Uncertain(pattern) => warnings.push(PolicyWarning::HomeAfterWildcard {
                    rule: rule.clone(),
                    attribute,
                    pattern,
                }),
                Finding::ProgramPath(literal) => {
                    warnings.push(PolicyWarning::ProgramSpelledAsPath {
                        rule: rule.clone(),
                        literal,
                    });
                }
            }
        }
    }
    Ok(warnings)
}

/// Whether every action in the rule's scope is `fs:other`.
pub(crate) fn names_only_reserved_action(policy: &Policy) -> bool {
    let uids = match policy.action_constraint() {
        ActionConstraint::Any => return false,
        ActionConstraint::Eq(uid) => vec![uid],
        ActionConstraint::In(uids) => uids,
    };
    !uids.is_empty()
        && uids.iter().all(|uid| {
            uid.type_name().to_string() == BOX_ACTION_TYPE && uid.id().escaped() == FS_OTHER
        })
}

/// The action family a rule's scope names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Filesystem,
    Shell,
    Network,
    /// Unconstrained, or more than one family, so `path` may be a URL path.
    Unscoped,
}

/// Which judgements apply to one attribute under one scope.
#[derive(Debug, Clone, Copy)]
struct Checks {
    trailing_slash: bool,
}

impl Scope {
    /// The scope of `policy`, or `None` when it names an action outside `Box::Action` or only
    /// actions of no judged family.
    fn of(policy: &Policy) -> Option<Self> {
        let uids = match policy.action_constraint() {
            ActionConstraint::Any => return Some(Self::Unscoped),
            ActionConstraint::Eq(uid) => vec![uid],
            ActionConstraint::In(uids) => uids,
        };
        if uids
            .iter()
            .any(|uid| uid.type_name().to_string() != BOX_ACTION_TYPE)
        {
            return None;
        }
        let families: Vec<Option<Self>> = uids.iter().map(Self::family).collect();
        let first = (*families.first()?)?;
        if families.iter().all(|family| family.is_none()) {
            return None;
        }
        Some(if families.iter().all(|family| *family == Some(first)) {
            first
        } else {
            Self::Unscoped
        })
    }

    fn family(uid: &EntityUid) -> Option<Self> {
        let id = uid.id().escaped();
        if id.starts_with("fs:") {
            Some(Self::Filesystem)
        } else if id.starts_with("shell:") {
            Some(Self::Shell)
        } else if id.starts_with("net:") || id.starts_with("http:") {
            Some(Self::Network)
        } else {
            None
        }
    }

    fn checks(self, attribute: &str) -> Option<Checks> {
        match (self, attribute) {
            (Self::Filesystem, PATH) | (Self::Shell, PROGRAM | PROGRAM_PATH) => Some(Checks {
                trailing_slash: true,
            }),
            (Self::Unscoped, PATH | PROGRAM_PATH | PROGRAM) => Some(Checks {
                trailing_slash: false,
            }),
            (Self::Network, HOST) => Some(Checks {
                trailing_slash: false,
            }),
            _ => None,
        }
    }
}

fn judge_literal(attribute: &str, literal: &str, homes: &[String], checks: Checks) -> Finding {
    if attribute == HOST {
        return judge_host_literal(literal);
    }
    if attribute == PROGRAM {
        return if literal.contains('/') {
            Finding::ProgramPath(literal.to_string())
        } else {
            Finding::Sound
        };
    }
    if let Some(home) = home_prefix(literal, homes) {
        let corrected = home_relative(literal, home, false);
        return Finding::Inert(format!(
            "compares context.input.{attribute} with \"{literal}\", and a path under the \
             operator home is spelled ~/…; write \"{corrected}\""
        ));
    }
    if checks.trailing_slash && has_trailing_slash(literal) {
        let corrected = literal.trim_end_matches('/');
        return Finding::Inert(format!(
            "compares context.input.{attribute} with \"{literal}\", and a directory is spelled \
             without a trailing slash; write \"{corrected}\""
        ));
    }
    Finding::Sound
}

fn judge_pattern(
    attribute: &str,
    elements: &[PatternElement],
    homes: &[String],
    checks: Checks,
) -> Finding {
    let pattern = render(elements);
    if attribute == HOST {
        return judge_host_pattern(elements, &pattern);
    }
    if attribute == PROGRAM {
        let names_a_path = elements
            .iter()
            .any(|element| matches!(element, PatternElement::Literal(text) if text.contains('/')));
        return if names_a_path {
            Finding::ProgramPath(pattern)
        } else {
            Finding::Sound
        };
    }
    if let Some(PatternElement::Literal(first)) = elements.first()
        && let Some(home) = home_prefix(first, homes)
    {
        let corrected = format!(
            "{}{}",
            home_relative(first, home, true),
            render(&elements[1..])
        );
        return Finding::Inert(format!(
            "compares context.input.{attribute} with the pattern \"{pattern}\", and a path under \
             the operator home is spelled ~/…; write \"{corrected}\""
        ));
    }
    if checks.trailing_slash
        && let Some(PatternElement::Literal(last)) = elements.last()
        && last.ends_with('/')
        && pattern != "/"
    {
        let corrected = pattern.trim_end_matches('/');
        return Finding::Inert(format!(
            "compares context.input.{attribute} with the pattern \"{pattern}\", and a directory \
             is spelled without a trailing slash; write \"{corrected}\""
        ));
    }
    let names_home = |element: &PatternElement| matches!(element, PatternElement::Literal(text) if homes.iter().any(|home| home != "/" && contains_home_component(text, home)));
    if elements.iter().skip(1).any(names_home) {
        return Finding::Uncertain(pattern);
    }
    Finding::Sound
}

/// A host literal the gateway can bind, which it can only when the literal is its own
/// [`normalize_host`] form and [`is_bindable_host`] accepts it.
fn judge_host_literal(literal: &str) -> Finding {
    let canonical = normalize_host(literal);
    if !is_bindable_host(&canonical) {
        return Finding::Inert(format!(
            "compares context.input.{HOST} with \"{literal}\", which no destination host can \
             equal; {}",
            unbindable_advice(&canonical)
        ));
    }
    if canonical != literal {
        return Finding::Inert(format!(
            "compares context.input.{HOST} with \"{literal}\", and a host is spelled in lowercase \
             and without a trailing dot; write \"{canonical}\""
        ));
    }
    Finding::Sound
}

/// A host pattern whose every literal element holds only bytes a bound host holds.
fn judge_host_pattern(elements: &[PatternElement], pattern: &str) -> Finding {
    let refuse = |advice: String| {
        Finding::Inert(format!(
            "compares context.input.{HOST} with the pattern \"{pattern}\", which no destination \
             host can match; {advice}"
        ))
    };
    for element in elements {
        let PatternElement::Literal(text) = element else {
            continue;
        };
        if !text.is_ascii() {
            return refuse(punycode_advice());
        }
        let lowercase = text.to_ascii_lowercase();
        if let Some(byte) = lowercase.bytes().find(|byte| !is_host_byte(*byte)) {
            return refuse(format!(
                "a host holds no \"{}\"; it holds only letters, digits, \".\", \"-\", and \"_\", \
                 or an IP address",
                char::from(byte).escape_debug()
            ));
        }
        if *text != lowercase {
            let corrected = render(&lowercased(elements));
            return refuse(format!(
                "a host is spelled in lowercase; write \"{corrected}\""
            ));
        }
    }
    if let Some(PatternElement::Literal(last)) = elements.last()
        && last.ends_with('.')
    {
        let corrected = pattern.trim_end_matches('.');
        return refuse(if corrected.is_empty() {
            "a host is never empty".to_string()
        } else {
            format!("a host carries no trailing dot; write \"{corrected}\"")
        });
    }
    Finding::Sound
}

/// Why no bound host equals `canonical`, which is already in [`normalize_host`] form.
fn unbindable_advice(canonical: &str) -> String {
    if !canonical.is_ascii() {
        return punycode_advice();
    }
    if canonical.is_empty() {
        return "a host is never empty".to_string();
    }
    if let Some(host) = host_before_port(canonical) {
        return format!("a host carries no port; write \"{host}\" and compare context.input.port");
    }
    "a host holds only letters, digits, \".\", \"-\", and \"_\", or an IP address".to_string()
}

fn punycode_advice() -> String {
    "an internationalized host reaches the gateway in its punycode form, so write the \"xn--…\" \
     spelling"
        .to_string()
}

/// The bindable host `canonical` holds before a numeric port suffix.
fn host_before_port(canonical: &str) -> Option<&str> {
    let (host, port) = canonical.rsplit_once(':')?;
    (!port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) && is_bindable_host(host))
        .then_some(host)
}

/// Whether a bound host ever holds `byte`, which it does for a lowercase name and for an IP.
fn is_host_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_' | b':')
}

fn lowercased(elements: &[PatternElement]) -> Vec<PatternElement> {
    elements
        .iter()
        .map(|element| match element {
            PatternElement::Wildcard => PatternElement::Wildcard,
            PatternElement::Literal(text) => PatternElement::Literal(text.to_ascii_lowercase()),
        })
        .collect()
}

/// Whether `text` holds `home` as a whole run of path components, bounded by `/` on both sides.
fn contains_home_component(text: &str, home: &str) -> bool {
    text.match_indices(home).any(|(index, _)| {
        let before = text[..index].chars().next_back();
        let after = text[index + home.len()..].chars().next();
        matches!(before, None | Some('/')) && matches!(after, None | Some('/'))
    })
}

/// The home `literal` names or sits under, when there is one.
fn home_prefix<'h>(literal: &str, homes: &'h [String]) -> Option<&'h str> {
    homes
        .iter()
        .find(|home| {
            literal == home.as_str()
                || (home.as_str() == "/" && literal.starts_with('/'))
                || literal
                    .strip_prefix(home.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .map(String::as_str)
}

/// `literal` respelled `~/…` under `home`; a pattern prefix keeps its trailing slash.
fn home_relative(literal: &str, home: &str, keep_trailing_slash: bool) -> String {
    let rest = if home == "/" {
        literal.strip_prefix('/').unwrap_or(literal)
    } else {
        literal[home.len()..].trim_start_matches('/')
    };
    let rest = if keep_trailing_slash {
        rest
    } else {
        rest.trim_end_matches('/')
    };
    if rest.is_empty() {
        "~".to_string()
    } else {
        format!("~/{rest}")
    }
}

fn has_trailing_slash(literal: &str) -> bool {
    literal.len() > 1 && literal.ends_with('/')
}

fn render(elements: &[PatternElement]) -> String {
    elements
        .iter()
        .map(|element| match element {
            PatternElement::Wildcard => "*".to_string(),
            PatternElement::Literal(text) => text.replace('*', "\\*"),
        })
        .collect()
}

pub(crate) fn rule_name(policy: &Policy) -> String {
    match policy.annotation("id") {
        Some(id) => format!("rule @id(\"{id}\")"),
        None => format!(
            "the {} rule with no @id",
            match policy.effect() {
                cedar_policy::Effect::Permit => "permit",
                cedar_policy::Effect::Forbid => "forbid",
            }
        ),
    }
}

/// Every comparison of `context.input.<attribute>` with a literal, anywhere in `node`.
fn collect(node: &Value, out: &mut Vec<(String, Comparison)>) {
    match node {
        Value::Array(items) => items.iter().for_each(|item| collect(item, out)),
        Value::Object(fields) => {
            if let Some(operands) = fields.get("==") {
                for (side, other) in [("left", "right"), ("right", "left")] {
                    if let Some(attribute) = input_attribute(&operands[side])
                        && let Some(literal) = string_value(&operands[other])
                    {
                        out.push((attribute, Comparison::Equals(literal)));
                    }
                }
            }
            if let Some(operands) = fields.get("like")
                && let Some(attribute) = input_attribute(&operands["left"])
                && let Some(elements) = pattern_elements(&operands["pattern"])
            {
                out.push((attribute, Comparison::Like(elements)));
            }
            if let Some(operands) = fields.get("contains")
                && let Some(attribute) = input_attribute(&operands["right"])
                && let Some(Value::Array(members)) = operands["left"].get("Set")
            {
                for literal in members.iter().filter_map(string_value) {
                    out.push((attribute.clone(), Comparison::Equals(literal)));
                }
            }
            fields.values().for_each(|value| collect(value, out));
        }
        _ => {}
    }
}

/// `path`, `program_path`, `program`, or `host` when `node` is `context.input.<that>`.
fn input_attribute(node: &Value) -> Option<String> {
    let access = node.get(".")?;
    let attribute = access.get("attr")?.as_str()?;
    if ![PATH, PROGRAM_PATH, PROGRAM, HOST].contains(&attribute) {
        return None;
    }
    let input = access.get("left")?.get(".")?;
    if input.get("attr")?.as_str()? != "input" {
        return None;
    }
    (input.get("left")?.get("Var")?.as_str()? == "context").then(|| attribute.to_string())
}

fn string_value(node: &Value) -> Option<String> {
    node.get("Value")?.as_str().map(str::to_string)
}

/// The pattern with adjacent literal characters joined into one element.
fn pattern_elements(node: &Value) -> Option<Vec<PatternElement>> {
    let mut elements: Vec<PatternElement> = Vec::new();
    for element in node.as_array()? {
        match element {
            Value::String(wildcard) if wildcard == "Wildcard" => {
                elements.push(PatternElement::Wildcard);
            }
            Value::Object(fields) => {
                let text = fields.get("Literal")?.as_str()?;
                match elements.last_mut() {
                    Some(PatternElement::Literal(run)) => run.push_str(text),
                    _ => elements.push(PatternElement::Literal(text.to_string())),
                }
            }
            _ => return None,
        }
    }
    Some(elements)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw Cedar parse; `tests/path_spelling.rs` covers the Dogwood lowering.
    fn parsed(source: &str) -> PolicySet {
        source.parse().expect("the policy parses")
    }

    fn anchored() -> Operator {
        Operator::unanchored().anchored_at("/Users/me")
    }

    #[test]
    fn an_absolute_path_under_the_home_is_refused_with_its_home_relative_form() {
        let policies = parsed(
            r#"@id("secrets")
            permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "/Users/me/project/secrets.env" };"#,
        );
        let error = judge(&policies, &anchored()).unwrap_err().to_string();
        assert!(error.contains("rule @id(\"secrets\")"), "{error}");
        assert!(error.contains("\"~/project/secrets.env\""), "{error}");

        let directory = parsed(
            r#"permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "/Users/me/project/" };"#,
        );
        let error = judge(&directory, &anchored()).unwrap_err().to_string();
        assert!(error.contains("write \"~/project\""), "{error}");
    }

    #[test]
    fn the_home_is_judged_by_path_component() {
        let policies = parsed(
            r#"permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "/Users/meow/file" };"#,
        );
        assert!(judge(&policies, &anchored()).is_ok());
    }

    #[test]
    fn a_pattern_rooted_at_the_home_is_refused_and_a_pattern_naming_it_later_warns() {
        let rooted = parsed(
            r#"permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path like "/Users/me/project/*" };"#,
        );
        let error = judge(&rooted, &anchored()).unwrap_err().to_string();
        assert!(error.contains("\"~/project/*\""), "{error}");

        let later = parsed(
            r#"permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path like "*/Users/me/*" };"#,
        );
        let warnings = judge(&later, &anchored()).expect("a warning, not a refusal");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].to_string().contains("*/Users/me/*"));

        let interior = parsed(
            r#"permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path like "/opt/Users/me/*" || context.input.path like "*/opt/Users/meow/*" };"#,
        );
        assert!(
            judge(&interior, &anchored())
                .expect("distinct paths")
                .is_empty()
        );
    }

    #[test]
    fn a_trailing_slash_is_refused_in_a_literal_and_in_a_pattern() {
        let literal = parsed(
            r#"permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "~/project/" };"#,
        );
        let error = judge(&literal, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(error.contains("write \"~/project\""), "{error}");

        let pattern = parsed(
            r#"permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path like "~/*/" };"#,
        );
        let error = judge(&pattern, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(error.contains("write \"~/*\""), "{error}");
    }

    #[test]
    fn the_root_and_a_lone_slash_pattern_are_sound() {
        let policies = parsed(
            r#"permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "/" || context.input.path like "/" };"#,
        );
        assert!(judge(&policies, &anchored()).is_ok());
    }

    #[test]
    fn a_home_at_the_root_puts_every_absolute_path_under_it() {
        let policies = parsed(
            r#"forbid(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "/etc/hosts" };"#,
        );
        let error = judge(&policies, &Operator::unanchored().anchored_at("/"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("write \"~/etc/hosts\""), "{error}");

        let relative = parsed(
            r#"forbid(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "~/etc/hosts" };"#,
        );
        assert!(judge(&relative, &Operator::unanchored().anchored_at("/")).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn the_home_is_judged_as_stated_and_as_canonical() {
        let directory = tempfile::tempdir().expect("a directory");
        let real = directory
            .path()
            .canonicalize()
            .expect("canonical")
            .join("real");
        std::fs::create_dir(&real).expect("the real home");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("a symlinked home");

        let through_link = parsed(&format!(
            r#"forbid(principal, action == Box::Action::"fs:read", resource)
            when {{ context.input.path == "{}/.aws/credentials" }};"#,
            link.display()
        ));
        let through_real = parsed(&format!(
            r#"forbid(principal, action == Box::Action::"fs:read", resource)
            when {{ context.input.path == "{}/.aws/credentials" }};"#,
            real.display()
        ));
        let operator = Operator::unanchored().anchored_at(&link);
        for policies in [through_link, through_real] {
            let error = judge(&policies, &operator).unwrap_err().to_string();
            assert!(error.contains("write \"~/.aws/credentials\""), "{error}");
        }
    }

    #[test]
    fn a_program_spelled_as_a_path_warns_and_names_program_path() {
        let policies = parsed(
            r#"permit(principal, action == Box::Action::"shell:spawn", resource)
            when { context.input.program == "/usr/bin/curl" || context.input.program like "*/wget" };"#,
        );
        let warnings = judge(&policies, &Operator::unanchored()).expect("a warning, not a refusal");
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings
                .iter()
                .all(|warning| matches!(warning, PolicyWarning::ProgramSpelledAsPath { .. })),
            "{warnings:?}"
        );
        assert!(
            warnings[0]
                .to_string()
                .contains("context.input.program_path")
        );
    }

    #[test]
    fn a_pattern_over_a_sibling_of_the_home_is_sound() {
        let policies = parsed(
            r#"forbid(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path like "/Users/meow/*" || context.input.path like "*/Users/meow/*" };"#,
        );
        assert!(judge(&policies, &anchored()).is_ok());
    }

    #[test]
    fn program_path_is_judged_as_a_path_and_not_as_a_program() {
        let policies = parsed(
            r#"permit(principal, action == Box::Action::"shell:spawn", resource)
            when { context.input.program_path == "/usr/bin/curl" };"#,
        );
        assert!(judge(&policies, &anchored()).is_ok());
    }

    #[test]
    fn a_literal_on_either_side_and_in_a_set_is_judged() {
        let reversed = parsed(
            r#"permit(principal, action == Box::Action::"fs:read", resource)
            when { "/Users/me/x" == context.input.path };"#,
        );
        assert!(judge(&reversed, &anchored()).is_err());

        let set = parsed(
            r#"permit(principal, action in [Box::Action::"fs:read", Box::Action::"fs:write"], resource)
            when { ["~/a", "/Users/me/b"].contains(context.input.path) };"#,
        );
        assert!(judge(&set, &anchored()).is_err());
    }

    #[test]
    fn an_unconstrained_scope_judges_the_home_and_warns_on_the_program_but_not_a_url_slash() {
        let broad_forbid = parsed(
            r#"forbid(principal, action, resource)
            when { context has input && context.input has path
                && context.input.path == "/Users/me/project/secrets.env" };"#,
        );
        assert!(judge(&broad_forbid, &anchored()).is_err());

        let broad_program = parsed(
            r#"forbid(principal, action, resource)
            when { context has input && context.input has program
                && context.input.program == "/usr/bin/curl" };"#,
        );
        assert_eq!(
            judge(&broad_program, &anchored()).expect("a warning").len(),
            1
        );

        let url = parsed(
            r#"permit(principal, action == Box::Action::"http:request", resource)
            when { context.input.path == "/v1/models/" || context.input.path == "/Users/me/api" };"#,
        );
        assert!(judge(&url, &anchored()).is_ok());

        let network_only = parsed(
            r#"permit(principal, action in [Box::Action::"http:request", Box::Action::"net:connect"], resource)
            when { context.input has path && context.input.path == "/Users/me/api" };"#,
        );
        assert!(judge(&network_only, &anchored()).is_ok());

        let mixed = parsed(
            r#"permit(principal, action in [Box::Action::"fs:read", Box::Action::"http:request"], resource)
            when { context.input.path == "/v1/" };"#,
        );
        assert!(judge(&mixed, &anchored()).is_ok());

        let baseline_shape = parsed(
            r#"forbid(principal, action, resource)
            when { context has input && context.input has path
                && context.input.path like "*/.strands-box/mcp-schemas/*" };"#,
        );
        assert!(judge(&baseline_shape, &anchored()).is_ok());
    }

    #[test]
    fn a_rule_over_another_namespace_is_not_judged() {
        let policies = parsed(
            r#"permit(principal, action == alpha::Action::"read", resource)
            when { context.input.path == "/Users/me/tool-argument" };"#,
        );
        assert!(judge(&policies, &anchored()).is_ok());

        let mixed = parsed(
            r#"permit(principal, action in [Box::Action::"fs:read", alpha::Action::"read"], resource)
            when { context.input.path == "/Users/me/tool-argument" };"#,
        );
        assert!(judge(&mixed, &anchored()).is_ok());
    }

    #[test]
    fn a_path_outside_the_home_is_sound() {
        let policies = parsed(
            r#"forbid(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "/etc/hosts" };"#,
        );
        assert!(judge(&policies, &anchored()).is_ok());
    }

    #[test]
    fn a_cased_or_dotted_host_literal_is_refused_with_its_canonical_spelling() {
        for (literal, canonical) in [
            ("API.Example.com", "api.example.com"),
            ("api.example.com.", "api.example.com"),
            ("api.example.com..", "api.example.com"),
            ("XN--Bcher-Kva.example", "xn--bcher-kva.example"),
            ("2001:DB8::1", "2001:db8::1"),
        ] {
            let policies = parsed(&format!(
                r#"@id("block_host")
                forbid(principal, action == Box::Action::"net:connect", resource)
                when {{ context.input.host == "{literal}" }};"#
            ));
            let error = judge(&policies, &Operator::unanchored())
                .unwrap_err()
                .to_string();
            assert!(error.contains("rule @id(\"block_host\")"), "{error}");
            assert!(error.contains(&format!("write \"{canonical}\"")), "{error}");
        }
    }

    /// The gateway refuses a non-ASCII host, so no Unicode spelling of the literal can ever bind.
    #[test]
    fn an_internationalized_host_literal_is_refused_and_names_punycode() {
        for literal in ["bücher.example", "BÜCHER.example", "ＡＰＩ.example.com"] {
            let policies = parsed(&format!(
                r#"forbid(principal, action == Box::Action::"http:request", resource)
                when {{ context.input.host == "{literal}" }};"#
            ));
            let error = judge(&policies, &Operator::unanchored())
                .unwrap_err()
                .to_string();
            assert!(error.contains("punycode"), "{error}");
            assert!(error.contains("xn--"), "{error}");
        }
    }

    #[test]
    fn a_host_literal_that_carries_a_port_names_the_port_attribute() {
        let policies = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { context.input.host == "api.example.com:443" };"#,
        );
        let error = judge(&policies, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(error.contains("write \"api.example.com\""), "{error}");
        assert!(error.contains("context.input.port"), "{error}");
    }

    #[test]
    fn a_host_literal_no_authority_yields_is_refused() {
        for literal in [
            "",
            "https://api.example.com",
            "api.example.com/v1",
            "[2001:db8::1]",
        ] {
            let policies = parsed(&format!(
                r#"forbid(principal, action == Box::Action::"net:connect", resource)
                when {{ context.input.host == "{literal}" }};"#
            ));
            assert!(
                judge(&policies, &Operator::unanchored()).is_err(),
                "{literal:?} binds to no host and must be refused"
            );
        }
    }

    /// Every spelling the gateway binds must load, so the judge refuses nothing an operator needs.
    #[test]
    fn a_canonical_host_literal_is_sound() {
        for literal in [
            "api.example.com",
            ".api.example.com",
            "api_internal.example",
            "api-internal.example",
            "xn--bcher-kva.example",
            "localhost",
            "127.0.0.1",
            "2001:db8::1",
            "::ffff:1.2.3.4",
        ] {
            let policies = parsed(&format!(
                r#"forbid(principal, action == Box::Action::"net:connect", resource)
                when {{ context.input.host == "{literal}" }};"#
            ));
            assert!(
                judge(&policies, &Operator::unanchored()).is_ok(),
                "{literal:?} is a host the gateway binds and must load"
            );
        }
    }

    #[test]
    fn a_host_pattern_is_judged_for_case_a_trailing_dot_and_an_unreachable_byte() {
        let cased = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { context.input.host like "*.Example.com" };"#,
        );
        let error = judge(&cased, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(error.contains("write \"*.example.com\""), "{error}");

        let dotted = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { context.input.host like "*.example.com." };"#,
        );
        let error = judge(&dotted, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(error.contains("write \"*.example.com\""), "{error}");

        let scheme = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { context.input.host like "https://*" };"#,
        );
        assert!(judge(&scheme, &Operator::unanchored()).is_err());

        let sound = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { context.input.host like "*.example.com"
                || context.input.host like "*bedrock-agentcore.*.amazonaws.com" };"#,
        );
        assert!(judge(&sound, &Operator::unanchored()).is_ok());
    }

    /// The host arm reaches the reversed-operand and set-membership shapes, not only a plain `==`.
    #[test]
    fn a_reversed_operand_and_a_set_membership_judge_the_host() {
        let reversed = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { "API.Example.com" == context.input.host };"#,
        );
        assert!(judge(&reversed, &Operator::unanchored()).is_err());

        let set = parsed(
            r#"forbid(principal, action in [Box::Action::"net:connect", Box::Action::"http:request"], resource)
            when { ["api.example.com", "API.Other.com"].contains(context.input.host) };"#,
        );
        assert!(judge(&set, &Operator::unanchored()).is_err());
    }

    /// Under an unconstrained action, `host` may be the argument of a generated MCP tool action
    /// rather than a destination, so no host literal is judged there.
    #[test]
    fn an_unconstrained_action_judges_no_host_literal() {
        for literal in [
            "API.Example.com",
            "PROD",
            "api.example.com:443",
            "bücher.example",
        ] {
            let broad = parsed(&format!(
                r#"forbid(principal, action, resource)
                when {{ context has input && context.input has host
                    && context.input.host == "{literal}" }};"#
            ));
            assert!(
                judge(&broad, &Operator::unanchored()).is_ok(),
                "{literal:?} may be a tool argument under an unconstrained action"
            );
        }

        let mixed = parsed(
            r#"forbid(principal, action in [Box::Action::"net:connect", Box::Action::"fs:read"], resource)
            when { context.input.host == "API.Example.com" };"#,
        );
        assert!(judge(&mixed, &Operator::unanchored()).is_ok());
    }

    /// A refusal never names a spelling that is itself unreachable, so the unreachable byte is
    /// reported before the case.
    #[test]
    fn a_host_refusal_names_no_second_dead_spelling() {
        let both = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { context.input.host like "API/path*" };"#,
        );
        let error = judge(&both, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(error.contains("a host holds no \"/\""), "{error}");
        assert!(!error.contains("write"), "{error}");

        let cased_only = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { context.input.host like "API.Example.com" };"#,
        );
        let error = judge(&cased_only, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(error.contains("write \"api.example.com\""), "{error}");
    }

    /// A literal and a pattern give one reason for a host that normalizes to nothing.
    #[test]
    fn a_host_that_normalizes_to_nothing_is_never_empty_in_both_shapes() {
        for source in [
            r#"when { context.input.host == ".." }"#,
            r#"when { context.input.host == "" }"#,
            r#"when { context.input.host like ".." }"#,
        ] {
            let policies = parsed(&format!(
                r#"forbid(principal, action == Box::Action::"net:connect", resource)
                {source};"#
            ));
            let error = judge(&policies, &Operator::unanchored())
                .unwrap_err()
                .to_string();
            assert!(error.contains("a host is never empty"), "{source}: {error}");
        }
    }
}
