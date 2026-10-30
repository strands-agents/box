//! Load-time judgement of the path, program, host, and address literals a rule compares.

use std::net::IpAddr;
use std::path::PathBuf;

use cedar_policy::{ActionConstraint, EntityUid, Policy, PolicySet};
use egress_gateway::{is_bindable_host, normalize_host};
use serde_json::Value;

use crate::PolicyError;
use crate::check::{Refused, RuleRef};
use crate::schema::action::{FS_OTHER, NET_CONNECT};
use crate::schema::attr::{HOST, IP4, IP6, PATH, PROGRAM, PROGRAM_PATH};

const BOX_ACTION_TYPE: &str = "Box::Action";

/// The address attribute [`IP4`] and [`IP6`] replace.
const REMOVED_IP: &str = "ip";

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

/// Refuse a rule that reads `context.input` and does not constrain its action to one family
/// (docs/design/decisions.md#a-rule-that-reads-the-input-names-one-action-family).
pub(crate) fn refuse_input_across_families(
    policies: &PolicySet,
    rule_of: &dyn Fn(&str) -> Option<RuleRef>,
) -> Result<(), Refused> {
    for policy in policies.policies() {
        let rule = rule_name(policy);
        let est = policy.to_json().map_err(|error| {
            PolicyError::Schema(format!("{rule} cannot be inspected at load: {error}"))
        })?;
        if let Some(text) = input_across_families(policy, &rule, &est["conditions"]) {
            let rules = rule_of(policy.id().as_ref()).into_iter().collect();
            return Err(Refused::new(
                PolicyError::InputAcrossFamilies(text.clone()),
                vec![crate::check::Finding::new(text).with_rules(rules)],
            ));
        }
    }
    Ok(())
}

/// Refuse a `net:connect` rule that reads `context.input.ip`, naming `ip4` and `ip6`.
pub(crate) fn refuse_removed_address_attribute(
    policies: &PolicySet,
    rule_of: &dyn Fn(&str) -> Option<RuleRef>,
) -> Result<(), Refused> {
    for policy in policies.policies() {
        if !names_only_connect(policy) {
            continue;
        }
        let rule = rule_name(policy);
        let est = policy.to_json().map_err(|error| {
            PolicyError::Schema(format!("{rule} cannot be inspected at load: {error}"))
        })?;
        if !reads_attribute(&est["conditions"], REMOVED_IP) {
            continue;
        }
        let text = format!(
            "{rule} reads context.input.{REMOVED_IP}, which a destination no longer carries; an \
             address reaches a rule as context.input.{IP4}, the IPv4 address it carries, and \
             context.input.{IP6}, the IPv6 form it arrived as, so write the one for the family the \
             rule means, and one clause for each family to cover both"
        );
        let rules = rule_of(policy.id().as_ref()).into_iter().collect();
        return Err(Refused::new(
            PolicyError::Schema(text.clone()),
            vec![crate::check::Finding::new(text).with_rules(rules)],
        ));
    }
    Ok(())
}

/// Whether every action in the rule's scope is `net:connect`, the one action an address reaches.
fn names_only_connect(policy: &Policy) -> bool {
    let uids = match policy.action_constraint() {
        ActionConstraint::Any => return false,
        ActionConstraint::Eq(uid) => vec![uid],
        ActionConstraint::In(uids) => uids,
    };
    !uids.is_empty()
        && uids.iter().all(|uid| {
            uid.type_name().to_string() == BOX_ACTION_TYPE && uid.id().escaped() == NET_CONNECT
        })
}

/// Whether `node` reads `context.input.<attribute>`, through `.` or through `has`.
fn reads_attribute(node: &Value, attribute: &str) -> bool {
    match node {
        Value::Array(items) => items.iter().any(|item| reads_attribute(item, attribute)),
        Value::Object(fields) => {
            for operator in [".", "has"] {
                if let Some(access) = fields.get(operator)
                    && access.get("left").is_some_and(is_context_input)
                    && access.get("attr").and_then(Value::as_str) == Some(attribute)
                {
                    return true;
                }
            }
            fields
                .values()
                .any(|value| reads_attribute(value, attribute))
        }
        _ => false,
    }
}

fn input_across_families(policy: &Policy, rule: &str, conditions: &Value) -> Option<String> {
    let read = input_read(conditions)?;
    let uids = match policy.action_constraint() {
        ActionConstraint::Any => {
            return Some(format!(
                "{rule} reads {read} and constrains no action, and an input attribute means what \
                 the action makes it mean; name the action the rule is for, or actions of one \
                 family, which share the prefix before \":\" as fs:read and fs:write do"
            ));
        }
        ActionConstraint::Eq(uid) => vec![uid],
        ActionConstraint::In(uids) => uids,
    };
    let mut families: Vec<(String, Vec<String>)> = Vec::new();
    for uid in &uids {
        let family = input_family(uid);
        match families.iter_mut().find(|(known, _)| *known == family) {
            Some((_, actions)) => actions.push(uid.to_string()),
            None => families.push((family, vec![uid.to_string()])),
        }
    }
    if families.len() < 2 {
        return None;
    }
    let scopes: Vec<String> = families
        .iter()
        .map(|(_, actions)| format!("[{}]", actions.join(", ")))
        .collect();
    Some(format!(
        "{rule} reads {read} under actions of more than one family, and an input attribute \
         means what the action makes it mean; write one rule for each family: {}",
        scopes.join(" and ")
    ))
}

/// The prefix before `:` of a `Box::Action`, or the whole action for any other.
fn input_family(uid: &EntityUid) -> String {
    let id = uid.id().escaped();
    if uid.type_name().to_string() == BOX_ACTION_TYPE
        && let Some((prefix, _)) = id.split_once(':')
    {
        return prefix.to_string();
    }
    uid.to_string()
}

/// The judged family a rule's scope names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Filesystem,
    Shell,
    Network,
}

/// Which judgements apply to one attribute under one scope.
#[derive(Debug, Clone, Copy)]
struct Checks {
    trailing_slash: bool,
}

impl Scope {
    /// The scope of `policy`, or `None` when it constrains no action, or names an action outside
    /// `Box::Action` or of no judged family.
    fn of(policy: &Policy) -> Option<Self> {
        let uids = match policy.action_constraint() {
            ActionConstraint::Any => return None,
            ActionConstraint::Eq(uid) => vec![uid],
            ActionConstraint::In(uids) => uids,
        };
        if uids
            .iter()
            .any(|uid| uid.type_name().to_string() != BOX_ACTION_TYPE)
        {
            return None;
        }
        let first = Self::family(uids.first()?)?;
        uids.iter()
            .all(|uid| Self::family(uid) == Some(first))
            .then_some(first)
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
            (Self::Network, HOST | IP4 | IP6) => Some(Checks {
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
    if attribute == IP4 || attribute == IP6 {
        return judge_address(attribute, &format!("\"{literal}\""), literal);
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
    if attribute == IP4 || attribute == IP6 {
        return match elements {
            [PatternElement::Literal(text)] => {
                judge_address(attribute, &format!("the pattern \"{pattern}\""), text)
            }
            _ => Finding::Sound,
        };
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

/// An address literal a pinned destination can equal under `attribute`, which it can only when
/// the literal is of that attribute's family and in that family's one spelling.
fn judge_address(attribute: &str, subject: &str, literal: &str) -> Finding {
    let Ok(address) = literal.parse::<IpAddr>() else {
        return Finding::Inert(format!(
            "compares context.input.{attribute} with {subject}, which no pinned destination \
             address can equal; {}",
            unpinnable_advice(attribute, literal)
        ));
    };
    let inert = |advice: String| {
        Finding::Inert(format!(
            "compares context.input.{attribute} with {subject}, {advice}"
        ))
    };
    match (attribute, address) {
        (IP4, IpAddr::V6(wire)) => match crate::address::embedded_v4(wire) {
            Some(embedded) => inert(format!(
                "and {IP4} holds the IPv4 address an IPv6 destination carries, as a dotted quad; \
                 write \"{embedded}\""
            )),
            None => inert(format!(
                "and {IP4} holds an IPv4 address; compare context.input.{IP6} to match this \
                 destination"
            )),
        },
        (IP6, IpAddr::V4(_)) => inert(format!(
            "and {IP6} holds the IPv6 form a destination arrived as, which an IPv4 destination has \
             none of; compare context.input.{IP4} to match this address"
        )),
        _ => match canonical_form(attribute, literal) {
            Some(canonical) if canonical != literal => {
                inert(spelling_advice(attribute, &canonical))
            }
            _ => Finding::Sound,
        },
    }
}

/// How `attribute` spells an address of its own family.
fn spelling_advice(attribute: &str, canonical: &str) -> String {
    if attribute == IP4 {
        format!("and an IPv4 address is spelled as a dotted quad; write \"{canonical}\"")
    } else {
        format!(
            "and an IPv6 address is spelled compressed and in lowercase, and an IPv4-mapped \
             address as \"::ffff:\" and a dotted quad; write \"{canonical}\""
        )
    }
}

/// Why no pinned address equals `literal` under `attribute`, which parses as no [`IpAddr`].
fn unpinnable_advice(attribute: &str, literal: &str) -> String {
    if literal.is_empty() {
        return "an address is never empty".to_string();
    }
    if let Some(address) = address_before_port(attribute, literal) {
        return format!(
            "an address carries no port; write \"{address}\" and compare context.input.port"
        );
    }
    if let Some(address) = bracketed(literal).and_then(|inner| canonical_form(attribute, inner)) {
        return format!("an address carries no brackets; write \"{address}\"");
    }
    let (family, other) = if attribute == IP4 {
        ("an IPv4 address is a dotted quad", IP6)
    } else {
        ("an IPv6 address is a hexadecimal form", IP4)
    };
    format!(
        "{family}; compare context.input.{other} to match the other family, or \
         context.input.{HOST} to pin a name"
    )
}

/// The canonical address of `attribute`'s family that `literal` holds before a numeric port
/// suffix, as `[v6]:port` or `v4:port`; a bare IPv6 prefix with one group too many reads as
/// neither.
fn address_before_port(attribute: &str, literal: &str) -> Option<String> {
    let (address, port) = literal.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match bracketed(address) {
        Some(inner) => canonical_form(attribute, inner),
        None if attribute == IP4 => canonical_form(IP4, address),
        None => None,
    }
}

/// What `literal` holds inside `[…]`.
fn bracketed(literal: &str) -> Option<&str> {
    literal.strip_prefix('[')?.strip_suffix(']')
}

/// How `attribute` spells `literal`, when `literal` is an address of `attribute`'s own family.
fn canonical_form(attribute: &str, literal: &str) -> Option<String> {
    match (attribute, literal.parse().ok()?) {
        (IP4, IpAddr::V4(address)) => crate::address::v4(IpAddr::V4(address)),
        (IP6, IpAddr::V6(address)) => crate::address::v6(IpAddr::V6(address)),
        _ => None,
    }
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

/// `path`, `program_path`, `program`, `host`, `ip4`, or `ip6` when `node` is
/// `context.input.<that>`.
fn input_attribute(node: &Value) -> Option<String> {
    let access = node.get(".")?;
    let attribute = access.get("attr")?.as_str()?;
    if ![PATH, PROGRAM_PATH, PROGRAM, HOST, IP4, IP6].contains(&attribute) {
        return None;
    }
    is_context_input(access.get("left")?).then(|| attribute.to_string())
}

/// The first read of `context.input` in `node`: `context.input.<attribute>` when it names one.
fn input_read(node: &Value) -> Option<String> {
    match node {
        Value::Array(items) => items.iter().find_map(input_read),
        Value::Object(fields) => {
            for operator in [".", "has"] {
                if let Some(access) = fields.get(operator)
                    && access.get("left").is_some_and(is_context_input)
                    && let Some(attribute) = access.get("attr").and_then(Value::as_str)
                {
                    return Some(format!("context.input.{attribute}"));
                }
            }
            if is_context_input(node) {
                return Some("context.input".to_string());
            }
            fields.values().find_map(input_read)
        }
        _ => None,
    }
}

fn is_context_input(node: &Value) -> bool {
    node.get(".").is_some_and(|access| {
        access.get("attr").and_then(Value::as_str) == Some("input")
            && access
                .get("left")
                .and_then(|left| left.get("Var"))
                .and_then(Value::as_str)
                == Some("context")
    })
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

    /// The scope refusal, the removed-attribute refusal, then the spelling judge, in load order.
    fn judge(policies: &PolicySet, operator: &Operator) -> Result<Vec<PolicyWarning>, PolicyError> {
        refuse_input_across_families(policies, &|_| None).map_err(Refused::into_error)?;
        refuse_removed_address_attribute(policies, &|_| None).map_err(Refused::into_error)?;
        super::judge(policies, operator)
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
    fn an_input_read_under_no_action_is_refused_and_names_the_actions_to_write() {
        for read in [
            r#"context.input.path == "/etc/hosts""#,
            r#"context.input.program == "git""#,
            r#"context.input.program_path == "/usr/bin/git""#,
            r#"context.input.host == "api.example.com""#,
            r#"context.input.server == "demo""#,
            r#"context.input.operation == Box::FsReadOperation::"read_content""#,
            "context has input && context.input has path",
        ] {
            let policies = parsed(&format!(
                r#"@id("broad") forbid(principal, action, resource) when {{ {read} }};"#
            ));
            let error = judge(&policies, &anchored()).unwrap_err().to_string();
            assert!(
                error.contains("rule @id(\"broad\") reads context.input."),
                "{read}: {error}"
            );
            assert!(error.contains("constrains no action"), "{read}: {error}");
            assert!(
                error.contains("name the action the rule is for"),
                "{read}: {error}"
            );
        }
    }

    #[test]
    fn an_input_read_across_families_is_refused_whatever_the_order() {
        for actions in [
            r#"Box::Action::"fs:read", Box::Action::"http:request""#,
            r#"Box::Action::"http:request", Box::Action::"fs:read""#,
            r#"Box::Action::"net:connect", Box::Action::"http:request""#,
            r#"Box::Action::"fs:read", Box::Action::"mcp:call""#,
            r#"Box::Action::"mcp:call", Box::Action::"fs:read""#,
            r#"Box::Action::"shell:spawn", Box::Action::"fs:read""#,
        ] {
            let policies = parsed(&format!(
                r#"permit(principal, action in [{actions}], resource)
                when {{ context.input has path }};"#
            ));
            let error = judge(&policies, &anchored()).unwrap_err().to_string();
            assert!(
                error.contains("reads context.input.path under actions of more than one family"),
                "{actions}: {error}"
            );
        }

        let grouped = parsed(
            r#"permit(principal, action in [Box::Action::"fs:read", Box::Action::"net:connect", Box::Action::"fs:write"], resource)
            when { context.input.path == "/v1/" };"#,
        );
        let error = judge(&grouped, &anchored()).unwrap_err().to_string();
        assert!(
            error.ends_with(
                r#"write one rule for each family: [Box::Action::"fs:read", Box::Action::"fs:write"] and [Box::Action::"net:connect"]"#
            ),
            "{error}"
        );
    }

    #[test]
    fn a_rule_that_reads_no_input_or_names_one_family_loads() {
        for source in [
            "permit(principal, action, resource);",
            "forbid(principal, action, resource);",
            r#"permit(principal, action in [Box::Action::"fs:read", Box::Action::"net:connect"], resource);"#,
            r#"forbid(principal, action, resource) when { context has input };"#,
            r#"permit(principal, action in [Box::Action::"fs:read", Box::Action::"fs:write", Box::Action::"fs:other"], resource)
               when { context.input.path == "/etc/hosts" };"#,
            r#"permit(principal, action in [Box::Action::"shell:exec", Box::Action::"shell:spawn"], resource)
               when { context.input.program == "git" };"#,
            r#"permit(principal, action == Box::Action::"mcp:call", resource)
               when { context.input.server == "demo" };"#,
        ] {
            assert!(judge(&parsed(source), &anchored()).is_ok(), "{source}");
        }
    }

    /// A URL path is not judged as a filesystem path.
    #[test]
    fn a_network_scope_does_not_judge_a_url_path() {
        let url = parsed(
            r#"permit(principal, action == Box::Action::"http:request", resource)
            when { context.input.path == "/v1/models/" || context.input.path == "/Users/me/api" };"#,
        );
        assert!(judge(&url, &anchored()).is_ok());
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
        let error = judge(&mixed, &anchored()).unwrap_err().to_string();
        assert!(error.contains("more than one family"), "{error}");
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
            r#"forbid(principal, action == Box::Action::"http:request", resource)
            when { ["api.example.com", "API.Other.com"].contains(context.input.host) };"#,
        );
        assert!(judge(&set, &Operator::unanchored()).is_err());
    }

    /// A host literal is judged only as a destination, so a rule that does not name its action
    /// is refused for the scope and is never told to respell a tool argument.
    #[test]
    fn a_host_literal_under_no_action_is_refused_for_its_scope_and_not_its_spelling() {
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
            let error = judge(&broad, &Operator::unanchored())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("constrains no action"),
                "{literal:?}: {error}"
            );
            assert!(!error.contains("lowercase"), "{literal:?}: {error}");

            let tool = parsed(&format!(
                r#"forbid(principal, action == alpha::Action::"deploy", resource)
                when {{ context.input.host == "{literal}" }};"#
            ));
            assert!(
                judge(&tool, &Operator::unanchored()).is_ok(),
                "{literal:?} is a tool argument under a tool action"
            );
        }

        let mixed = parsed(
            r#"forbid(principal, action in [Box::Action::"net:connect", Box::Action::"fs:read"], resource)
            when { context.input.host == "API.Example.com" };"#,
        );
        let error = judge(&mixed, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(error.contains("more than one family"), "{error}");
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

    /// An IPv6 literal under `ip4` is refused with the IPv4 address that IPv6 form carries.
    #[test]
    fn an_ipv6_literal_under_ip4_is_refused_with_the_address_it_carries() {
        for literal in [
            "::ffff:169.254.169.254",
            "::ffff:a9fe:a9fe",
            "::169.254.169.254",
            "2002:a9fe:a9fe::",
            "2001:0:0:0:0:0:5601:5601",
            "64:ff9b::169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "::ffff:0:a9fe:a9fe",
        ] {
            let policies = parsed(&format!(
                r#"@id("block_address")
                forbid(principal, action == Box::Action::"net:connect", resource)
                when {{ context.input has ip4 && context.input.ip4 == "{literal}" }};"#
            ));
            let error = judge(&policies, &Operator::unanchored())
                .unwrap_err()
                .to_string();
            assert!(error.contains("rule @id(\"block_address\")"), "{error}");
            assert!(
                error.contains("write \"169.254.169.254\""),
                "{literal}: {error}"
            );
        }
    }

    /// An IPv6 literal that carries no IPv4 address is refused under `ip4` and names `ip6`.
    #[test]
    fn an_ipv6_literal_that_carries_no_address_under_ip4_names_ip6() {
        for literal in [
            "fd00:ec2::254",
            "2001:db8::1",
            "::1",
            "64:ff9b:1::a9fe:a9fe",
        ] {
            let policies = parsed(&format!(
                r#"forbid(principal, action == Box::Action::"net:connect", resource)
                when {{ context.input has ip4 && context.input.ip4 == "{literal}" }};"#
            ));
            let error = judge(&policies, &Operator::unanchored())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("compare context.input.ip6"),
                "{literal}: {error}"
            );
            assert!(!error.contains("write \""), "{literal}: {error}");
        }
    }

    /// `ip6` holds the form a destination arrived as, and an IPv4 destination has none. No IPv6
    /// form is computed for one, so the refusal names `ip4` and no spelling to write.
    #[test]
    fn an_ipv4_literal_under_ip6_is_refused_and_names_ip4() {
        for literal in ["169.254.169.254", "127.0.0.1", "203.0.113.7"] {
            let policies = parsed(&format!(
                r#"forbid(principal, action == Box::Action::"net:connect", resource)
                when {{ context.input has ip6 && context.input.ip6 == "{literal}" }};"#
            ));
            let error = judge(&policies, &Operator::unanchored())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("compare context.input.ip4"),
                "{literal}: {error}"
            );
            assert!(!error.contains("write \""), "{literal}: {error}");
        }
    }

    /// An IPv6 literal under `ip6` is refused when it is not the compressed lowercase form, or
    /// not the mixed form a wrapped IPv4 address arrives as.
    #[test]
    fn an_uncompressed_ipv6_literal_under_ip6_is_refused_with_its_wire_form() {
        for (literal, canonical) in [
            ("FD00:00EC:0000:0000:0000:0000:0000:0254", "fd00:ec::254"),
            ("FE80::1", "fe80::1"),
            ("::ffff:a9fe:a9fe", "::ffff:169.254.169.254"),
            ("2001:0:0:0:0:0:5601:5601", "2001::5601:5601"),
            ("64:ff9b::169.254.169.254", "64:ff9b::a9fe:a9fe"),
        ] {
            let policies = parsed(&format!(
                r#"forbid(principal, action == Box::Action::"net:connect", resource)
                when {{ context.input has ip6 && context.input.ip6 == "{literal}" }};"#
            ));
            let error = judge(&policies, &Operator::unanchored())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!("write \"{canonical}\"")),
                "{literal}: {error}"
            );
        }
    }

    /// Every spelling each attribute reads must load, so the judge refuses nothing an operator
    /// needs.
    #[test]
    fn a_canonical_address_literal_is_sound_under_its_own_attribute() {
        for (attribute, literal) in [
            (IP4, "169.254.169.254"),
            (IP4, "127.0.0.1"),
            (IP4, "0.0.0.0"),
            (IP6, "fd00:ec2::254"),
            (IP6, "2001:db8::1"),
            (IP6, "::"),
            (IP6, "::1"),
            (IP6, "64:ff9b::a9fe:a9fe"),
            (IP6, "64:ff9c::a9fe:a9fe"),
            (IP6, "64:ff9b:1::a9fe:a9fe"),
            (IP6, "::ffff:169.254.169.254"),
        ] {
            let policies = parsed(&format!(
                r#"forbid(principal, action == Box::Action::"net:connect", resource)
                when {{ context.input has {attribute}
                    && context.input.{attribute} == "{literal}" }};"#
            ));
            assert!(
                judge(&policies, &Operator::unanchored()).is_ok(),
                "{literal:?} is a spelling {attribute} reads and must load"
            );
        }
    }

    #[test]
    fn an_address_literal_that_no_pinned_address_can_equal_is_refused() {
        for (attribute, literal, advice) in [
            (IP4, "169.254.169.254:80", "write \"169.254.169.254\""),
            (IP6, "[2001:db8::1]:443", "write \"2001:db8::1\""),
            (IP6, "[2001:db8::1]", "carries no brackets"),
            (IP4, "", "an address is never empty"),
            (IP6, "", "an address is never empty"),
            (
                IP4,
                "169.254.169.254/32",
                "an IPv4 address is a dotted quad",
            ),
            (IP4, "metadata.example", "an IPv4 address is a dotted quad"),
            (IP6, "metadata.example", "an IPv6 address is a hexadecimal"),
            // One group too many splits like a port, and names no port in the advice.
            (
                IP6,
                "2001:db8::1:2:3:4:5:6",
                "an IPv6 address is a hexadecimal",
            ),
            (IP6, "fe80::1%eth0", "an IPv6 address is a hexadecimal"),
            // A port on the other family's spelling never names that spelling back.
            (IP4, "[2001:db8::1]:443", "an IPv4 address is a dotted quad"),
            (
                IP6,
                "169.254.169.254:80",
                "an IPv6 address is a hexadecimal",
            ),
        ] {
            let policies = parsed(&format!(
                r#"forbid(principal, action == Box::Action::"net:connect", resource)
                when {{ context.input has {attribute}
                    && context.input.{attribute} == "{literal}" }};"#
            ));
            let error = judge(&policies, &Operator::unanchored())
                .unwrap_err()
                .to_string();
            assert!(error.contains(advice), "{attribute} {literal:?}: {error}");
        }
    }

    /// A pattern with a wildcard is judged by nothing, because an address a wildcard admits
    /// cannot be enumerated; a pattern with none is judged as the literal it is.
    #[test]
    fn an_address_pattern_is_judged_only_when_it_holds_no_wildcard() {
        let wildcards = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { (context.input has ip4 && context.input.ip4 like "169.254.*")
                   || (context.input has ip6 && (context.input.ip6 like "64:ff9b::*"
                   || context.input.ip6 like "fe8*")) };"#,
        );
        assert!(
            judge(&wildcards, &Operator::unanchored())
                .expect("a pattern loads")
                .is_empty()
        );

        let exact = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { context.input has ip4 && context.input.ip4 like "64:ff9b::a9fe:a9fe" };"#,
        );
        let error = judge(&exact, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("the pattern \"64:ff9b::a9fe:a9fe\""),
            "{error}"
        );
        assert!(error.contains("write \"169.254.169.254\""), "{error}");
    }

    /// An address literal is judged only as a pinned destination, so a rule outside `net:*`
    /// keeps it and a rule that names no action is refused for its scope.
    #[test]
    fn an_address_literal_under_no_action_is_refused_for_its_scope_and_not_its_spelling() {
        let broad = parsed(
            r#"forbid(principal, action, resource)
            when { context has input && context.input has ip4
                && context.input.ip4 == "64:ff9b::a9fe:a9fe" };"#,
        );
        let error = judge(&broad, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(error.contains("constrains no action"), "{error}");
        assert!(!error.contains("write \"169.254.169.254\""), "{error}");

        let tool = parsed(
            r#"forbid(principal, action == alpha::Action::"deploy", resource)
            when { context.input.ip4 == "64:ff9b::a9fe:a9fe" };"#,
        );
        assert!(
            judge(&tool, &Operator::unanchored()).is_ok(),
            "an address under a tool action is a tool argument"
        );

        let pinned = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { context.input.ip4 == "64:ff9b::a9fe:a9fe" };"#,
        );
        let error = judge(&pinned, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("write \"169.254.169.254\""),
            "the same literal under net:connect is a pinned address: {error}"
        );
    }

    /// The address arm reaches the reversed-operand and set-membership shapes.
    #[test]
    fn a_reversed_operand_and_a_set_membership_judge_the_address() {
        let reversed = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { "::ffff:a9fe:a9fe" == context.input.ip4 };"#,
        );
        assert!(judge(&reversed, &Operator::unanchored()).is_err());

        let set = parsed(
            r#"forbid(principal, action == Box::Action::"net:connect", resource)
            when { ["169.254.169.254", "64:ff9b::a9fe:a9fe"].contains(context.input.ip4) };"#,
        );
        assert!(judge(&set, &Operator::unanchored()).is_err());
    }

    /// A network rule that names the removed `ip` is refused, and the refusal names both
    /// attributes that replace it.
    #[test]
    fn the_removed_ip_attribute_is_refused_and_names_ip4_and_ip6() {
        for condition in [
            r#"context.input has ip && context.input.ip == "169.254.169.254""#,
            r#"context.input.ip like "169.254.*""#,
            r#""169.254.169.254" == context.input.ip"#,
            r#"["169.254.169.254"].contains(context.input.ip)"#,
            "context.input has ip",
        ] {
            let policies = parsed(&format!(
                r#"@id("legacy")
                forbid(principal, action == Box::Action::"net:connect", resource)
                when {{ {condition} }};"#
            ));
            let error = judge(&policies, &Operator::unanchored())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("rule @id(\"legacy\")"),
                "{condition}: {error}"
            );
            assert!(
                error.contains("reads context.input.ip, which a destination no longer carries"),
                "{condition}: {error}"
            );
            assert!(
                error.contains("context.input.ip4") && error.contains("context.input.ip6"),
                "{condition}: {error}"
            );
        }
    }

    /// `ip` is refused only as a destination address. A tool action's own `ip` argument is not a
    /// destination, and a rule that names no action is refused for its scope first.
    #[test]
    fn the_removed_ip_attribute_is_refused_only_under_a_network_action() {
        let tool = parsed(
            r#"forbid(principal, action == alpha::Action::"deploy", resource)
            when { context.input.ip == "169.254.169.254" };"#,
        );
        assert!(
            judge(&tool, &Operator::unanchored()).is_ok(),
            "an ip under a tool action is a tool argument"
        );

        let broad = parsed(
            r#"forbid(principal, action, resource)
            when { context has input && context.input has ip };"#,
        );
        let error = judge(&broad, &Operator::unanchored())
            .unwrap_err()
            .to_string();
        assert!(error.contains("constrains no action"), "{error}");
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
