// SPDX-License-Identifier: Apache-2.0
// The temporal rendering routines are adapted from dogwood-language 1.0.0,
// src/render.rs:355–569, published under Apache-2.0:
// https://github.com/dogwood-policy/dogwood/blob/996d756de1013b7ae209a14f566a80375a59f2f0/dogwood-language/src/render.rs
// Changes: use the public 1.1.2 AST, return errors for unsupported nodes, and
// check binding capture separately. The surrounding policy text is rendered
// by the current library. This is not a general legacy parser or renderer.

use super::MigrationError;
use super::source::temporal_ranges;
use dogwood_language::{ParsedPolicy, temporal_ast as ast};

/// The exact older spelling predicted from a trusted, pre-upgrade authored rule.
/// This is only for explicit migration. Never use it to match ordinary edits.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LegacyForm {
    pub(crate) statement: String,
}

/// Preserve lexical bindings while predicting 1.0.0 generated-name spelling.
/// The explicit migration compares this single predicted spelling with stored rules.
/// Unsupported or capturing projections refuse; they never authorize replacement.
pub(crate) fn legacy_form(policy: &ParsedPolicy<'_>) -> Result<Option<LegacyForm>, MigrationError> {
    validate_policy(policy)?;
    let conditions: Vec<_> = policy.temporal_conditions().collect();
    if !conditions
        .iter()
        .any(|condition| contains_generated(condition))
    {
        return Ok(None);
    }
    let canonical = policy.expanded_source();
    let bodies = conditions
        .iter()
        .map(|condition| render_condition(condition))
        .collect::<Result<Vec<_>, _>>()
        .map_err(MigrationError::unsupported)?;
    let ranges = temporal_ranges(&canonical)?;
    if ranges.len() != bodies.len() {
        return Err(MigrationError::unsupported(
            "temporal occurrence count changed",
        ));
    }
    let mut statement = String::with_capacity(canonical.len());
    let mut cursor = 0;
    for ((start, end), body) in ranges.into_iter().zip(bodies) {
        statement.push_str(&canonical[cursor..start]);
        statement.push(' ');
        statement.push_str(&body);
        statement.push(' ');
        cursor = end;
    }
    statement.push_str(&canonical[cursor..]);
    if statement == canonical {
        return Ok(None);
    }
    Ok(Some(LegacyForm { statement }))
}

pub(super) fn validate_policy(policy: &ParsedPolicy<'_>) -> Result<(), MigrationError> {
    if policy.uses_providers() {
        return Err(MigrationError::unsupported(
            "information-provider rules are outside the migration subset",
        ));
    }
    for condition in policy.temporal_conditions() {
        validate_condition(condition)?;
    }
    Ok(())
}

fn validate_condition(condition: &ast::Condition) -> Result<(), MigrationError> {
    check_condition(&Vec::new(), condition)
}

// No alpha-equivalence: the only changed names contain the compiler's '$'.
fn legacy_name(name: &str) -> String {
    name.replace('$', "_")
}
fn generated_slot(slot: &ast::BinderSlot) -> bool {
    matches!(slot, ast::BinderSlot::Name(name) if name.contains('$'))
}
fn generated_term(term: &ast::Term) -> bool {
    use ast::Term as T;
    match term {
        T::Var(name) => name.contains('$'),
        T::Array(items) => items.iter().any(generated_term),
        T::Agg(aggregate) => match &aggregate.kind {
            ast::AggExprKind::Sum {
                bound_var,
                for_vars,
                body,
            } => {
                generated_slot(bound_var)
                    || for_vars.iter().any(|v| generated_slot(&v.slot))
                    || contains_generated(body)
            }
            ast::AggExprKind::Count { for_vars, body } => {
                for_vars.iter().any(|v| generated_slot(&v.slot)) || contains_generated(body)
            }
            ast::AggExprKind::Call(_) => false,
        },
        T::Arith { left, right, .. } => generated_term(left) || generated_term(right),
        T::Entity { .. }
        | T::Integer(_)
        | T::Decimal(_)
        | T::String(_)
        | T::Bool(_)
        | T::ContextField(_)
        | T::ScopeField(_)
        | T::Wildcard
        | T::ParamRef(_)
        | T::BinderRef(_) => false,
    }
}
fn contains_generated(condition: &ast::Condition) -> bool {
    use ast::ConditionKind as C;
    match &condition.kind {
        C::And { left, right } | C::Or { left, right } | C::Since { left, right, .. } => {
            contains_generated(left) || contains_generated(right)
        }
        C::Not { inner } => contains_generated(inner),
        C::Formerly { body, .. } | C::Previous { body, .. } => contains_generated(body),
        C::Predicate(predicate) => predicate.args.iter().any(|a| generated_term(&a.value)),
        C::Comparison { left, right, .. } => generated_term(left) || generated_term(right),
        C::Exists { var, body } => generated_slot(&var.slot) || contains_generated(body),
        C::Tp { var } => generated_slot(var),
        C::Call(_) | C::SigilRef { .. } | C::Refine { .. } => false,
    }
}

// The two names at each declaration position describe one lexical binder.
// Conservative rejection is intentional when distinct active raw names project
// to the same old spelling, even if the problematic reference is unused.
type Environment = Vec<(String, String)>;
fn declare(environment: &mut Environment, slot: &ast::BinderSlot) -> Result<(), MigrationError> {
    let ast::BinderSlot::Name(raw) = slot else {
        return Err(MigrationError::unsupported("unexpanded temporal binder"));
    };
    let legacy = legacy_name(raw);
    if environment
        .iter()
        .any(|(name, old)| old == &legacy && name != raw)
    {
        return Err(MigrationError::capture(format!(
            "legacy spelling {legacy} aliases a different active binder"
        )));
    }
    environment.push((raw.clone(), legacy));
    Ok(())
}
fn check_variable(environment: &Environment, raw: &str) -> Result<(), MigrationError> {
    let legacy = legacy_name(raw);
    let current = environment.iter().rposition(|(name, _)| name == raw);
    let previous = environment.iter().rposition(|(_, name)| name == &legacy);
    if current != previous || (raw.contains('$') && current.is_none()) {
        return Err(MigrationError::capture(format!(
            "legacy spelling changes the binding of {raw}"
        )));
    }
    Ok(())
}
fn check_slot(environment: &Environment, slot: &ast::BinderSlot) -> Result<(), MigrationError> {
    match slot {
        ast::BinderSlot::Name(name) => check_variable(environment, name),
        _ => Err(MigrationError::unsupported(
            "unexpanded temporal binder reference",
        )),
    }
}
fn check_term(environment: &Environment, term: &ast::Term) -> Result<(), MigrationError> {
    use ast::Term as T;
    match term {
        T::Var(name) => check_variable(environment, name),
        T::Array(items) => items
            .iter()
            .try_for_each(|item| check_term(environment, item)),
        T::Agg(aggregate) => {
            let mut local = environment.clone();
            match &aggregate.kind {
                ast::AggExprKind::Sum {
                    bound_var,
                    for_vars,
                    body,
                } => {
                    for var in for_vars {
                        declare(&mut local, &var.slot)?;
                    }
                    check_slot(&local, bound_var)?;
                    check_condition(&local, body)
                }
                ast::AggExprKind::Count { for_vars, body } => {
                    for var in for_vars {
                        declare(&mut local, &var.slot)?;
                    }
                    check_condition(&local, body)
                }
                ast::AggExprKind::Call(_) => Err(MigrationError::unsupported(
                    "unexpanded temporal aggregation",
                )),
            }
        }
        T::Arith { .. } | T::ParamRef(_) | T::BinderRef(_) => Err(MigrationError::unsupported(
            "unsupported legacy temporal term",
        )),
        T::Entity { .. }
        | T::Integer(_)
        | T::Decimal(_)
        | T::String(_)
        | T::Bool(_)
        | T::ContextField(_)
        | T::ScopeField(_)
        | T::Wildcard => Ok(()),
    }
}
fn check_condition(
    environment: &Environment,
    condition: &ast::Condition,
) -> Result<(), MigrationError> {
    use ast::ConditionKind as C;
    match &condition.kind {
        C::And { left, right } => {
            check_condition(environment, left)?;
            check_condition(environment, right)
        }
        C::Since {
            left,
            within,
            right,
        } => {
            render_within(within).map_err(MigrationError::unsupported)?;
            check_condition(environment, left)?;
            check_condition(environment, right)
        }
        C::Not { inner } => check_condition(environment, inner),
        C::Formerly { within, body } | C::Previous { within, body } => {
            render_within(within).map_err(MigrationError::unsupported)?;
            check_condition(environment, body)
        }
        C::Predicate(predicate) => predicate
            .args
            .iter()
            .try_for_each(|a| check_term(environment, &a.value)),
        C::Comparison { left, right, .. } => {
            check_term(environment, left)?;
            check_term(environment, right)
        }
        C::Exists { var, body } => {
            let mut local = environment.clone();
            declare(&mut local, &var.slot)?;
            check_condition(&local, body)
        }
        C::Tp { var } => check_slot(environment, var),
        C::Or { .. } | C::Call(_) | C::SigilRef { .. } | C::Refine { .. } => Err(
            MigrationError::unsupported("unsupported legacy temporal condition"),
        ),
    }
}

fn render_condition(condition: &ast::Condition) -> Result<String, String> {
    use ast::ConditionKind as C;
    Ok(match &condition.kind {
        C::And { left, right } => format!("{} && {}", group(left)?, group(right)?),
        C::Not { inner } => format!("!{}", group(inner)?),
        C::Formerly { within, body } => format!(
            "formerly within {} {}",
            render_within(within)?,
            group(body)?
        ),
        C::Previous { within, body } => format!(
            "previous within {} {}",
            render_within(within)?,
            group(body)?
        ),
        C::Since {
            left,
            within,
            right,
        } => format!(
            "{} since within {} {}",
            group(left)?,
            render_within(within)?,
            group(right)?
        ),
        C::Predicate(predicate) => render_predicate(predicate)?,
        C::Comparison { op, left, right } => format!(
            "{} {} {}",
            render_term(left)?,
            comparison(*op),
            render_term(right)?
        ),
        C::Exists { var, body } => format!(
            "exists ({}: {}). {}",
            render_slot(&var.slot)?,
            var.ty.render(),
            group(body)?
        ),
        C::Tp { var } => format!("tp({})", render_slot(var)?),
        C::Or { .. } | C::Call(_) | C::SigilRef { .. } | C::Refine { .. } => {
            return Err("unsupported legacy temporal condition".into());
        }
    })
}
fn group(condition: &ast::Condition) -> Result<String, String> {
    Ok(format!("({})", render_condition(condition)?))
}
fn render_within(within: &ast::WithinSpec) -> Result<String, String> {
    match within {
        ast::WithinSpec::Concrete(interval) => Ok(interval.render()),
        _ => Err("unexpanded temporal window".into()),
    }
}
fn render_predicate(predicate: &ast::Predicate) -> Result<String, String> {
    let head = format!(
        "{}::{}::{}",
        predicate.namespace.join("::"),
        quote(&predicate.action),
        predicate.kind
    );
    if predicate.args.is_empty() {
        return Ok(format!("{head}{{}}"));
    }
    let args = predicate
        .args
        .iter()
        .map(|arg| Ok(format!("{}: {}", arg.name, render_term(&arg.value)?)))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(format!("{head}{{ {} }}", args.join(", ")))
}
fn render_term(term: &ast::Term) -> Result<String, String> {
    use ast::Term as T;
    Ok(match term {
        T::Entity { ty, id } => format!("{ty}::{}", quote(id)),
        T::Integer(value) => value.to_string(),
        T::Decimal(value) => format!("decimal({})", quote(value)),
        T::String(value) => quote(value),
        T::Bool(value) => value.to_string(),
        T::ContextField(path) => format!("context.{}", path.join(".")),
        T::ScopeField(path) => path.join("."),
        T::Var(name) => legacy_name(name),
        T::Wildcard => "*".into(),
        T::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(render_term)
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        ),
        T::Agg(aggregate) => render_aggregate(aggregate)?,
        T::Arith { .. } | T::ParamRef(_) | T::BinderRef(_) => {
            return Err("unsupported legacy temporal term".into());
        }
    })
}
fn render_aggregate(aggregate: &ast::AggExpr) -> Result<String, String> {
    match &aggregate.kind {
        ast::AggExprKind::Sum {
            bound_var,
            for_vars,
            body,
        } => Ok(format!(
            "sum {} for {}. where {}",
            render_slot(bound_var)?,
            render_for_vars(for_vars)?,
            group(body)?
        )),
        ast::AggExprKind::Count { for_vars, body } => Ok(format!(
            "count for {}. where {}",
            render_for_vars(for_vars)?,
            group(body)?
        )),
        ast::AggExprKind::Call(_) => Err("unexpanded temporal aggregation".into()),
    }
}
fn render_for_vars(vars: &[ast::TypedBinder]) -> Result<String, String> {
    Ok(vars
        .iter()
        .map(|var| {
            Ok(format!(
                "({}: {})",
                render_slot(&var.slot)?,
                var.ty.render()
            ))
        })
        .collect::<Result<Vec<_>, String>>()?
        .join(", "))
}
fn render_slot(slot: &ast::BinderSlot) -> Result<String, String> {
    match slot {
        ast::BinderSlot::Name(name) => Ok(legacy_name(name)),
        _ => Err("unexpanded temporal binder".into()),
    }
}
fn comparison(op: ast::CmpOp) -> &'static str {
    match op {
        ast::CmpOp::Le => "<=",
        ast::CmpOp::Lt => "<",
        ast::CmpOp::Ge => ">=",
        ast::CmpOp::Gt => ">",
        ast::CmpOp::Eq => "==",
        ast::CmpOp::NotEq => "!=",
    }
}
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod guard_tests {
    use super::super::MigrationErrorKind;
    use super::*;
    use dogwood_language::{ParsedPolicySet, ServiceSchema};

    fn condition() -> ast::Condition {
        let service = ServiceSchema::builder()
            .event_schema_str(include_str!("fixtures/events.dwschema"))
            .build()
            .unwrap();
        let parsed =
            ParsedPolicySet::parse(include_str!("fixtures/collision.dw"), &service).unwrap();
        parsed
            .policies()
            .next()
            .unwrap()
            .temporal_conditions()
            .next()
            .unwrap()
            .clone()
    }

    #[test]
    fn unsupported_conditions_return_errors_without_panics() {
        let base = condition();
        let mut unsupported = base.clone();
        unsupported.kind = ast::ConditionKind::Or {
            left: Box::new(base.clone()),
            right: Box::new(base.clone()),
        };
        assert_eq!(
            validate_condition(&unsupported).unwrap_err().kind,
            MigrationErrorKind::UnsupportedSyntax
        );
        unsupported.kind = ast::ConditionKind::Comparison {
            op: ast::CmpOp::Eq,
            left: ast::Term::ParamRef("unexpanded".into()),
            right: ast::Term::Integer(1),
        };
        assert_eq!(
            validate_condition(&unsupported).unwrap_err().kind,
            MigrationErrorKind::UnsupportedSyntax
        );
        unsupported.kind = ast::ConditionKind::Comparison {
            op: ast::CmpOp::Eq,
            left: ast::Term::Arith {
                op: ast::ArithOp::Add,
                left: Box::new(ast::Term::Integer(1)),
                right: Box::new(ast::Term::Integer(2)),
            },
            right: ast::Term::Integer(3),
        };
        assert_eq!(
            validate_condition(&unsupported).unwrap_err().kind,
            MigrationErrorKind::UnsupportedSyntax
        );
        unsupported.kind = ast::ConditionKind::Tp {
            var: ast::BinderSlot::BinderRef("unexpanded".into()),
        };
        assert_eq!(
            validate_condition(&unsupported).unwrap_err().kind,
            MigrationErrorKind::UnsupportedSyntax
        );
    }

    #[test]
    fn unexpanded_windows_refuse_even_without_generated_names() {
        let mut node = condition();
        let mut leaf = node.clone();
        leaf.kind = ast::ConditionKind::Comparison {
            op: ast::CmpOp::Eq,
            left: ast::Term::Integer(1),
            right: ast::Term::Integer(1),
        };
        node.kind = ast::ConditionKind::Formerly {
            within: ast::WithinSpec::ParamRef("window".into()),
            body: Box::new(leaf),
        };
        assert_eq!(
            validate_condition(&node).unwrap_err().kind,
            MigrationErrorKind::UnsupportedSyntax
        );
    }

    #[test]
    fn free_references_cannot_be_captured_by_projected_generated_names() {
        let environment = vec![("t$33".to_owned(), "t_33".to_owned())];
        assert!(check_variable(&environment, "t_33").is_err());
        assert!(check_variable(&Vec::new(), "t$33").is_err());
        assert!(check_variable(&environment, "t$33").is_ok());
        // An unrelated free authored reference is unchanged by this projection.
        assert!(check_variable(&environment, "unrelated").is_ok());
    }

    #[test]
    fn strings_and_field_paths_are_never_binder_renames() {
        let literal = ast::Term::String("t$33 has \"x\".y temporal { }".into());
        let rendered = render_term(&literal).unwrap();
        assert!(rendered.contains("t$33"));
        assert!(!rendered.contains("t_33"));
        assert_eq!(
            render_term(&ast::Term::ContextField(vec!["t$33".into()])).unwrap(),
            "context.t$33"
        );
        assert_eq!(render_term(&ast::Term::Var("t$33".into())).unwrap(), "t_33");
    }
}
