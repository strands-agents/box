use std::fmt;

use super::{Decision, DenyReason, PolicyAttribution};

const MESSAGE_LIMIT: usize = 4096;
const RESOURCE_LIMIT: usize = 1024;
const TRUNCATED: &str = "...";

impl fmt::Display for Decision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut message = String::new();
        if describe(self, &mut message).is_none() {
            message.push_str(TRUNCATED);
        }
        formatter.write_str(&message)
    }
}

fn describe(decision: &Decision, message: &mut String) -> Option<()> {
    let (verb, resource) = match decision {
        Decision::Allow { resource, .. } => ("permitted", resource),
        Decision::Deny { resource, .. } => ("denied", resource),
    };
    append(message, "policy ")?;
    append(message, verb)?;
    append(message, " this operation")?;
    if let Some(resource) = nonblank(Some(resource)) {
        append(message, " on ")?;
        append_resource(message, resource)?;
    }

    let Decision::Deny {
        reason,
        rule,
        attribution,
        ..
    } = decision
    else {
        return append(message, ".");
    };

    match reason {
        DenyReason::NoMatch => append(
            message,
            " [default-deny]: No permit policy matched this request.",
        ),
        DenyReason::InternalFault => {
            append(message, " because the request could not be evaluated.")
        }
        DenyReason::PolicyPending => append(
            message,
            " [policy-pending]: The complete policy bundle is not installed.",
        ),
        DenyReason::Forbidden => {
            let mut policies: Vec<_> = attribution.iter().collect();
            policies.sort_unstable_by_key(|policy| {
                (
                    policy.token.as_str(),
                    policy.rule.as_str(),
                    policy.annotation_id.as_deref(),
                    policy.description.as_deref(),
                )
            });
            if policies.is_empty() {
                append(message, " [policy: ")?;
                append_annotation(message, rule.as_str())?;
                append(message, "]")?;
            }
            for (index, policy) in policies.into_iter().enumerate() {
                append(message, if index == 0 { " " } else { "; " })?;
                describe_policy(message, policy)?;
            }
            if !message.ends_with(['.', '!', '?']) {
                append(message, ".")?;
            }
            Some(())
        }
    }
}

fn append_resource(message: &mut String, resource: &str) -> Option<()> {
    append(message, "'")?;
    let mut budget = RESOURCE_LIMIT;
    for character in resource.chars() {
        let escaped = escaped(character, true);
        if escaped.len() > budget {
            append(message, TRUNCATED)?;
            break;
        }
        budget -= escaped.len();
        append(message, &escaped)?;
    }
    append(message, "'")
}

fn describe_policy(message: &mut String, policy: &PolicyAttribution) -> Option<()> {
    let id = nonblank(policy.annotation_id.as_deref()).unwrap_or(policy.rule.as_str());
    append(message, "[policy: ")?;
    append_annotation(message, id)?;
    append(message, "]")?;
    if let Some(description) = nonblank(policy.description.as_deref()) {
        append(message, ": ")?;
        append_annotation(message, description)?;
    }
    Some(())
}

fn nonblank(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

fn append(message: &mut String, text: &str) -> Option<()> {
    for character in text.chars() {
        append_character(message, character)?;
    }
    Some(())
}

fn append_annotation(message: &mut String, text: &str) -> Option<()> {
    for character in text.chars() {
        append(message, &escaped(character, false))?;
    }
    Some(())
}

fn escaped(character: char, quoted: bool) -> String {
    if quoted {
        return character.escape_debug().collect();
    }
    if character.is_control()
        || matches!(
            character,
            '\\'
                | '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
    {
        character.escape_default().collect()
    } else {
        character.to_string()
    }
}

fn append_character(message: &mut String, character: char) -> Option<()> {
    if message.len() + character.len_utf8() > MESSAGE_LIMIT - TRUNCATED.len() {
        return None;
    }
    message.push(character);
    Some(())
}
