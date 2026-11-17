//! What a box would refuse in a policy, found without opening an authority.

use std::ops::Range;

/// The findings of one policy check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyCheck {
    errors: Vec<Finding>,
    warnings: Vec<Finding>,
    unchecked: Vec<RuleRef>,
}

impl PolicyCheck {
    pub(crate) fn new(
        errors: Vec<Finding>,
        warnings: Vec<Finding>,
        unchecked: Vec<RuleRef>,
    ) -> Self {
        Self {
            errors,
            warnings,
            unchecked,
        }
    }

    /// Each finding that stops a box from opening.
    pub fn errors(&self) -> &[Finding] {
        &self.errors
    }

    /// Each finding that a box reports and opens with.
    pub fn warnings(&self) -> &[Finding] {
        &self.warnings
    }

    /// Each rule that names a per-tool MCP action, which only a running box can validate.
    pub fn unchecked(&self) -> &[RuleRef] {
        &self.unchecked
    }
}

/// One problem in a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    message: String,
    rules: Vec<RuleRef>,
    location: Option<Location>,
    help: Option<String>,
    span: Option<Range<usize>>,
}

impl Finding {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            rules: Vec::new(),
            location: None,
            help: None,
            span: None,
        }
    }

    pub(crate) fn with_rules(mut self, rules: Vec<RuleRef>) -> Self {
        self.rules = rules;
        self
    }

    pub(crate) fn with_span(mut self, span: Range<usize>) -> Self {
        self.span = Some(span);
        self
    }

    pub(crate) fn with_help(mut self, help: Option<String>) -> Self {
        self.help = help;
        self
    }

    /// This finding's text with its line, column, and help, as a refusal states it.
    pub(crate) fn described(&self, message: &str) -> String {
        let mut text = message.to_string();
        if let Some(location) = self.location {
            text.push_str(&format!(
                " at line {}, column {}",
                location.line, location.column
            ));
        }
        if let Some(help) = &self.help {
            text.push_str(&format!(" ({help})"));
        }
        text
    }

    /// This finding with the location of `other`, and no help.
    pub(crate) fn with_location_of(mut self, other: &Finding) -> Self {
        self.location = other.location;
        self
    }

    /// This finding with no position in the source.
    pub(crate) fn without_span(mut self) -> Self {
        self.span = None;
        self.location = None;
        self
    }

    /// This finding with its location in `source`, the text its span is an offset into.
    pub(crate) fn located_in(mut self, source: &str) -> Self {
        self.location = self
            .span
            .as_ref()
            .map(|span| Location::of(source, span.clone()));
        self
    }

    /// What is wrong.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The rules this finding names.
    pub fn rules(&self) -> &[RuleRef] {
        &self.rules
    }

    /// Where in the policy source the problem is, when the engine reports it.
    pub fn location(&self) -> Option<Location> {
        self.location
    }

    /// The engine's hint for a fix, such as the closest known name.
    pub fn help(&self) -> Option<&str> {
        self.help.as_deref()
    }
}

/// One rule of a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRef {
    position: usize,
    id: Option<String>,
}

impl RuleRef {
    pub(crate) fn new(index: usize, id: Option<String>) -> Self {
        Self {
            position: index.saturating_add(1),
            id: id.filter(|id| !id.trim().is_empty()),
        }
    }

    /// The rule's place in the policy, counting from 1.
    pub fn position(&self) -> usize {
        self.position
    }

    /// The rule's `@id`, when it has one.
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

/// A range of a policy source, by line and column, each counting from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
}

impl Location {
    fn of(source: &str, span: Range<usize>) -> Self {
        let (line, column) = line_and_column(source, span.start);
        let (end_line, end_column) = line_and_column(source, span.end.max(span.start));
        Self {
            line,
            column,
            end_line,
            end_column,
        }
    }

    /// The line the range starts on.
    pub fn line(&self) -> usize {
        self.line
    }

    /// The column the range starts at, in characters.
    pub fn column(&self) -> usize {
        self.column
    }

    /// The line the range ends on.
    pub fn end_line(&self) -> usize {
        self.end_line
    }

    /// The column the range ends at, in characters.
    pub fn end_column(&self) -> usize {
        self.end_column
    }
}

fn line_and_column(source: &str, offset: usize) -> (usize, usize) {
    let mut offset = offset.min(source.len());
    while !source.is_char_boundary(offset) {
        offset -= 1;
    }
    let before = &source[..offset];
    let line_start = before.rfind('\n').map_or(0, |index| index + 1);
    (
        before.matches('\n').count() + 1,
        before[line_start..].chars().count() + 1,
    )
}

/// The `@id` annotation of a rule rendered as Dogwood source.
pub(crate) fn annotated_id(rendered: &str) -> Option<String> {
    let mut rest = rendered.trim_start();
    while let Some(annotation) = rest.strip_prefix('@') {
        let name_end = annotation
            .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(annotation.len());
        let name = &annotation[..name_end];
        let after_name = annotation[name_end..].trim_start();
        let Some(argument) = after_name.strip_prefix('(') else {
            rest = after_name;
            continue;
        };
        let argument = argument.trim_start();
        let mut characters = argument.char_indices();
        if characters.next().map(|(_, character)| character) != Some('"') {
            return None;
        }
        let mut value = String::new();
        let mut end = None;
        while let Some((index, character)) = characters.next() {
            match character {
                '"' => {
                    end = Some(index);
                    break;
                }
                '\\' => value.push(characters.next()?.1),
                other => value.push(other),
            }
        }
        if name == "id" {
            return Some(value);
        }
        rest = argument[end? + 1..]
            .trim_start()
            .strip_prefix(')')?
            .trim_start();
    }
    None
}

/// A refusal, as the `PolicyError` that `open` returns and as the findings behind it.
#[derive(Debug)]
pub(crate) struct Refused {
    pub(crate) error: crate::PolicyError,
    pub(crate) findings: Vec<Finding>,
}

impl Refused {
    pub(crate) fn new(error: crate::PolicyError, findings: Vec<Finding>) -> Self {
        Self { error, findings }
    }

    pub(crate) fn into_error(self) -> crate::PolicyError {
        self.error
    }
}

impl From<crate::PolicyError> for Refused {
    fn from(error: crate::PolicyError) -> Self {
        let findings = vec![Finding::new(error.to_string())];
        Self { error, findings }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_location_counts_lines_and_characters_from_one() {
        let source = "// é\n\n@id(\"a\") permit";
        let start = source.find("permit").expect("permit");
        let location = Location::of(source, start..start + 6);
        assert_eq!(
            (
                location.line(),
                location.column(),
                location.end_line(),
                location.end_column()
            ),
            (3, 10, 3, 16)
        );
        assert_eq!(line_and_column("é", 1), (1, 1));
    }

    #[test]
    fn an_annotated_id_is_read_before_the_effect_and_keeps_an_escaped_quote() {
        assert_eq!(
            annotated_id("@id(\"a\\\"b\")\npermit (principal, action, resource);").as_deref(),
            Some("a\"b")
        );
        assert_eq!(
            annotated_id(
                "permit (principal, action, resource) when { context.input.path == \"@id(\\\"x\\\")\" };"
            ),
            None
        );
        assert_eq!(
            annotated_id(
                "@description(\"no\")\n@id(\"permit_all\")\npermit (principal, action, resource);"
            )
            .as_deref(),
            Some("permit_all")
        );
        assert_eq!(
            annotated_id("@foo @id(\"x\") permit (principal, action, resource);").as_deref(),
            Some("x")
        );
    }

    #[test]
    fn a_rule_counts_from_one_and_drops_a_blank_id() {
        let rule = RuleRef::new(0, Some(" ".to_string()));
        assert_eq!((rule.position(), rule.id()), (1, None));
    }
}
