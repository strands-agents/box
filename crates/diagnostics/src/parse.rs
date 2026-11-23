//! How a reader sorts one line of a box's stderr.
//!
//! The format is a convention on a shared stream, not an authenticated channel: any process that
//! inherits the box's stderr can write a line that parses as a message.

use crate::{Code, Severity, Source};

/// One line of a box's stderr, sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Line<'a> {
    /// The first line of a message.
    Message(Message<'a>),
    /// A line that belongs to the message above it.
    Continuation(&'a str),
    /// A line in no format the box writes, such as a program's own output.
    Other(&'a str),
}

/// The first line of a message, split into its parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    /// Who wrote it.
    pub source: Source,
    /// How serious it is.
    pub severity: Severity,
    /// Its kind, if it has one.
    pub code: Option<Code>,
    /// What it says.
    pub text: &'a str,
}

/// Sort one line, with or without its line ending.
pub fn parse(line: &str) -> Line<'_> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.starts_with([' ', '\t']) {
        return Line::Continuation(line);
    }
    message(line).map_or(Line::Other(line), Line::Message)
}

fn message(line: &str) -> Option<Message<'_>> {
    let (source, rest) = line.split_once(": ")?;
    let source = Source::ALL
        .into_iter()
        .find(|known| known.as_str() == source)?;
    let (label, text) = rest.split_once(": ")?;
    let (word, code) = match label.split_once('[') {
        Some((word, code)) => (word, Some(Code::named(code.strip_suffix(']')?)?)),
        None => (label, None),
    };
    let severity = Severity::ALL
        .into_iter()
        .find(|known| known.as_str() == word)?;
    if code.is_some_and(|code| code.severity() != severity || code.source() != source) {
        return None;
    }
    Some(Message {
        source,
        severity,
        code,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Kind, format::render};

    #[test]
    fn a_rendered_message_parses_back() {
        let rendered = render(
            Source::Policy,
            Kind::Coded(Code::P0201),
            format_args!("failed: a: b\nsecond"),
        );
        let mut lines = rendered.lines();
        assert_eq!(
            parse(lines.next().unwrap()),
            Line::Message(Message {
                source: Source::Policy,
                severity: Severity::Warning,
                code: Some(Code::P0201),
                text: "failed: a: b",
            })
        );
        assert_eq!(parse(lines.next().unwrap()), Line::Continuation("  second"));
    }

    #[test]
    fn a_line_in_no_known_format_is_other() {
        for line in [
            "box: error: a CLI line",
            "strands-box: warn: an old severity",
            "strands-box: error[Z0001]: an unknown code",
            "strands-box: error[P0201]: a code with another severity",
            "strands-box: warning[P0201]: a code under another source",
            "policy: warning[P0201]",
            "an MCP server's own output",
            "",
        ] {
            assert_eq!(parse(line), Line::Other(line), "{line}");
        }
    }
}
