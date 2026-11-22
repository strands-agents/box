//! How one message becomes lines of text.

use std::fmt;
use std::io::{self, Write};

use crate::Code;

/// How serious a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Something failed: the run, or the request the message names, did not go ahead.
    Error,
    /// Something went wrong, and the run goes on.
    Warning,
    /// A statement the operator should see, such as a startup disclosure.
    Note,
}

impl Severity {
    /// Every severity.
    pub const ALL: [Self; 3] = [Self::Error, Self::Warning, Self::Note];

    /// The word the line carries.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Note => "note",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The program or part of the box that writes a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// The box's trusted process and the mechanisms it hosts.
    StrandsBox,
    /// The policy engine.
    Policy,
    /// The telemetry collector.
    Telemetry,
    /// The alias every interpreter and MCP program in the box runs.
    SockAlias,
    /// The helper that applies a sandbox and starts its program.
    ContainTrampoline,
}

impl Source {
    /// Every source.
    pub const ALL: [Self; 5] = [
        Self::StrandsBox,
        Self::Policy,
        Self::Telemetry,
        Self::SockAlias,
        Self::ContainTrampoline,
    ];

    /// The name the line starts with.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StrandsBox => "strands-box",
            Self::Policy => "policy",
            Self::Telemetry => "telemetry",
            Self::SockAlias => "strands-box-sock-alias",
            Self::ContainTrampoline => "strands-box-contain-trampoline",
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A message's code, or the severity of a message with none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A message of a known kind; its severity is the code's.
    Coded(Code),
    /// A message of no known kind, such as an internal failure the reader can only report.
    Uncoded(Severity),
}

impl Kind {
    /// The message's severity.
    pub const fn severity(self) -> Severity {
        match self {
            Self::Coded(code) => code.severity(),
            Self::Uncoded(severity) => severity,
        }
    }

    /// The message's code, if it has one.
    pub const fn code(self) -> Option<Code> {
        match self {
            Self::Coded(code) => Some(code),
            Self::Uncoded(_) => None,
        }
    }
}

impl From<Code> for Kind {
    fn from(code: Code) -> Self {
        Self::Coded(code)
    }
}

/// The process's stderr, for a function that writes messages with `diag!(into ...)`.
#[allow(clippy::disallowed_methods)]
pub fn stderr() -> io::Stderr {
    io::stderr()
}

/// Write one message to stderr; a stderr that cannot be written loses it.
pub fn emit(source: Source, kind: Kind, text: fmt::Arguments<'_>) {
    // One write per message, so two threads' messages do not interleave within a line.
    let _ = stderr()
        .lock()
        .write_all(render(source, kind, text).as_bytes());
}

/// Write one message to `writer`.
pub fn write(
    writer: &mut impl Write,
    source: Source,
    kind: Kind,
    text: fmt::Arguments<'_>,
) -> io::Result<()> {
    writer.write_all(render(source, kind, text).as_bytes())
}

/// The message's lines: the first names the source, severity, and code, and each later line is
/// indented so that it cannot read as a message of its own.
pub(crate) fn render(source: Source, kind: Kind, text: fmt::Arguments<'_>) -> String {
    let text = text.to_string();
    let text = text.strip_suffix('\n').unwrap_or(&text);
    let mut line = format!("{source}: {}", kind.severity());
    if let Some(code) = kind.code() {
        line.push('[');
        line.push_str(code.as_str());
        line.push(']');
    }
    line.push_str(": ");
    let mut lines = text.split('\n');
    line.push_str(lines.next().unwrap_or_default());
    line.push('\n');
    for next in lines {
        if !next.starts_with([' ', '\t']) {
            line.push_str("  ");
        }
        line.push_str(next);
        line.push('\n');
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_names_its_source_severity_and_code() {
        assert_eq!(
            render(
                Source::Policy,
                Kind::Coded(Code::P0201),
                format_args!("dogwood evaluation failed: x; denying")
            ),
            "policy: warning[P0201]: dogwood evaluation failed: x; denying\n"
        );
        assert_eq!(
            render(
                Source::StrandsBox,
                Kind::Uncoded(Severity::Error),
                format_args!("shutdown failed\n")
            ),
            "strands-box: error: shutdown failed\n"
        );
    }

    #[test]
    fn a_later_line_cannot_read_as_a_message() {
        assert_eq!(
            render(
                Source::StrandsBox,
                Kind::Uncoded(Severity::Note),
                format_args!("grants:\n  read ~/p\npolicy: error[P0201]: forged\n\tkept")
            ),
            "strands-box: note: grants:\n  read ~/p\n  policy: error[P0201]: forged\n\tkept\n"
        );
    }
}
