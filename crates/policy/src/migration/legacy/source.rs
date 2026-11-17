use super::{MigrationError, MigrationErrorKind};
use dogwood_language::{ParsedPolicySet, ServiceSchema};

/// An auditable source edit. Offsets refer to the original statement's UTF-8 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticPathRewrite {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConvertedStatement {
    /// Only supported static `has` operands change. Temporal text stays exact.
    pub(crate) statement: String,
    pub(crate) rewrites: Vec<StaticPathRewrite>,
}

/// Convert one expanded, saved 1.0.0 rule for an explicit migration.
///
/// Supported old operand: `has "IDENT".IDENT[.IDENT...]`, where IDENT is an
/// unescaped ASCII identifier and the first is neither `true` nor `false`.
/// Line comments and strings are tokenized; no substring replacement is used.
/// Every other byte is preserved, then the entire result must parse as exactly
/// one current policy. Schema validation and monitor fingerprint checks belong
/// to the coordinator; a successful parse does not prove recovery compatibility.
pub(crate) fn convert_saved_statement(
    source: &str,
    service: &ServiceSchema,
) -> Result<ConvertedStatement, MigrationError> {
    let tokens = tokenize(source)?;
    let bodies = temporal_ranges_from_tokens(source, &tokens)?;
    reject_definitions(source, &tokens)?;
    let mut edits = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        if bodies
            .iter()
            .any(|&(start, end)| token.start >= start && token.start < end)
        {
            i += 1;
            continue;
        }
        if token.word(source) != Some("has")
            || i + 2 >= tokens.len()
            || tokens[i + 1].kind != TokenKind::Quoted
            || tokens[i + 2].kind != TokenKind::Punct(b'.')
        {
            i += 1;
            continue;
        }
        let quoted = tokens[i + 1];
        let name = &source[quoted.start + 1..quoted.end - 1];
        if !identifier(name) || matches!(name, "true" | "false") {
            return Err(at(
                MigrationErrorKind::UnsupportedSyntax,
                quoted.start,
                "legacy has-path first segment is outside the supported identifier subset",
            ));
        }
        let mut next = i + 2;
        while next < tokens.len() && tokens[next].kind == TokenKind::Punct(b'.') {
            let Some(segment) = tokens.get(next + 1) else {
                return Err(at(
                    MigrationErrorKind::UnsupportedSyntax,
                    tokens[next].start,
                    "legacy has-path is missing a segment",
                ));
            };
            if segment.kind != TokenKind::Identifier {
                return Err(at(
                    MigrationErrorKind::UnsupportedSyntax,
                    segment.start,
                    "legacy has-path requires unquoted identifier segments",
                ));
            }
            next += 2;
        }
        edits.push(StaticPathRewrite {
            start: quoted.start,
            end: quoted.end,
            identifier: name.to_owned(),
        });
        i = next;
    }
    let mut statement = String::with_capacity(source.len());
    let mut cursor = 0;
    for edit in &edits {
        statement.push_str(&source[cursor..edit.start]);
        statement.push_str(&edit.identifier);
        cursor = edit.end;
    }
    statement.push_str(&source[cursor..]);
    let parsed = ParsedPolicySet::parse(&statement, service).map_err(|error| MigrationError {
        kind: MigrationErrorKind::InvalidPolicy,
        byte_offset: None,
        detail: format!("saved statement is unsupported after static path conversion: {error}"),
    })?;
    let policies: Vec<_> = parsed.policies().collect();
    if policies.len() != 1 {
        return Err(MigrationError {
            kind: MigrationErrorKind::PolicyCount,
            byte_offset: None,
            detail: format!("expected one saved policy, found {}", policies.len()),
        });
    }
    super::temporal::validate_policy(&policies[0])?;
    Ok(ConvertedStatement {
        statement,
        rewrites: edits,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    Identifier,
    Quoted,
    Punct(u8),
    Other,
}
#[derive(Debug, Clone, Copy)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}
impl Token {
    fn word<'a>(&self, source: &'a str) -> Option<&'a str> {
        (self.kind == TokenKind::Identifier).then(|| &source[self.start..self.end])
    }
}

fn identifier(source: &str) -> bool {
    let mut bytes = source.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn at(kind: MigrationErrorKind, byte_offset: usize, detail: &str) -> MigrationError {
    MigrationError {
        kind,
        byte_offset: Some(byte_offset),
        detail: detail.into(),
    }
}

/// Dogwood's published surface grammar uses double-quoted strings, backslash
/// escapes, ASCII identifiers, and `//` line comments. This scanner keeps exact
/// byte spans and leaves expression validation to the public parser.
fn tokenize(source: &str) -> Result<Vec<Token>, MigrationError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b'\r' {
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            return Err(at(
                MigrationErrorKind::UnsupportedSyntax,
                i,
                "block comments are outside the published policy grammar",
            ));
        }
        let start = i;
        let kind = if byte == b'"' {
            i += 1;
            let mut closed = false;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 1;
                    if i == bytes.len() {
                        break;
                    }
                    // Escape contents are checked by the public parser. Advancing
                    // one byte is safe here: only ASCII quote/backslash delimit.
                    i += 1;
                } else if bytes[i] == b'"' {
                    i += 1;
                    closed = true;
                    break;
                } else {
                    i += 1;
                }
            }
            if !closed {
                return Err(at(
                    MigrationErrorKind::Lexical,
                    start,
                    "unclosed policy string",
                ));
            }
            TokenKind::Quoted
        } else if byte.is_ascii_alphabetic() || byte == b'_' {
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            TokenKind::Identifier
        } else if byte.is_ascii() {
            i += 1;
            TokenKind::Punct(byte)
        } else {
            // source is already valid UTF-8; advance to the next character boundary.
            let width = source[i..]
                .chars()
                .next()
                .map(char::len_utf8)
                .ok_or_else(|| at(MigrationErrorKind::Lexical, i, "invalid policy token"))?;
            i += width;
            TokenKind::Other
        };
        tokens.push(Token {
            kind,
            start,
            end: i,
        });
    }
    Ok(tokens)
}

pub(super) fn temporal_ranges(source: &str) -> Result<Vec<(usize, usize)>, MigrationError> {
    temporal_ranges_from_tokens(source, &tokenize(source)?)
}

fn temporal_ranges_from_tokens(
    source: &str,
    tokens: &[Token],
) -> Result<Vec<(usize, usize)>, MigrationError> {
    let mut ranges = Vec::new();
    let mut i = 0;
    while i + 1 < tokens.len() {
        if tokens[i].word(source) != Some("temporal")
            || tokens[i + 1].kind != TokenKind::Punct(b'{')
        {
            i += 1;
            continue;
        }
        let open = tokens[i + 1];
        let mut depth = 1usize;
        let mut next = i + 2;
        while next < tokens.len() {
            match tokens[next].kind {
                TokenKind::Punct(b'{') => depth += 1,
                TokenKind::Punct(b'}') => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            next += 1;
        }
        if depth != 0 {
            return Err(at(
                MigrationErrorKind::Lexical,
                open.start,
                "unclosed temporal block",
            ));
        }
        ranges.push((open.end, tokens[next].start));
        i = next + 1;
    }
    Ok(ranges)
}

fn reject_definitions(source: &str, tokens: &[Token]) -> Result<(), MigrationError> {
    let (mut braces, mut parentheses) = (0usize, 0usize);
    for (index, token) in tokens.iter().enumerate() {
        let annotation = index > 0 && tokens[index - 1].kind == TokenKind::Punct(b'@');
        if braces == 0 && parentheses == 0 && !annotation && token.word(source) == Some("def") {
            return Err(at(
                MigrationErrorKind::UnsupportedSyntax,
                token.start,
                "macro definitions are not saved expanded statements",
            ));
        }
        match token.kind {
            TokenKind::Punct(b'{') => braces += 1,
            TokenKind::Punct(b'}') => braces = braces.saturating_sub(1),
            TokenKind::Punct(b'(') => parentheses += 1,
            TokenKind::Punct(b')') => parentheses = parentheses.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}
