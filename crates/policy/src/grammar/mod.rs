//! Tool grammars: an author-written action vocabulary and shell grammar for one program.
//!
//! | Module | Owns |
//! |---|---|
//! | `bindings` | which installed grammar covers a program file's identity and its called name |
//! | `format` | the `*.grammar.toml` document as written |
//! | `model` | the checked grammar that loading builds from that document |
//! | `usage` | one `usage` line, read into the shape of its command lines |
//! | `shell_grammar` | the shell grammar that compiling a grammar builds |
//! | `parse` | one command line, read against the shell grammar |
//! | `schema` | the Cedar schema fragment that a checked grammar generates |
//! | `invocation` | one command line that a grammar read, as the record its action decides |

mod bindings;
mod format;
mod invocation;
mod model;
mod parse;
mod schema;
mod shell_grammar;
mod usage;

#[cfg(test)]
mod corpus;
#[cfg(test)]
mod fuzz;

use std::fmt;
use std::path::{Path, PathBuf};

pub(crate) use bindings::ProgramFile;
#[cfg(feature = "shell-adapter")]
pub(crate) use bindings::{CoverageRefusal, GrammarBindings, GrammarCoverage};
pub(crate) use invocation::{GrammarInvocation, GrammarRequest, PendingGrammarResponse};
pub(crate) use model::Grammar;
pub(crate) use schema::TOOL_NAMESPACE;
use usage::UsageFault;

/// The grammar file formats this Box reads.
const KNOWN_FORMATS: &[i64] = &[1];

/// A tool grammar file that Box refuses to load.
#[derive(Debug, thiserror::Error)]
#[error("tool grammar {}: {refusal}", .origin.display())]
pub(crate) struct GrammarError {
    origin: PathBuf,
    refusal: Box<GrammarRefusal>,
}

/// Why Box refuses a tool grammar file.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum GrammarRefusal {
    #[error("cannot read the file: {0}")]
    Unreadable(String),
    #[error("{0}")]
    Malformed(String),
    #[error("`format` is required: write `format = 1`")]
    MissingFormat,
    #[error("`format = {0}` is not a grammar file format this Box reads (it reads 1)")]
    UnknownFormat(String),
    #[error("`version` is required: write `version = 1` for a new grammar")]
    MissingVersion,
    #[error("`version = {0}` must be a positive integer")]
    BadVersion(String),
    #[error(
        "{place}: {name:?} is not an identifier (ASCII letters, digits, and `_`, not first a digit)"
    )]
    NotIdentifier { place: Place, name: String },
    #[error("`program = {0:?}` must be one program name, not a path")]
    BadProgram(String),
    #[error("{place}: usage starts with {first:?}, but the grammar's program is {program:?}")]
    UsageDisagrees {
        place: Place,
        first: String,
        program: String,
    },
    #[error("{place}: names effect {effect:?}, which `[effects]` does not declare")]
    UndeclaredEffect { place: Place, effect: String },
    #[error("{place}: {fault}")]
    BadOption { place: Place, fault: OptionFault },
    #[error("{place}: flag {flag:?} is also a flag of {other}")]
    FlagTaken {
        place: Place,
        flag: String,
        other: Box<Place>,
    },
    #[error("{place}: {alias:?} must be command words (lowercase ASCII letters, digits, and `-`)")]
    BadAlias { place: Place, alias: String },
    #[error("{place}: spells `{spelling}`, and {other} spells it too")]
    SpellingTaken {
        place: Place,
        spelling: String,
        other: Box<Place>,
    },
    #[error("{place}: usage {fault}")]
    BadUsage { place: Place, fault: UsageFault },
    #[error("{place}: declares `options`, but its usage has no `[options]`")]
    OptionsNotInUsage { place: Place },
    #[error("{place}: the usage does not name this operand")]
    OperandNotInUsage { place: Place },
    #[error(
        "{place}: `rest` needs this operand alone in the usage, written as `<name>...` and not after a required `--`"
    )]
    BadRest { place: Place },
    #[error("{place}: two fields have the name {field:?}")]
    FieldTaken { place: Place, field: String },
    #[error("{place}: the name is reserved for a command that no action matches")]
    ReservedAction { place: Place },
    #[error("{place}: field {field:?} has a name that the schema gives every action")]
    ReservedField { place: Place, field: String },
    #[error("{place}: field {field:?} starts with `__`, which Box reserves for Cedar record keys")]
    CedarReservedField { place: Place, field: String },
}

/// Why Box refuses one option of a tool grammar.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum OptionFault {
    #[error("declares no flag")]
    NoFlag,
    #[error("flag {0:?} must be `--` and a name with no `=`, or `-` and one character")]
    MalformedFlag(String),
    #[error("takes no value, so it cannot carry `like` or `when`")]
    PatternWithoutValue,
    #[error("takes no value, so it cannot be `repeated`")]
    RepeatedWithoutValue,
    #[error("only a `[global]` option can set `anywhere`")]
    AnywhereOnAction,
}

/// One location in a tool grammar file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Place {
    Name,
    Effect(String),
    GlobalOption(String),
    Action(String),
    ActionAdds(String),
    ActionAliases(String),
    ActionOption { action: String, option: String },
    Operand { action: String, operand: String },
}

impl fmt::Display for Place {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name => write!(formatter, "`name`"),
            Self::Effect(effect) => write!(formatter, "`[effects] {effect}`"),
            Self::GlobalOption(option) => write!(formatter, "`[global] options.{option}`"),
            Self::Action(action) => write!(formatter, "`[shell.{action}]`"),
            Self::ActionAdds(action) => write!(formatter, "`[shell.{action}] adds`"),
            Self::ActionAliases(action) => write!(formatter, "`[shell.{action}] aliases`"),
            Self::ActionOption { action, option } => {
                write!(formatter, "`[shell.{action}] options.{option}`")
            }
            Self::Operand { action, operand } => {
                write!(formatter, "`[shell.{action}] operands.{operand}`")
            }
        }
    }
}

impl Grammar {
    /// Read and check the tool grammar file at `path`.
    pub(crate) fn load(path: &Path) -> Result<Self, GrammarError> {
        let text = std::fs::read_to_string(path).map_err(|error| GrammarError {
            origin: path.to_path_buf(),
            refusal: Box::new(GrammarRefusal::Unreadable(error.to_string())),
        })?;
        Self::parse(&text).map_err(|refusal| GrammarError {
            origin: path.to_path_buf(),
            refusal: Box::new(refusal),
        })
    }

    fn parse(text: &str) -> Result<Self, GrammarRefusal> {
        let malformed = |error: toml::de::Error| GrammarRefusal::Malformed(error.to_string());
        let document: toml::Table = toml::from_str(text).map_err(malformed)?;
        match document.get("format") {
            None => return Err(GrammarRefusal::MissingFormat),
            Some(toml::Value::Integer(format)) if KNOWN_FORMATS.contains(format) => {}
            Some(other) => return Err(GrammarRefusal::UnknownFormat(other.to_string())),
        }
        Self::read(toml::from_str(text).map_err(malformed)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/grammars");
    const EXPECT: &str = "# expect:";

    fn expected_message(text: &str) -> Option<String> {
        let lines: Vec<&str> = text
            .lines()
            .map_while(|line| line.strip_prefix(EXPECT))
            .map(str::trim)
            .collect();
        (!lines.is_empty()).then(|| lines.join("\n"))
    }

    fn operator_message(error: &GrammarError, path: &Path) -> String {
        let message = error
            .to_string()
            .replace(&path.display().to_string(), "<file>");
        message
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn corpus(kind: &str) -> Vec<PathBuf> {
        let directory = Path::new(CORPUS).join(kind);
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
            .map(|entry| entry.expect("a corpus entry").path())
            .collect();
        paths.sort();
        assert!(
            !paths.is_empty(),
            "{} holds no grammar",
            directory.display()
        );
        paths
    }

    #[test]
    fn every_grammar_in_the_corpus_loads_or_is_refused_as_it_expects() {
        let mut failures = Vec::new();
        for (kind, valid) in [("valid", true), ("invalid", false)] {
            for path in corpus(kind) {
                let file = format!("{kind}/{}", path.file_name().unwrap_or_default().display());
                if !file.ends_with(".grammar.toml") {
                    failures.push(format!("{file}: is not named `*.grammar.toml`"));
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("the corpus file reads");
                let leading = text.lines().take_while(|line| line.starts_with(EXPECT));
                if text
                    .lines()
                    .skip(leading.count())
                    .any(|line| line.starts_with(EXPECT))
                {
                    failures.push(format!("{file}: has a `# expect:` line below the top"));
                    continue;
                }
                let expected = expected_message(&text);
                let loaded = Grammar::load(&path).map_err(|error| operator_message(&error, &path));
                let failure = match (valid, expected, loaded) {
                    (true, None, Ok(_)) => continue,
                    (true, Some(_), _) => "a valid grammar carries a `# expect:` line".to_string(),
                    (true, None, Err(message)) => format!("refused:\n{message}"),
                    (false, None, _) => "an invalid grammar has no `# expect:` line".to_string(),
                    (false, Some(_), Ok(_)) => "loaded, but expected a refusal".to_string(),
                    (false, Some(expected), Err(message)) if expected == message => continue,
                    (false, Some(expected), Err(message)) => {
                        format!("expected:\n{expected}\nbut got:\n{message}")
                    }
                };
                failures.push(format!("{file}: {failure}"));
            }
        }

        assert!(failures.is_empty(), "\n{}", failures.join("\n\n"));
    }

    #[test]
    fn a_missing_file_is_refused_as_unreadable() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let error = Grammar::load(&directory.path().join("absent.grammar.toml"))
            .expect_err("the grammar is refused");

        assert!(matches!(*error.refusal, GrammarRefusal::Unreadable(_)));
    }
}
