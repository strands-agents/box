//! Tool grammars: an author-written action vocabulary and shell grammar for one program.
//!
//! | Module | Owns |
//! |---|---|
//! | `bindings` | which installed grammar covers a program file's identity and its called name |
//! | `format` | the grammar table as written |
//! | `model` | the checked grammar that loading builds from that table |
//! | `tool_grammar` | the checked grammars that a box installs, keyed by their place in `box.toml` |
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
mod tool_grammar;
mod usage;

#[cfg(test)]
mod corpus;
#[cfg(test)]
mod fuzz;

use std::fmt;
#[cfg(test)]
use std::path::Path;

pub(crate) use bindings::ProgramFile;
pub use bindings::{BindingRefusal, GrammarBindings};
#[cfg(feature = "shell-adapter")]
pub(crate) use bindings::{CoverageRefusal, GrammarCoverage, Starter};
pub(crate) use invocation::{GrammarInvocation, GrammarRequest, PendingGrammarResponse};
pub(crate) use model::Grammar;
pub(crate) use schema::TOOL_NAMESPACE;
pub use tool_grammar::{ToolGrammar, ToolGrammarError, ToolGrammars};
use usage::UsageFault;

/// The grammar file formats this Box reads.
const KNOWN_FORMATS: &[i64] = &[1];

/// Why Box refuses a tool grammar.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum GrammarRefusal {
    #[error("{place}: {message}")]
    Malformed { place: Place, message: String },
    #[error("{place} is required: write `format = 1`")]
    MissingFormat { place: Place },
    #[error("{place} is {value}, which is not a grammar format this Box reads (it reads 1)")]
    UnknownFormat { place: Place, value: String },
    #[error("{place} is required: write `version = 1` for a new grammar")]
    MissingVersion { place: Place },
    #[error("{place} is {value}, and it must be a positive integer")]
    BadVersion { place: Place, value: String },
    #[error(
        "{place}: {name:?} is not an identifier (ASCII letters, digits, and `_`, not first a digit)"
    )]
    NotIdentifier { place: Place, name: String },
    #[error("{place} is {program:?}, and it must be one program name, not a path")]
    BadProgram { place: Place, program: String },
    #[error("{place} starts with {first:?}, but the grammar's program is {program:?}")]
    UsageDisagrees {
        place: Place,
        first: String,
        program: String,
    },
    #[error("{place}: names effect {effect:?}, which `effects` does not declare")]
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
    #[error("{place} {fault}")]
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
    #[error("only a `global` option can set `anywhere`")]
    AnywhereOnAction,
}

/// One key in a tool grammar, as a dotted path below the grammar's own table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Place {
    Grammar,
    Path(String),
    Format,
    Version,
    Name,
    Program,
    Effect(String),
    GlobalOption(String),
    Action(String),
    ActionUsage(String),
    ActionAdds(String),
    ActionAliases(String),
    ActionOption { action: String, option: String },
    Operand { action: String, operand: String },
    Under { table: String, place: Box<Place> },
}

impl Place {
    /// The dotted key path of this place below the grammar's table, empty for the table itself.
    fn key(&self) -> String {
        let path = |segments: &[&str]| {
            segments
                .iter()
                .map(|segment| key_segment(segment))
                .collect::<Vec<_>>()
                .join(".")
        };
        match self {
            Self::Grammar => String::new(),
            Self::Path(dotted) => dotted.clone(),
            Self::Format => "format".to_string(),
            Self::Version => "version".to_string(),
            Self::Name => "name".to_string(),
            Self::Program => "program".to_string(),
            Self::Effect(effect) => path(&["effects", effect]),
            Self::GlobalOption(option) => path(&["global", "options", option]),
            Self::Action(action) => path(&["shell", action]),
            Self::ActionUsage(action) => path(&["shell", action, "usage"]),
            Self::ActionAdds(action) => path(&["shell", action, "adds"]),
            Self::ActionAliases(action) => path(&["shell", action, "aliases"]),
            Self::ActionOption { action, option } => path(&["shell", action, "options", option]),
            Self::Operand { action, operand } => path(&["shell", action, "operands", operand]),
            Self::Under { table, place } => match place.key() {
                key if key.is_empty() => table.clone(),
                key => format!("{table}.{key}"),
            },
        }
    }

    fn under(&mut self, table: &str) {
        let place = std::mem::replace(self, Self::Grammar);
        *self = Self::Under {
            table: table.to_string(),
            place: Box::new(place),
        };
    }
}

impl fmt::Display for Place {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.key() {
            key if key.is_empty() => write!(formatter, "the grammar"),
            key => write!(formatter, "`{key}`"),
        }
    }
}

/// One TOML key, bare when TOML reads it bare and quoted otherwise.
fn key_segment(segment: &str) -> String {
    let bare = !segment.is_empty()
        && segment
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'));
    if bare {
        segment.to_string()
    } else {
        format!("{segment:?}")
    }
}

impl GrammarRefusal {
    /// This refusal with each place it names put under the table `table`.
    fn under(mut self, table: &str) -> Self {
        match &mut self {
            Self::FlagTaken { place, other, .. } | Self::SpellingTaken { place, other, .. } => {
                place.under(table);
                other.under(table);
            }
            Self::Malformed { place, .. }
            | Self::MissingFormat { place }
            | Self::UnknownFormat { place, .. }
            | Self::MissingVersion { place }
            | Self::BadVersion { place, .. }
            | Self::NotIdentifier { place, .. }
            | Self::BadProgram { place, .. }
            | Self::UsageDisagrees { place, .. }
            | Self::UndeclaredEffect { place, .. }
            | Self::BadOption { place, .. }
            | Self::BadAlias { place, .. }
            | Self::BadUsage { place, .. }
            | Self::OptionsNotInUsage { place }
            | Self::OperandNotInUsage { place }
            | Self::BadRest { place }
            | Self::FieldTaken { place, .. }
            | Self::ReservedAction { place }
            | Self::ReservedField { place, .. }
            | Self::CedarReservedField { place, .. } => place.under(table),
        }
        self
    }

    /// A document that does not deserialize, at the key path the TOML error names.
    fn malformed(error: &toml::de::Error) -> Self {
        let message = error.to_string();
        let message = message.trim_end();
        let (message, place) = match message.rsplit_once('\n') {
            Some((head, tail)) => match tail
                .strip_prefix("in `")
                .and_then(|tail| tail.strip_suffix('`'))
            {
                Some(path) => (head.trim_end(), Place::Path(path.to_string())),
                None => (message, Place::Grammar),
            },
            None => (message, Place::Grammar),
        };
        Self::Malformed {
            place,
            message: message.to_string(),
        }
    }
}

impl Grammar {
    /// Check the grammar table `table`, which sits at the dotted key path `table_key`.
    pub(crate) fn from_table(table: toml::Table, table_key: &str) -> Result<Self, GrammarRefusal> {
        Self::read_table(table).map_err(|refusal| refusal.under(table_key))
    }

    fn read_table(table: toml::Table) -> Result<Self, GrammarRefusal> {
        match table.get("format") {
            None => {
                return Err(GrammarRefusal::MissingFormat {
                    place: Place::Format,
                });
            }
            Some(toml::Value::Integer(format)) if KNOWN_FORMATS.contains(format) => {}
            Some(other) => {
                return Err(GrammarRefusal::UnknownFormat {
                    place: Place::Format,
                    value: other.to_string(),
                });
            }
        }
        let file = toml::Value::Table(table)
            .try_into()
            .map_err(|error| GrammarRefusal::malformed(&error))?;
        Self::read(file)
    }

    /// Read and check the grammar file at `path`, as if it sat at `tool.corpus.grammar`.
    #[cfg(test)]
    pub(crate) fn load(path: &Path) -> Result<Self, GrammarRefusal> {
        let text = std::fs::read_to_string(path).expect("the grammar file reads");
        Self::parse(&text)
    }

    /// Check the grammar document `text`, as if it sat at `tool.corpus.grammar`.
    #[cfg(test)]
    pub(crate) fn parse(text: &str) -> Result<Self, GrammarRefusal> {
        let table: toml::Table =
            toml::from_str(text).map_err(|error| GrammarRefusal::Malformed {
                place: Place::Grammar,
                message: error.message().to_string(),
            })?;
        Self::from_table(table, CORPUS_TABLE)
    }
}

/// The key path the test corpus loads each grammar at.
#[cfg(test)]
pub(crate) const CORPUS_TABLE: &str = "tool.corpus.grammar";

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

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

    fn operator_message(refusal: &GrammarRefusal) -> String {
        let message = refusal.to_string().replace(CORPUS_TABLE, "<grammar>");
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
                let loaded = Grammar::parse(&text).map_err(|refusal| operator_message(&refusal));
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
    fn a_refusal_names_the_key_path_in_box_toml() {
        let table: toml::Table = toml::from_str(
            "format = 1\nversion = 1\nname = \"git\"\nprogram = \"git\"\n\
             [shell.push]\nusage = \"git push [\"\n",
        )
        .expect("the document parses");

        let refusal =
            Grammar::from_table(table, "tool.git.grammar").expect_err("the grammar is refused");

        assert_eq!(
            refusal.to_string(),
            "`tool.git.grammar.shell.push.usage` has a `[` with no `]`"
        );
    }

    #[test]
    fn an_unknown_key_is_refused_at_the_table_that_holds_it() {
        let table: toml::Table = toml::from_str(
            "format = 1\nversion = 1\nname = \"git\"\nprogram = \"git\"\n\
             [shell.push]\nusage = \"git push\"\nflags = 1\n",
        )
        .expect("the document parses");

        let refusal =
            Grammar::from_table(table, "tool.git.grammar").expect_err("the grammar is refused");

        assert!(
            refusal
                .to_string()
                .starts_with("`tool.git.grammar.shell.push`: unknown field `flags`"),
            "{refusal}"
        );
    }
}
