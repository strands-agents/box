//! One `usage` line, read into the shape that the command lines of its action take.

use super::model::{command_word, is_identifier};

/// What one `usage` line says about the command lines of its action.
#[derive(Debug, Default)]
pub(super) struct Usage {
    pub(super) words: Vec<String>,
    pub(super) globals: bool,
    pub(super) toolchain: Option<String>,
    pub(super) options: bool,
    pub(super) operands: Vec<Placeholder>,
    pub(super) separator: Separator,
}

/// One `<name>` or `<name>...` in a usage line.
#[derive(Debug)]
pub(super) struct Placeholder {
    pub(super) name: String,
    pub(super) required: bool,
    pub(super) variadic: bool,
}

/// Where a usage line puts `--` among its operands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum Separator {
    #[default]
    None,
    /// `[--]`: the operands from this index follow `--` when the command line gives one.
    Optional(usize),
    /// `--` or `[-- ...]`: the operands from this index follow `--` only.
    Required(usize),
}

/// Why Box refuses a usage line.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum UsageFault {
    #[error("has a `]` with no `[`")]
    UnopenedBracket,
    #[error("has a `[` with no `]`")]
    UnclosedBracket,
    #[error("uses {0:?}, which a usage line does not support")]
    Unsupported(char),
    #[error("names no command word")]
    NoCommandWord,
    #[error("puts command word {0:?} in `[ ]` or after an operand")]
    CommandWordOutOfPlace(String),
    #[error("has {0:?}, which is not a command word, an operand `<name>`, or `--`")]
    UnknownWord(String),
    #[error("has option {0:?}; declare it in `options`, and write `[options]` in the usage")]
    InlineOption(String),
    #[error("puts `[global options]` after the command words")]
    GlobalOptionsOutOfPlace,
    #[error("puts `[options]` before the command words")]
    OptionsOutOfPlace,
    #[error("puts an operand or `--` before the command words")]
    OperandOutOfPlace,
    #[error("has more than one `--`")]
    SecondSeparator,
    #[error("puts `[+<toolchain>]` in a place other than directly after the program")]
    ToolchainOutOfPlace,
}

#[derive(Debug)]
enum Node {
    Word(String),
    Group(Vec<Node>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Before,
    Words,
    After,
}

impl Usage {
    /// Read `usage`, whose first word is `program`.
    pub(super) fn read(usage: &str, program: &str) -> Result<Self, UsageFault> {
        let after_program = usage.trim_start().strip_prefix(program).unwrap_or_default();
        let nodes = tokenize(after_program)?;
        let mut walker = Walker {
            usage: Self::default(),
            phase: Phase::Before,
        };
        for (position, node) in nodes.iter().enumerate() {
            match node {
                Node::Group(group) if toolchain(group).is_some() => {
                    if position != 0 {
                        return Err(UsageFault::ToolchainOutOfPlace);
                    }
                    walker.usage.toolchain = toolchain(group);
                }
                node => walker.node(node, false)?,
            }
        }
        if walker.usage.words.is_empty() {
            return Err(UsageFault::NoCommandWord);
        }
        Ok(walker.usage)
    }
}

fn tokenize(usage: &str) -> Result<Vec<Node>, UsageFault> {
    let mut stack: Vec<Vec<Node>> = vec![Vec::new()];
    let mut word = String::new();
    let flush = |word: &mut String, stack: &mut Vec<Vec<Node>>| {
        if !word.is_empty()
            && let Some(top) = stack.last_mut()
        {
            top.push(Node::Word(std::mem::take(word)));
        }
    };
    for character in usage.chars() {
        match character {
            '[' => {
                flush(&mut word, &mut stack);
                stack.push(Vec::new());
            }
            ']' => {
                flush(&mut word, &mut stack);
                let group = stack.pop().ok_or(UsageFault::UnopenedBracket)?;
                stack
                    .last_mut()
                    .ok_or(UsageFault::UnopenedBracket)?
                    .push(Node::Group(group));
            }
            '|' | '(' | ')' | '{' | '}' => return Err(UsageFault::Unsupported(character)),
            character if character.is_whitespace() => flush(&mut word, &mut stack),
            character => word.push(character),
        }
    }
    flush(&mut word, &mut stack);
    match stack.pop() {
        Some(nodes) if stack.is_empty() => Ok(nodes),
        _ => Err(UsageFault::UnclosedBracket),
    }
}

fn placeholder(word: &str) -> Option<(&str, bool)> {
    let (inner, variadic) = match word.strip_suffix("...") {
        Some(inner) => (inner, true),
        None => (word, false),
    };
    let name = inner.strip_prefix('<')?.strip_suffix('>')?;
    is_identifier(name).then_some((name, variadic))
}

fn toolchain(group: &[Node]) -> Option<String> {
    match group {
        [Node::Word(word)] => {
            let name = word.strip_prefix("+<")?.strip_suffix('>')?;
            is_identifier(name).then(|| name.to_string())
        }
        _ => None,
    }
}

struct Walker {
    usage: Usage,
    phase: Phase,
}

impl Walker {
    fn node(&mut self, node: &Node, optional: bool) -> Result<(), UsageFault> {
        match node {
            Node::Word(word) => self.word(word, optional),
            Node::Group(group) => self.group(group),
        }
    }

    fn word(&mut self, word: &str, optional: bool) -> Result<(), UsageFault> {
        if word == "--" {
            return self.separator(true);
        }
        if let Some((name, variadic)) = placeholder(word) {
            self.after_words()?;
            self.usage.operands.push(Placeholder {
                name: name.to_string(),
                required: !optional,
                variadic,
            });
            return Ok(());
        }
        if command_word(word) {
            if optional || self.phase == Phase::After {
                return Err(UsageFault::CommandWordOutOfPlace(word.to_string()));
            }
            self.phase = Phase::Words;
            self.usage.words.push(word.to_string());
            return Ok(());
        }
        if word.starts_with('-') {
            return Err(UsageFault::InlineOption(word.to_string()));
        }
        Err(UsageFault::UnknownWord(word.to_string()))
    }

    fn group(&mut self, group: &[Node]) -> Result<(), UsageFault> {
        let words: Vec<&str> = group
            .iter()
            .map_while(|node| match node {
                Node::Word(word) => Some(word.as_str()),
                Node::Group(_) => None,
            })
            .collect();
        match (words.as_slice(), group.len()) {
            (["global", "options"], 2) => {
                if self.phase != Phase::Before {
                    return Err(UsageFault::GlobalOptionsOutOfPlace);
                }
                self.usage.globals = true;
                Ok(())
            }
            (["options"], 1) => {
                if self.phase == Phase::Before {
                    return Err(UsageFault::OptionsOutOfPlace);
                }
                self.phase = Phase::After;
                self.usage.options = true;
                Ok(())
            }
            (["--"], 1) => self.separator(false),
            (["--", ..], _) => {
                self.separator(true)?;
                group[1..].iter().try_for_each(|node| self.node(node, true))
            }
            _ => group.iter().try_for_each(|node| self.node(node, true)),
        }
    }

    fn after_words(&mut self) -> Result<(), UsageFault> {
        if self.phase == Phase::Before {
            return Err(UsageFault::OperandOutOfPlace);
        }
        self.phase = Phase::After;
        Ok(())
    }

    fn separator(&mut self, required: bool) -> Result<(), UsageFault> {
        self.after_words()?;
        if self.usage.separator != Separator::None {
            return Err(UsageFault::SecondSeparator);
        }
        let at = self.usage.operands.len();
        self.usage.separator = if required {
            Separator::Required(at)
        } else {
            Separator::Optional(at)
        };
        Ok(())
    }
}
