//! The checked tool grammars that a box installs, each at its key path in `box.toml`.

use std::sync::Arc;

use super::{Grammar, GrammarRefusal};

/// One checked tool grammar.
#[derive(Debug, Clone)]
pub struct ToolGrammar {
    grammar: Arc<Grammar>,
    table: String,
}

/// A tool grammar, or a set of them, that Box refuses to install.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ToolGrammarError(Box<Refusal>);

#[derive(Debug, thiserror::Error)]
enum Refusal {
    #[error(transparent)]
    Grammar(GrammarRefusal),
    #[error("`{first}` and `{second}` both have `name = {name:?}`; give each grammar its own name")]
    NamedTwice {
        name: String,
        first: String,
        second: String,
    },
    #[error(
        "`{first}` and `{second}` both have `program = {program:?}`; keep one grammar for each program"
    )]
    ProgramTwice {
        program: String,
        first: String,
        second: String,
    },
}

impl ToolGrammar {
    /// Check the grammar `table`, which sits at the dotted key path `table_key`, such as
    /// `tool.git.grammar`. Each refusal names a key path under `table_key`.
    pub fn from_table(table: toml::Table, table_key: &str) -> Result<Self, ToolGrammarError> {
        let grammar = Grammar::from_table(table, table_key)
            .map_err(|refusal| ToolGrammarError(Box::new(Refusal::Grammar(refusal))))?;
        Ok(Self {
            grammar: Arc::new(grammar),
            table: table_key.to_string(),
        })
    }

    /// The policy namespace of this grammar, as in `Tool::<name>::Action`.
    pub fn name(&self) -> &str {
        &self.grammar.name
    }

    /// The name of the program whose command lines this grammar reads.
    pub fn program(&self) -> &str {
        &self.grammar.program
    }

    pub(crate) fn grammar(&self) -> &Arc<Grammar> {
        &self.grammar
    }
}

/// The tool grammars of one box, no two with one name or one program.
#[derive(Debug, Clone, Default)]
pub struct ToolGrammars(Vec<ToolGrammar>);

impl ToolGrammars {
    /// Hold `grammars`, or refuse two that share a name or a program.
    pub fn new(grammars: Vec<ToolGrammar>) -> Result<Self, ToolGrammarError> {
        for (index, first) in grammars.iter().enumerate() {
            for second in &grammars[index + 1..] {
                let refusal = if first.name() == second.name() {
                    Refusal::NamedTwice {
                        name: first.name().to_string(),
                        first: first.table.clone(),
                        second: second.table.clone(),
                    }
                } else if first.program() == second.program() {
                    Refusal::ProgramTwice {
                        program: first.program().to_string(),
                        first: first.table.clone(),
                        second: second.table.clone(),
                    }
                } else {
                    continue;
                };
                return Err(ToolGrammarError(Box::new(refusal)));
            }
        }
        Ok(Self(grammars))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &ToolGrammar> {
        self.0.iter()
    }

    /// The schema fragment of each grammar, in order.
    pub(crate) fn schemas(&self) -> Vec<String> {
        self.iter().map(|tool| tool.grammar.schema()).collect()
    }

    /// The canonical action schema with the actions of each grammar and of each `(server,
    /// schema)` pair in `generated`, as [`compose_action_schema`](crate::compose_action_schema)
    /// composes it.
    pub fn compose_action_schema(
        &self,
        generated: &[(&str, &str)],
    ) -> Result<String, crate::McpSchemaError> {
        crate::mcp_schema::validate_mcp_schema_composition(generated)?;
        let fragments = generated
            .iter()
            .map(|(_, source)| (*source).to_string())
            .collect::<Vec<_>>();
        crate::schema::composed_action_schema(&self.schemas(), &fragments)
            .map(|schema| schema.source)
            .map_err(|source| crate::McpSchemaError::Composition {
                reason: source.to_string(),
            })
    }
}

#[cfg(test)]
impl ToolGrammars {
    /// The grammars `tests/grammars/valid/<name>.grammar.toml`, each at `tool.<name>.grammar`.
    pub(crate) fn corpus(names: &[&str]) -> Self {
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/grammars/valid");
        let grammars = names
            .iter()
            .map(|name| {
                let text = std::fs::read_to_string(corpus.join(format!("{name}.grammar.toml")))
                    .expect("a grammar");
                let table: toml::Table = toml::from_str(&text).expect("a table");
                ToolGrammar::from_table(table, &format!("tool.{name}.grammar")).expect("a grammar")
            })
            .collect();
        Self::new(grammars).expect("distinct grammars")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grammar(table_key: &str, name: &str, program: &str) -> ToolGrammar {
        let table: toml::Table = toml::from_str(&format!(
            "format = 1\nversion = 1\nname = {name:?}\nprogram = {program:?}\n"
        ))
        .expect("the table parses");
        ToolGrammar::from_table(table, table_key).expect("the grammar loads")
    }

    #[test]
    fn two_grammars_with_one_name_are_refused_with_both_tables() {
        let error = ToolGrammars::new(vec![
            grammar("tool.git.grammar", "git", "git"),
            grammar("tool.hub.grammar", "git", "hub"),
        ])
        .expect_err("the set is refused");

        assert_eq!(
            error.to_string(),
            "`tool.git.grammar` and `tool.hub.grammar` both have `name = \"git\"`; give each \
             grammar its own name"
        );
    }

    #[test]
    fn two_grammars_with_one_name_are_refused_in_any_order() {
        let git = |table: &str| grammar(table, "git", "git");
        let cargo = || grammar("tool.cargo.grammar", "cargo", "cargo");
        for (case, grammars) in [
            (
                "alone",
                vec![git("tool.git.grammar"), git("tool.hub.grammar")],
            ),
            (
                "around another grammar",
                vec![git("tool.git.grammar"), cargo(), git("tool.hub.grammar")],
            ),
            (
                "before another grammar",
                vec![git("tool.git.grammar"), git("tool.hub.grammar"), cargo()],
            ),
            (
                "after another grammar",
                vec![cargo(), git("tool.git.grammar"), git("tool.hub.grammar")],
            ),
        ] {
            assert_eq!(
                ToolGrammars::new(grammars)
                    .expect_err("the set is refused")
                    .to_string(),
                "`tool.git.grammar` and `tool.hub.grammar` both have `name = \"git\"`; give each \
                 grammar its own name",
                "{case}"
            );
        }
    }

    #[test]
    fn two_grammars_with_one_program_are_refused_with_both_tables() {
        let error = ToolGrammars::new(vec![
            grammar("tool.git.grammar", "git", "git"),
            grammar("tool.brew_git.grammar", "brew_git", "git"),
        ])
        .expect_err("the set is refused");

        assert_eq!(
            error.to_string(),
            "`tool.git.grammar` and `tool.brew_git.grammar` both have `program = \"git\"`; keep \
             one grammar for each program"
        );
    }

    #[test]
    fn grammars_with_distinct_names_and_programs_install() {
        let grammars = ToolGrammars::new(vec![
            grammar("tool.git.grammar", "git", "git"),
            grammar("tool.cargo.grammar", "cargo", "cargo"),
        ])
        .expect("the set installs");

        assert_eq!(grammars.schemas().len(), 2);
    }
}
