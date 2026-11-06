//! `box.toml`'s `[tool.<name>.grammar]` tables, read into the tool grammars a box installs.

use std::collections::BTreeMap;
use std::path::Path;

use policy::{ToolGrammar, ToolGrammars};
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

use super::process::ProcessSpec;

/// The policy namespace of every tool grammar action, which no `[mcp.<name>]` takes while
/// `tool-grammars` is on.
pub(crate) const TOOL_GRAMMAR_NAMESPACE: &str = "Tool";

/// One `[tool.<name>.grammar]` table, as the operator wrote it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct GrammarTable(toml::Table);

impl Eq for GrammarTable {}

/// The name a `[tool]` command runs its program by: the last component of `command` element 0.
pub(crate) fn called_name(spec: &ProcessSpec) -> &str {
    let program = spec.program();
    Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
}

/// The grammar of each `[tool.<label>]` in `tools`, checked, with no two that share a name or a
/// program. A grammar whose `program` is not the name its own `[tool]` runs is refused.
pub(crate) fn tool_grammars(
    tools: &BTreeMap<String, ProcessSpec>,
) -> Result<ToolGrammars, ConfigError> {
    let mut grammars = Vec::new();
    for (label, spec) in tools {
        let Some(GrammarTable(table)) = &spec.grammar else {
            continue;
        };
        let table_key = format!("tool.{}.grammar", key_segment(label));
        let grammar = ToolGrammar::from_table(table.clone(), &table_key)
            .map_err(|source| ConfigError::ToolGrammar { source })?;
        let called = called_name(spec);
        if grammar.program() != called {
            return Err(ConfigError::Process {
                table: format!("[tool.{label}]"),
                reason: format!(
                    "`{table_key}.program` is {:?}, but `command` runs {called:?}; a grammar \
                     reads only the program its own tool runs, so set `program = {called:?}` or \
                     move the grammar to the tool that runs {:?}",
                    grammar.program(),
                    grammar.program(),
                ),
            });
        }
        grammars.push(grammar);
    }
    ToolGrammars::new(grammars).map_err(|source| ConfigError::ToolGrammar { source })
}

/// One TOML key, bare when TOML reads it bare and quoted otherwise.
fn key_segment(label: &str) -> String {
    if label
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        label.to_string()
    } else {
        format!("{label:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIT: &str = r#"
format = 1
version = 1
name = "git"
program = "git"
[shell.push]
usage = "git push [<remote>]"
"#;

    fn tool(command: &str, grammar: Option<&str>) -> ProcessSpec {
        let mut text = format!("command = [{command:?}]\n");
        if let Some(grammar) = grammar {
            let table: toml::Table = toml::from_str(grammar).expect("the grammar parses");
            text.push_str(
                &toml::to_string(&toml::Table::from_iter([(
                    "grammar".to_string(),
                    toml::Value::Table(table),
                )]))
                .expect("the grammar writes"),
            );
        }
        toml::from_str(&text).expect("the tool parses")
    }

    fn tools(entries: &[(&str, ProcessSpec)]) -> BTreeMap<String, ProcessSpec> {
        entries
            .iter()
            .map(|(label, spec)| ((*label).to_string(), spec.clone()))
            .collect()
    }

    #[test]
    fn a_grammar_loads_from_its_tool_table() {
        let grammars = tool_grammars(&tools(&[("git", tool("/usr/bin/git", Some(GIT)))]))
            .expect("the grammar loads");
        let policy = policy::Policy {
            origin: "policy.dw".into(),
            text: r#"forbid (principal, action == Tool::git::Action::"push", resource);"#.into(),
        };

        policy::PolicyEngine::validate_with_grammars(
            &policy::Operator::unanchored(),
            &[policy],
            &grammars,
        )
        .expect("the grammar declares its action");
    }

    #[test]
    fn a_grammar_whose_program_is_not_its_tools_called_name_is_refused() {
        let error = tool_grammars(&tools(&[("gh", tool("gh", Some(GIT)))]))
            .expect_err("the grammar cannot read gh");

        assert_eq!(
            error.to_string(),
            "invalid `[tool.gh]` table: `tool.gh.grammar.program` is \"git\", but `command` runs \
             \"gh\"; a grammar reads only the program its own tool runs, so set `program = \"gh\"` \
             or move the grammar to the tool that runs \"git\""
        );
    }

    #[test]
    fn two_grammars_for_one_program_are_refused() {
        let other = GIT.replace("name = \"git\"", "name = \"brew_git\"");

        let error = tool_grammars(&tools(&[
            ("git", tool("/usr/bin/git", Some(GIT))),
            ("brew_git", tool("/opt/homebrew/bin/git", Some(&other))),
        ]))
        .expect_err("two grammars name git");

        assert_eq!(
            error.to_string(),
            "tool grammar refused: `tool.brew_git.grammar` and `tool.git.grammar` both have \
             `program = \"git\"`; keep one grammar for each program"
        );
    }

    #[test]
    fn two_grammars_with_one_name_are_refused() {
        let other = GIT
            .replace("program = \"git\"", "program = \"hub\"")
            .replace("usage = \"git", "usage = \"hub");

        let error = tool_grammars(&tools(&[
            ("git", tool("/usr/bin/git", Some(GIT))),
            ("hub", tool("/usr/bin/hub", Some(&other))),
        ]))
        .expect_err("two grammars name git");

        assert_eq!(
            error.to_string(),
            "tool grammar refused: `tool.git.grammar` and `tool.hub.grammar` both have \
             `name = \"git\"`; give each grammar its own name"
        );
    }

    #[test]
    fn a_refusal_names_the_key_path_under_the_tool() {
        let broken = GIT.replace("git push [<remote>]", "git push [<remote>");

        let error = tool_grammars(&tools(&[("git", tool("git", Some(&broken)))]))
            .expect_err("the usage is broken");

        assert_eq!(
            error.to_string(),
            "tool grammar refused: `tool.git.grammar.shell.push.usage` has a `[` with no `]`"
        );
    }

    #[test]
    fn a_label_that_toml_quotes_is_quoted_in_the_key_path() {
        let broken = GIT.replace("version = 1", "version = 0");

        let error = tool_grammars(&tools(&[("git.v2", tool("git", Some(&broken)))]))
            .expect_err("the version is zero");

        assert!(
            error
                .to_string()
                .contains("`tool.\"git.v2\".grammar.version` is 0"),
            "{error}"
        );
    }
}
