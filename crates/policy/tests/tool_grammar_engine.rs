//! A tool grammar installed through the engine opener that a box uses.

use std::fs::File;
use std::path::{Path, PathBuf};

use policy::{
    Operator, Policy, PolicyEngine, PolicyError, PolicyStagingError, SchemaStage, ToolGrammar,
    ToolGrammars, generate_mcp_schema,
};

const GIT_GRAMMAR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/grammars/valid/git.grammar.toml"
);

const FORBID_PUSH: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
forbid(principal, action == Tool::git::Action::"push", resource);
"#;

fn source(text: &str) -> Vec<Policy> {
    vec![Policy {
        origin: PathBuf::from("policy.dw"),
        text: text.to_string(),
    }]
}

fn git() -> ToolGrammars {
    let text = std::fs::read_to_string(GIT_GRAMMAR).expect("the git grammar reads");
    let table: toml::Table = toml::from_str(&text).expect("the git grammar parses");
    let grammar =
        ToolGrammar::from_table(table, "tool.git.grammar").expect("the git grammar loads");
    ToolGrammars::new(vec![grammar]).expect("one grammar installs")
}

fn history(directory: &Path) -> (File, PathBuf) {
    let path = directory.join("dogwood.redb");
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .expect("the history file opens");
    (file, path)
}

fn open(sources: Vec<Policy>, grammars: ToolGrammars) -> Result<PolicyEngine, PolicyStagingError> {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let (file, path) = history(directory.path());
    PolicyEngine::open_staged_file_with_grammars(
        &Operator::unanchored(),
        sources,
        grammars,
        file,
        path,
    )
}

#[test]
fn a_policy_that_names_a_grammar_action_opens_with_its_grammar() {
    let engine = open(source(FORBID_PUSH), git()).expect("the policy opens with its grammar");

    engine
        .reload(&source(FORBID_PUSH))
        .expect("a reload keeps the grammar schema");
}

#[test]
fn the_same_policy_without_its_grammar_is_refused_at_open() {
    let error = open(source(FORBID_PUSH), ToolGrammars::default())
        .expect_err("no grammar declares the action");

    assert!(
        matches!(
            error,
            PolicyStagingError::Policy(PolicyError::UnknownAction(_))
        ),
        "{error}"
    );
}

#[test]
fn a_grammar_action_rule_is_refused_rather_than_held_for_an_mcp_schema() {
    let policy = format!(
        "{FORBID_PUSH}\npermit(principal, action == Box::Action::\"mcp:call\", resource);\n\
         forbid(principal, action == alpha::Action::\"deploy\", resource);\n"
    );

    let error = open(source(&policy), ToolGrammars::default())
        .expect_err("an MCP schema can never declare a tool grammar action");

    assert!(error.to_string().contains("Tool::git"), "{error}");
}

#[test]
fn an_mcp_schema_stages_over_the_grammar_schema() {
    let policy = format!(
        "{FORBID_PUSH}\npermit(principal, action == Box::Action::\"mcp:call\", resource);\n\
         forbid(principal, action == alpha::Action::\"deploy\", resource);\n"
    );
    let engine = open(source(&policy), git()).expect("the grammar rule loads, the MCP rule waits");
    let fragment = generate_mcp_schema(
        "alpha",
        r#"{"result": {"tools": [{"name": "deploy", "inputSchema": {"type": "object"}}]}}"#,
    )
    .expect("the MCP schema generates");

    assert_eq!(
        engine
            .stage_mcp_schema("alpha", fragment)
            .expect("staging is not a terminal fault"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
}

#[test]
fn validation_reads_the_grammar_schema() {
    let operator = Operator::unanchored();

    PolicyEngine::validate_with_grammars(&operator, &source(FORBID_PUSH), &git())
        .expect("the grammar declares the action");
    assert!(matches!(
        PolicyEngine::validate_with_grammars(
            &operator,
            &source(FORBID_PUSH),
            &ToolGrammars::default()
        ),
        Err(PolicyError::UnknownAction(_))
    ));
}

#[test]
fn the_grammar_and_the_rule_the_configuration_page_shows_load() {
    let page = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/user/config.md"
    ))
    .expect("the configuration page reads");
    let section = page
        .split_once("## `[tool.<name>.grammar]`")
        .expect("the page has the grammar section")
        .1;
    let block = |fence: &str| {
        section
            .split_once(fence)
            .and_then(|(_, rest)| rest.split_once("```"))
            .map(|(body, _)| body.to_string())
            .expect("the section shows the block")
    };
    let document: toml::Table = toml::from_str(&block("```toml\n")).expect("the example parses");
    let table = document["tool"]["git"]["grammar"]
        .as_table()
        .expect("the example holds `[tool.git.grammar]`")
        .clone();
    let grammar = ToolGrammar::from_table(table, "tool.git.grammar").expect("the example loads");
    let grammars = ToolGrammars::new(vec![grammar]).expect("one grammar installs");

    PolicyEngine::validate_with_grammars(
        &Operator::unanchored(),
        &source(&block("```dw\n")),
        &grammars,
    )
    .expect("the example rule validates against the example grammar");
}
