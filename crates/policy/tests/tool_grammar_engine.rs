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

const MIXED: &str = r#"
permit(principal, action == Box::Action::"mcp:call", resource);
forbid(principal, action in [alpha::Action::"deploy", Tool::git::Action::"push"], resource);
"#;

#[test]
fn a_rule_that_also_names_an_mcp_action_is_refused_when_no_grammar_declares_its_tool_action() {
    let error = open(source(MIXED), ToolGrammars::default())
        .expect_err("an MCP schema can never declare the tool grammar action");

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
fn a_check_reads_the_grammar_schema_in_both_load_modes() {
    let operator = Operator::unanchored();

    for complete in [true, false] {
        let with =
            PolicyEngine::check_with_grammars(&operator, &source(FORBID_PUSH), complete, &git());
        let without = PolicyEngine::check_with_grammars(
            &operator,
            &source(FORBID_PUSH),
            complete,
            &ToolGrammars::default(),
        );

        assert!(with.errors().is_empty(), "{:?}", with.errors());
        assert!(!without.errors().is_empty(), "complete = {complete}");
    }
}
