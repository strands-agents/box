//! `strands_box::check_policy` reads the policy a configuration selects, as `run` reads it.

use std::path::{Path, PathBuf};

const UNKNOWN_ACTION: &str = "// mine\n\n@id(\"run\") permit (principal, action == Box::Action::\"shell:exce\", resource);\n";

const TYPED: &str =
    "@id(\"tool\") permit (principal, action == alpha::Action::\"read\", resource);\n";

/// Write `box.toml` with `extra` lines under its required keys, and `policy.dw` beside it.
fn configuration(directory: &Path, extra: &str, policy: Option<&str>) -> PathBuf {
    let config = directory.join("box.toml");
    let box_dir = directory.join("box");
    std::fs::write(
        &config,
        format!(
            "name = \"check\"\nbox_dir = \"{}\"\n{extra}",
            box_dir.display()
        ),
    )
    .expect("write box.toml");
    if let Some(policy) = policy {
        std::fs::write(directory.join("policy.dw"), policy).expect("write policy.dw");
    }
    config
}

#[test]
fn a_check_names_the_line_rule_and_hint_of_an_unknown_action() {
    let directory = tempfile::tempdir().expect("a directory");
    let config = configuration(
        directory.path(),
        "policy = \"policy.dw\"\n",
        Some(UNKNOWN_ACTION),
    );
    let check = strands_box::check_policy(config).expect("the check runs");
    let finding = &check.errors()[0];
    let location = finding.location().expect("a location");
    assert_eq!((location.line(), location.column()), (3, 41));
    assert_eq!(
        finding.help(),
        Some("did you mean `Box::Action::\"shell:exec\"`?")
    );
    assert_eq!(finding.rules()[0].id(), Some("run"));
}

#[test]
fn a_check_writes_nothing() {
    let directory = tempfile::tempdir().expect("a directory");
    let config = configuration(
        directory.path(),
        "policy = \"policy.dw\"\n",
        Some(UNKNOWN_ACTION),
    );
    strands_box::check_policy(config).expect("the check runs");
    assert!(
        !directory.path().join("box").exists(),
        "no box_dir is created"
    );
}

#[test]
fn a_configuration_with_no_policy_has_no_findings() {
    let directory = tempfile::tempdir().expect("a directory");
    let config = configuration(directory.path(), "", None);
    let check = strands_box::check_policy(config).expect("the check runs");
    assert!(check.errors().is_empty() && check.warnings().is_empty());
}

#[test]
fn a_per_tool_rule_is_unchecked_only_when_a_local_mcp_server_is_declared() {
    let directory = tempfile::tempdir().expect("a directory");
    let config = configuration(
        directory.path(),
        "policy = \"policy.dw\"\n[mcp.alpha]\ntype = \"stdio\"\ncommand = [\"fake-alpha-mcp\"]\n",
        Some(TYPED),
    );
    let check = strands_box::check_policy(config).expect("the check runs");
    assert!(check.errors().is_empty(), "{:?}", check.errors());
    assert_eq!(check.unchecked()[0].id(), Some("tool"));

    let directory = tempfile::tempdir().expect("a directory");
    let config = configuration(directory.path(), "policy = \"policy.dw\"\n", Some(TYPED));
    let check = strands_box::check_policy(config).expect("the check runs");
    assert!(!check.errors().is_empty(), "no server: the rule is unknown");
}

#[test]
fn a_check_that_cannot_read_its_files_fails() {
    let directory = tempfile::tempdir().expect("a directory");
    assert!(strands_box::check_policy(directory.path().join("missing.toml")).is_err());
    let config = configuration(directory.path(), "policy = \"absent.dw\"\n", None);
    let failed = strands_box::check_policy(config).expect_err("no policy file");
    assert!(failed.to_string().contains("absent.dw"), "{failed}");
}
