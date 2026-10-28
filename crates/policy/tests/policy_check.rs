//! `PolicyEngine::check` refuses what a box refuses at open, and names each rule, line, and hint.

mod support;

use std::path::PathBuf;

use policy::{Operator, Policy, PolicyCheck, PolicyEngine};

fn source(text: &str) -> Policy {
    Policy {
        origin: PathBuf::from("policy-check.dw"),
        text: text.to_string(),
    }
}

fn check(text: &str) -> PolicyCheck {
    PolicyEngine::check(&Operator::unanchored(), &[source(text)], true)
}

fn check_staged(text: &str) -> PolicyCheck {
    PolicyEngine::check(&Operator::unanchored(), &[source(text)], false)
}

fn open_staged(text: &str) -> bool {
    let history = tempfile::tempdir().expect("history directory");
    PolicyEngine::open_staged(
        &Operator::unanchored(),
        vec![source(text)],
        &history.path().join("dogwood.redb"),
    )
    .is_ok()
}

const GOOD: &str =
    r#"@id("shell") permit (principal, action == Box::Action::"shell:exec", resource);"#;

const UNKNOWN_ACTION: &str = "// mine\n\n@id(\"run\") permit (principal, action == Box::Action::\"shell:exce\", resource);\n";

const UNKNOWN_FIELD: &str = "@id(\"a\") permit (principal, action == Box::Action::\"shell:exec\", resource);\n\
     @id(\"b\") permit (principal, action == Box::Action::\"fs:read\", resource) when { context.input.paht == \"/x\" };\n";

const PARSE: &str = "// mine\n\n@id(\"a\") permit (principal, action == , resource);\n";

const SHARED_ID: &str = "@id(\"x\") permit (principal, action == Box::Action::\"fs:read\", resource);\n\
     @id(\"x\") permit (principal, action == Box::Action::\"fs:write\", resource);\n";

const RESERVED: &str =
    "@id(\"other\") permit (principal, action == Box::Action::\"fs:other\", resource);\n";

const CAP_AS_PERMIT: &str = r#"@id("all") permit (principal, action == Box::Action::"fs:write", resource);

@id("cap")
permit (principal, action == Box::Action::"fs:write", resource)
when temporal {
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"fs:write"::response{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" } && tp(t)
            )
        )) == total
        && total < 6
    )
};
"#;

const SPELLING: &str = "@id(\"slash\") permit (principal, action == Box::Action::\"fs:read\", resource) when { context.input.path == \"/tmp/dir/\" };\n";

const TYPED: &str =
    "@id(\"tool\") permit (principal, action == alpha::Action::\"read\", resource);\n";

#[test]
fn an_unknown_action_names_its_rule_line_and_the_closest_action() {
    let check = check(UNKNOWN_ACTION);
    let finding = &check.errors()[0];
    let location = finding.location().expect("a location");
    assert_eq!((location.line(), location.column()), (3, 41));
    assert_eq!(
        finding.help(),
        Some("did you mean `Box::Action::\"shell:exec\"`?")
    );
    assert!(
        finding.message().starts_with("unrecognized action"),
        "{}",
        finding.message()
    );
    let rule = &finding.rules()[0];
    assert_eq!((rule.position(), rule.id()), (1, Some("run")));
}

#[test]
fn an_unknown_field_names_its_rule_line_and_the_closest_field() {
    let check = check(UNKNOWN_FIELD);
    let finding = &check.errors()[0];
    assert_eq!(finding.location().map(|location| location.line()), Some(2));
    assert_eq!(finding.help(), Some("did you mean `path`?"));
    let rule = &finding.rules()[0];
    assert_eq!((rule.position(), rule.id()), (2, Some("b")));
}

#[test]
fn a_parse_error_names_its_line() {
    let check = check(PARSE);
    let location = check.errors()[0].location().expect("a location");
    assert_eq!((location.line(), location.column()), (3, 39));
}

#[test]
fn one_id_on_two_rules_names_both_rules() {
    let check = check(SHARED_ID);
    let finding = &check.errors()[0];
    let rules: Vec<_> = finding
        .rules()
        .iter()
        .map(|rule| (rule.position(), rule.id()))
        .collect();
    assert_eq!(rules, [(1, Some("x")), (2, Some("x"))]);
    assert_eq!(finding.location(), None);
}

#[test]
fn a_cap_written_as_a_permit_names_the_cap_and_the_permit_beside_it() {
    let check = check(CAP_AS_PERMIT);
    let rules: Vec<_> = check.errors()[0]
        .rules()
        .iter()
        .map(|rule| (rule.position(), rule.id()))
        .collect();
    assert_eq!(rules, [(2, Some("cap")), (1, Some("all"))]);
}

#[test]
fn a_reserved_action_names_its_rule() {
    let check = check(RESERVED);
    let rule = &check.errors()[0].rules()[0];
    assert_eq!((rule.position(), rule.id()), (1, Some("other")));
}

#[test]
fn the_refusal_text_names_the_line_and_the_hint() {
    let refusal = PolicyEngine::validate(&Operator::unanchored(), &[source(UNKNOWN_ACTION)])
        .expect_err("an unknown action")
        .to_string();
    assert!(refusal.contains("at line 3, column 41"), "{refusal}");
    assert!(
        refusal.contains("(did you mean `Box::Action::\"shell:exec\"`?)"),
        "{refusal}"
    );
    let refusal = PolicyEngine::validate(&Operator::unanchored(), &[source(PARSE)])
        .expect_err("a parse error")
        .to_string();
    assert!(refusal.contains("at line 3, column 39"), "{refusal}");
}

#[test]
fn a_check_refuses_exactly_what_open_refuses() {
    for text in [
        GOOD,
        UNKNOWN_ACTION,
        UNKNOWN_FIELD,
        PARSE,
        SHARED_ID,
        RESERVED,
        CAP_AS_PERMIT,
        SPELLING,
        TYPED,
        "",
    ] {
        assert_eq!(
            check(text).errors().is_empty(),
            support::open_policy(vec![source(text)]).is_ok(),
            "{text}"
        );
    }
}

#[test]
fn a_staged_check_refuses_exactly_what_open_staged_refuses() {
    for text in [
        GOOD,
        UNKNOWN_ACTION,
        UNKNOWN_FIELD,
        PARSE,
        SHARED_ID,
        RESERVED,
        CAP_AS_PERMIT,
        SPELLING,
        TYPED,
    ] {
        let with_tool = format!("{text}\n{TYPED}");
        assert_eq!(
            check_staged(&with_tool).errors().is_empty(),
            open_staged(&with_tool),
            "{with_tool}"
        );
    }
}

#[test]
fn a_staged_check_lists_a_per_tool_rule_as_unchecked() {
    let check = check_staged(&format!("{GOOD}\n{TYPED}"));
    assert!(check.errors().is_empty(), "{:?}", check.errors());
    let unchecked: Vec<_> = check
        .unchecked()
        .iter()
        .map(|rule| (rule.position(), rule.id()))
        .collect();
    assert_eq!(unchecked, [(2, Some("tool"))]);
}

#[test]
fn a_staged_check_refuses_an_error_in_a_rule_over_the_fixed_vocabulary() {
    let check = check_staged(&format!("{TYPED}\n{UNKNOWN_ACTION}"));
    let finding = &check.errors()[0];
    let rule = &finding.rules()[0];
    assert_eq!((rule.position(), rule.id()), (2, Some("run")));
    assert_eq!(finding.location(), None);
}

#[test]
fn a_complete_check_refuses_a_per_tool_rule_with_no_server() {
    assert!(!check(TYPED).errors().is_empty());
}

#[test]
fn no_sources_load_with_no_findings() {
    let check = PolicyEngine::check(&Operator::unanchored(), &[], true);
    assert!(check.errors().is_empty() && check.warnings().is_empty());
}

#[test]
fn a_staged_refusal_names_no_line_because_its_text_is_not_the_authored_text() {
    let history = tempfile::tempdir().expect("history directory");
    let Err(refusal) = PolicyEngine::open_staged(
        &Operator::unanchored(),
        vec![source(&format!("{TYPED}\n{UNKNOWN_FIELD}"))],
        &history.path().join("dogwood.redb"),
    ) else {
        panic!("an unknown field refuses the staged load");
    };
    let refusal = refusal.to_string();
    assert!(!refusal.contains("at line"), "{refusal}");
}

#[test]
fn a_staged_check_numbers_each_rule_by_its_place_in_the_authored_policy() {
    let check = check_staged(&format!("{TYPED}\n{SHARED_ID}"));
    let rules: Vec<_> = check.errors()[0]
        .rules()
        .iter()
        .map(|rule| (rule.position(), rule.id()))
        .collect();
    assert_eq!(rules, [(2, Some("x")), (3, Some("x"))]);

    let check = check_staged(&format!("{TYPED}\n{GOOD}\n{UNKNOWN_FIELD}"));
    let rules: Vec<_> = check.errors()[0]
        .rules()
        .iter()
        .map(|rule| (rule.position(), rule.id()))
        .collect();
    assert_eq!(rules, [(4, Some("b"))]);
}

#[test]
fn a_check_of_two_sources_names_no_line() {
    let check = PolicyEngine::check(
        &Operator::unanchored(),
        &[source(GOOD), source(UNKNOWN_ACTION)],
        true,
    );
    assert_eq!(check.errors()[0].location(), None);
}

#[test]
fn an_inert_spelling_names_its_rule() {
    let check = check(&format!("{GOOD}\n{SPELLING}"));
    let finding = &check.errors()[0];
    assert!(
        finding.message().contains("trailing slash"),
        "{}",
        finding.message()
    );
    let rule = &finding.rules()[0];
    assert_eq!((rule.position(), rule.id()), (2, Some("slash")));
}

#[test]
fn a_finding_about_the_whole_rule_names_no_line() {
    let check = check(UNKNOWN_ACTION);
    let whole = check
        .errors()
        .iter()
        .find(|finding| {
            finding
                .message()
                .starts_with("unable to find an applicable action")
        })
        .expect("cedar names the rule's scope too");
    assert_eq!(whole.location(), None);
}
