//! A rule whose only action is reserved, two rules with one `@id`, or a cap written as a permit
//! beside a broader permit, refuse the load.

mod support;

use std::path::PathBuf;

use policy::{Operator, Policy, PolicyEngine, PolicyError, PolicyStagingError};

fn source(text: &str) -> Policy {
    Policy {
        origin: PathBuf::from("load-time-rule-checks.dw"),
        text: text.to_string(),
    }
}

fn open(text: &str) -> Result<PolicyEngine, PolicyError> {
    support::open_policy(vec![source(text)])
}

fn validate(text: &str) -> Result<(), PolicyError> {
    PolicyEngine::validate(&Operator::unanchored(), &[source(text)])
}

const RESERVED_ACTION: &str = r#"
    permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
    @id("other-only")
    permit(principal == Box::Agent::"self", action == Box::Action::"fs:other", resource);
"#;

fn reserved_action_refusal(result: Result<(), PolicyError>) -> String {
    match result {
        Err(PolicyError::ReservedAction(reason)) => reason,
        Err(other) => panic!("expected a reserved-action refusal, got {other}"),
        Ok(()) => panic!("a rule whose only action is fs:other must refuse the load"),
    }
}

#[test]
fn a_rule_naming_only_fs_other_is_refused_and_the_refusal_names_the_rule() {
    let reason = reserved_action_refusal(validate(RESERVED_ACTION));
    assert_eq!(
        reason,
        "rule @id(\"other-only\") (rule 2) names only the reserved action \"fs:other\"; no \
         operation raises it, so the rule cannot match; name fs:read, fs:write, fs:delete, or \
         fs:move, alone or beside fs:other"
    );
    assert_eq!(
        reserved_action_refusal(open(RESERVED_ACTION).map(|_| ())),
        reason
    );
    assert_eq!(
        PolicyError::ReservedAction(reason).to_string(),
        "policy names only a reserved action: rule @id(\"other-only\") (rule 2) names only the \
         reserved action \"fs:other\"; no operation raises it, so the rule cannot match; name \
         fs:read, fs:write, fs:delete, or fs:move, alone or beside fs:other"
    );

    let unnamed_list = reserved_action_refusal(validate(
        r#"forbid(principal, action in [Box::Action::"fs:other"], resource);"#,
    ));
    assert!(
        unnamed_list.starts_with("the forbid rule with no @id (rule 1) names only"),
        "{unnamed_list}"
    );
}

#[test]
fn a_rule_listing_fs_other_beside_a_raised_action_loads_with_no_warning() {
    let engine = open(
        r#"@id("every_fs_action")
        forbid(principal, action in [
            Box::Action::"fs:read", Box::Action::"fs:write", Box::Action::"fs:delete",
            Box::Action::"fs:move", Box::Action::"fs:other"
        ], resource)
        when { context.input.path like "~/.aws/*" };
        permit(principal, action == Box::Action::"fs:write", resource);"#,
    )
    .expect("the policy loads");
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
}

const SHARED_ID: &str = r#"
    permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
    permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
    @id("workspace_read")
    forbid(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
      when { context.input.path == "/home/lash/secret-a" };
    @id("workspace_read")
    forbid(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
      when { context.input.path == "/home/lash/secret-b" };
"#;

fn shared_id_refusal(result: Result<(), PolicyError>) -> String {
    match result {
        Err(PolicyError::SharedRuleId(reason)) => reason,
        Err(other) => panic!("expected a shared-id refusal, got {other}"),
        Ok(()) => panic!("two rules with one @id must refuse the load"),
    }
}

#[test]
fn two_rules_with_one_id_are_refused_and_the_refusal_names_both_rules() {
    let reason = shared_id_refusal(validate(SHARED_ID));
    assert_eq!(
        reason,
        "@id(\"workspace_read\") is on rules 3, 4; a denial and a telemetry record name a rule \
         by its @id, so give each rule its own @id"
    );
    let error = shared_id_refusal(open(SHARED_ID).map(|_| ()));
    assert_eq!(error, reason);
    assert_eq!(
        PolicyError::SharedRuleId(reason).to_string(),
        "policy gives one @id to more than one rule: @id(\"workspace_read\") is on rules 3, 4; \
         a denial and a telemetry record name a rule by its @id, so give each rule its own @id"
    );
}

#[test]
fn every_shared_id_is_named_with_every_rule_that_carries_it() {
    let reason = shared_id_refusal(validate(
        r#"@id("a") permit(principal, action, resource);
           @id("b") permit(principal, action, resource);
           @id("a") permit(principal, action, resource);
           @id("b") permit(principal, action, resource);
           @id("a") permit(principal, action, resource);"#,
    ));
    assert!(
        reason.starts_with("@id(\"a\") is on rules 1, 3, 5; @id(\"b\") is on rules 2, 4;"),
        "{reason}"
    );
}

#[test]
fn the_staged_load_path_refuses_one_id_on_two_rules_and_counts_every_authored_rule() {
    let history = tempfile::tempdir().expect("history directory");
    let result = PolicyEngine::open_staged(
        &Operator::unanchored(),
        vec![source(
            r#"permit(principal, action == Box::Action::"shell:exec", resource);
               permit(principal, action == Box::Action::"mcp:call", resource);
               permit(principal, action == alpha::Action::"read", resource);
               @id("x") permit(principal, action == Box::Action::"fs:read", resource);
               @id("x") permit(principal, action == Box::Action::"fs:write", resource);"#,
        )],
        &history.path().join("dogwood.redb"),
    );
    match result {
        Err(PolicyStagingError::Policy(PolicyError::SharedRuleId(reason))) => {
            assert!(
                reason.starts_with("@id(\"x\") is on rules 4, 5;"),
                "{reason}"
            );
        }
        Err(other) => panic!("expected a shared-id refusal, got {other}"),
        Ok(_) => panic!("two rules with one @id must refuse the staged load"),
    }

    let history = tempfile::tempdir().expect("history directory");
    let result = PolicyEngine::open_staged(
        &Operator::unanchored(),
        vec![source(
            r#"permit(principal, action == Box::Action::"shell:exec", resource);
               permit(principal, action == alpha::Action::"read", resource);
               @id("inert") permit(principal, action == Box::Action::"fs:other", resource);"#,
        )],
        &history.path().join("dogwood.redb"),
    );
    match result {
        Err(PolicyStagingError::Policy(PolicyError::ReservedAction(reason))) => {
            assert!(
                reason.starts_with("rule @id(\"inert\") (rule 3) names only"),
                "{reason}"
            );
        }
        Err(other) => panic!("expected a reserved-action refusal, got {other}"),
        Ok(_) => panic!("a rule whose only action is fs:other must refuse the staged load"),
    }
}

#[test]
fn distinct_ids_load_and_blank_or_absent_ids_never_conflict() {
    let distinct = SHARED_ID.replacen("workspace_read", "secret_a", 1);
    validate(&distinct).expect("distinct ids validate");
    let engine = open(&distinct).expect("distinct ids load");
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());

    let blank = r#"
        @id("") permit(principal, action == Box::Action::"fs:read", resource);
        @id("") permit(principal, action == Box::Action::"fs:write", resource);
        @id(" \t") permit(principal, action == Box::Action::"fs:delete", resource);
        permit(principal, action == Box::Action::"fs:move", resource);
        permit(principal, action == Box::Action::"shell:exec", resource);
    "#;
    validate(blank).expect("blank ids validate");
    assert!(open(blank).expect("blank ids load").warnings().is_empty());
}

/// The content writes completed in the last hour, as a temporal count compared with `{op}`.
fn completed_writes(comparison: &str) -> String {
    format!(
        r#"exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 3600s (
                Box::Action::"fs:write"::response{{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" }} && tp(t)
            )
        )) == total && total {comparison}
    )"#
    )
}

fn permit_shaped_cap(id: &str) -> String {
    format!(
        r#"@id("{id}")
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {{ {} }};"#,
        completed_writes("< 3")
    )
}

fn inert_cap_refusal(result: Result<(), PolicyError>) -> String {
    match result {
        Err(PolicyError::InertTemporalPermit(reason)) => reason,
        Err(other) => panic!("expected an inert-cap refusal, got {other}"),
        Ok(()) => panic!("a cap written as a permit beside a broader permit must refuse the load"),
    }
}

#[test]
fn a_temporal_permit_beside_an_unconditioned_permit_for_its_action_is_refused_and_both_are_named() {
    let source = format!(
        r#"@id("writes")
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
{}"#,
        permit_shaped_cap("write_budget")
    );
    let reason = inert_cap_refusal(validate(&source));
    assert_eq!(
        reason,
        "rule @id(\"write_budget\") (rule 2) carries a temporal clause beside rule @id(\"writes\") \
         (rule 1), which permits the same action with no condition; a permit cannot narrow another \
         permit, so write the cap as a forbid"
    );
    assert_eq!(inert_cap_refusal(open(&source).map(|_| ())), reason);
    assert_eq!(
        PolicyError::InertTemporalPermit(reason).to_string(),
        "policy writes a cap as a permit: rule @id(\"write_budget\") (rule 2) carries a temporal \
         clause beside rule @id(\"writes\") (rule 1), which permits the same action with no \
         condition; a permit cannot narrow another permit, so write the cap as a forbid"
    );

    // An unconstrained scope covers the budgeted action, and a rule with no `@id` is named by its
    // position.
    let covered_by_a_catch_all = format!(
        r#"permit(principal, action, resource);
{}"#,
        permit_shaped_cap("write_budget")
    );
    let reason = inert_cap_refusal(validate(&covered_by_a_catch_all));
    assert!(
        reason.starts_with(
            "rule @id(\"write_budget\") (rule 2) carries a temporal clause beside the permit rule \
             with no @id (rule 1), which permits the same action with no condition;"
        ),
        "{reason}"
    );
}

#[test]
fn a_temporal_permit_alone_loads_with_no_warning() {
    let engine = open(&permit_shaped_cap("write_budget")).expect("a lone temporal permit loads");
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
}

#[test]
fn a_temporal_permit_beside_an_unconditioned_permit_for_another_action_loads_with_no_warning() {
    let source = format!(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
{}"#,
        permit_shaped_cap("write_budget")
    );
    let engine = open(&source).expect("different actions do not cover the budget");
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
}

#[test]
fn a_temporal_permit_beside_a_conditioned_permit_for_its_action_loads_with_a_warning() {
    let source = format!(
        r#"@id("project_writes")
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when {{ context.input.path like "~/project/*" }};
{}"#,
        permit_shaped_cap("write_budget")
    );
    validate(&source).expect("the heuristic shape validates");
    let engine = open(&source).expect("the heuristic shape loads");
    let warnings: Vec<String> = engine.warnings().iter().map(ToString::to_string).collect();
    assert_eq!(
        warnings,
        vec![
            "rule @id(\"write_budget\") (rule 2) carries a temporal clause beside rule \
             @id(\"project_writes\") (rule 1), which also permits that action; the budget is inert \
             for every request the other rule admits, so write a cap as a forbid"
                .to_string()
        ]
    );
}

#[test]
fn a_cap_written_as_a_forbid_beside_an_unconditioned_permit_loads_with_no_warning() {
    let source = format!(
        r#"@id("writes")
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
@id("write_cap")
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {{ {} }};"#,
        completed_writes(">= 3")
    );
    validate(&source).expect("the recommended shape validates");
    let engine = open(&source).expect("the recommended shape loads");
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
}

#[test]
fn the_inert_cap_refusal_fires_before_the_engine_opens_the_history() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let source = format!(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
{}"#,
        permit_shaped_cap("write_budget")
    );
    let opened = PolicyEngine::open(vec![self::source(&source)], &path);
    inert_cap_refusal(opened.map(|_| ()));
    assert!(
        !path.exists(),
        "a refused load must not create the history file"
    );

    let staged = PolicyEngine::open_staged(
        &Operator::unanchored(),
        vec![self::source(&format!(
            r#"permit(principal, action == alpha::Action::"read", resource);
{source}"#
        ))],
        &path,
    );
    match staged {
        Err(PolicyStagingError::Policy(PolicyError::InertTemporalPermit(reason))) => {
            assert!(
                reason.starts_with("rule @id(\"write_budget\") (rule 3) carries a temporal clause"),
                "{reason}"
            );
        }
        Err(other) => panic!("expected an inert-cap refusal, got {other}"),
        Ok(_) => panic!("the staged load must refuse a cap written as a permit"),
    }
}

#[test]
fn a_sibling_whose_resource_coverage_is_undecided_warns_and_does_not_refuse() {
    let source = format!(
        r#"@id("one_resource")
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource == Box::Resource::"unused");
{}"#,
        permit_shaped_cap("write_budget")
    );
    validate(&source).expect("an undecided resource scope does not refuse");
    let engine = open(&source).expect("an undecided resource scope loads");
    let warnings: Vec<String> = engine.warnings().iter().map(ToString::to_string).collect();
    assert_eq!(
        warnings,
        vec![
            "rule @id(\"write_budget\") (rule 2) carries a temporal clause beside rule \
             @id(\"one_resource\") (rule 1), which also permits that action; the budget is inert \
             for every request the other rule admits, so write a cap as a forbid"
                .to_string()
        ]
    );
}

#[test]
fn a_temporal_permit_beside_an_unconditioned_permit_for_another_principal_loads_with_no_warning() {
    let source = format!(
        r#"permit(principal == Box::Agent::"other", action == Box::Action::"fs:write", resource);
{}"#,
        permit_shaped_cap("write_budget")
    );
    validate(&source).expect("another principal does not cover the budget");
    let engine = open(&source).expect("another principal loads");
    assert!(engine.warnings().is_empty(), "{:?}", engine.warnings());
}
