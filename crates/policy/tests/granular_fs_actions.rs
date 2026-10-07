//! The filesystem action vocabulary: four customer-altitude verbs, and within-action
//! narrowing on the kernel operation
//! (docs/design/decisions.md#filesystem-authorization-uses-four-verbs-and-a-catch-all).
//!
//! Three properties are pinned here:
//!
//! 1. **`fs:read`, `fs:write`, `fs:delete`, and `fs:move` are real actions a rule names
//!    directly.** A customer reasons in four verbs, so a rule scopes to one with
//!    `action == Box::Action::"fs:read"`. There are no group actions.
//! 2. **A removed action name is a hard load error.** The fine per-verb names
//!    (`fs:read_content`, `fs:enumerate`, `fs:exec_file`, …) and the old group names
//!    (`net`, `shell`) are gone, so `Box::Action::"fs:read_content"` fails to load rather than
//!    loading and matching nothing — a silent no-match reading as "the rule did not apply"
//!    rather than "the rule names an action that does not exist".
//! 3. **`context.input.operation` narrows within a coarse action.** The kernel's exact
//!    verb rides `operation`, so "enumerate a directory but do not read the files in it"
//!    stays writable as `permit fs:read when operation == Box::FsReadOperation::"enumerate"`.

mod support;

use std::path::{Path, PathBuf};

use policy::{
    ApprovedPath, Decision, FsOperation, GovernedBox, PathResolver, Policy, PolicyEngine,
    PolicyError, Principal, Request,
};

/// Mint the `ApprovedPath` a `Request::Fs` now demands.
///
/// `PathResolver` is the only public minter, and every path here is synthetic — so the
/// resolver runs in the **virtual** namespace: it closes `.` and `..`, checks the declared
/// roots, and touches no filesystem. The two roots are the trees these fixtures name.
fn approved(path: &str) -> ApprovedPath {
    PathResolver::over([PathBuf::from("/home"), PathBuf::from("/Users")])
        .expect("both roots are absolute")
        .approve_virtual(Path::new(path))
        .unwrap_or_else(|refusal| panic!("a fixture path must resolve: {refusal}"))
}

fn open(source: &str) -> Result<PolicyEngine, PolicyError> {
    support::open_policy(vec![Policy {
        origin: PathBuf::from("granular-fs.dw"),
        text: source.to_string(),
    }])
}

fn loaded(source: &str) -> PolicyEngine {
    open(source).expect("policy loads")
}

fn allows(
    policy: &PolicyEngine,
    principal: &Principal,
    operation: FsOperation,
    path: &str,
) -> bool {
    let approved = approved(path);
    matches!(
        policy.decide(
            &GovernedBox::assigned("test-box"),
            principal,
            &Request::Fs {
                path: &approved,
                operation,
            },
        ),
        Decision::Allow { .. }
    )
}

/// Every read operation, as a rule author meets them. Each rides `fs:read`,
/// including the executability probe, which is a metadata disclosure.
const READS: &[FsOperation] = &[
    FsOperation::ReadContent,
    FsOperation::ReadMetadata,
    FsOperation::Enumerate,
    FsOperation::ReadLink,
    FsOperation::ChangeDir,
    FsOperation::ExecFile,
];

/// Every write operation. Each rides `fs:write` — content writes, directory creation,
/// permission changes, and symlink creation. Removal and rename are their own verbs.
const WRITES: &[FsOperation] = &[
    FsOperation::WriteContent,
    FsOperation::CreateDir,
    FsOperation::Symlink,
    FsOperation::SetPermissions,
];

#[test]
fn the_four_verbs_are_real_actions_a_rule_names_directly() {
    // Each customer verb loads with the `==` form and grants a representative operation.
    // A group would not be a real action, so this would fail to load; these do.
    let shell = Principal::agent();
    let cases = [
        ("fs:read", FsOperation::ReadContent),
        ("fs:write", FsOperation::WriteContent),
        ("fs:delete", FsOperation::RemoveFile),
        ("fs:move", FsOperation::Rename),
    ];
    for (verb, operation) in cases {
        let policy = loaded(&format!(
            r#"permit(principal == Box::Agent::"self", action == Box::Action::"{verb}", resource);"#
        ));
        assert!(
            allows(&policy, &shell, operation, "/home/strands-box/a.txt"),
            "{verb} must grant {operation:?}"
        );
    }
}

#[test]
fn a_removed_action_name_is_a_hard_load_error() {
    // The fine per-verb names and the old group names no longer exist, so naming one is a
    // load error, not a rule that quietly matches nothing. `lower()` alone would accept a
    // typo'd action; strict validation refuses it and names the fault.
    for removed in [
        "fs:read_content",
        "fs:enumerate",
        "fs:set_permissions",
        "fs:exec_file",
        "fs:exec",
        "net",
        "shell",
    ] {
        let source = format!(
            r#"permit(principal == Box::Agent::"self", action == Box::Action::"{removed}", resource);"#
        );
        let error = open(&source).expect_err("a removed action name must not load");
        // Cedar reports it as "unable to find an applicable action"; the crate maps a
        // failed validation to `Schema` or `UnknownAction`. Either way it is a hard load
        // error.
        assert!(
            matches!(
                error,
                PolicyError::Schema(_) | PolicyError::UnknownAction(_)
            ),
            "expected a load error naming the schema fault for `{removed}`, got {error:?}"
        );
    }
}

#[test]
fn permitting_fs_read_reaches_every_read_operation_and_no_mutation() {
    // One clause on the coarse action covers every kernel read verb — the customer
    // contract. It reaches no write, delete, or move operation.
    let policy = loaded(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);"#,
    );
    let shell = Principal::agent();

    for &operation in READS {
        assert!(
            allows(&policy, &shell, operation, "/home/strands-box/a.txt"),
            "fs:read must reach {operation:?}"
        );
    }
    let mutations = WRITES
        .iter()
        .copied()
        .chain([FsOperation::RemoveFile, FsOperation::Rename]);
    for operation in mutations {
        assert!(
            !allows(&policy, &shell, operation, "/home/strands-box/a.txt"),
            "fs:read must NOT reach {operation:?}"
        );
    }
}

#[test]
fn the_operation_guard_narrows_within_fs_read() {
    // Enumeration and content read now ride the same action, so the distinction moves to
    // `context.input.operation`. This is the within-action narrowing the vocabulary keeps: allow
    // listing a directory while refusing to read the files in it.
    let policy = loaded(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
           when { context.input.operation == Box::FsReadOperation::"enumerate" };"#,
    );
    let shell = Principal::agent();

    assert!(allows(
        &policy,
        &shell,
        FsOperation::Enumerate,
        "/home/strands-box"
    ));
    assert!(!allows(
        &policy,
        &shell,
        FsOperation::ReadContent,
        "/home/strands-box/secret.txt"
    ));
}

#[test]
fn a_misspelled_operation_value_is_a_load_error() {
    // `operation` is an enum entity, so a verb the schema does not declare is refused at
    // load. A stringly-typed `operation` accepted the misspelling and the rule quietly
    // never matched — the one silent-miss hole the closed record could not close.
    assert!(
        open(
            r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
               when { context.input.operation == Box::FsReadOperation::"read_contnet" };"#,
        )
        .is_err(),
        "an undeclared FsReadOperation value must refuse to load"
    );
}

#[test]
fn a_verb_spelled_with_the_actions_own_enum_but_undeclared_is_a_load_error() {
    // Each action declares its own operation enum, so a verb from another action is an
    // undeclared eid of the named enum and refuses to load. Note the limit: comparing
    // against ANOTHER enum's value (`Box::FsWriteOperation::"write_content"` on `fs:read`)
    // loads and is statically false — Cedar permits `==` across entity types.
    assert!(
        open(
            r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
               when { context.input.operation == Box::FsReadOperation::"write_content" };"#,
        )
        .is_err(),
        "a write verb is not a declared FsReadOperation, so it must refuse to load"
    );
}

#[test]
fn a_destructive_operation_is_refusable_while_content_writes_stay_permitted() {
    // "May write and append, but may not delete, and may not change permissions." Delete
    // is its own action (`fs:delete`), so simply not granting it refuses it. Permission
    // change rides `fs:write`, so refusing it while allowing writes needs an `operation`
    // guard on `fs:write`.
    let policy = loaded(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
           forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
           when { context.input.operation == Box::FsWriteOperation::"set_permissions" };"#,
    );
    let shell = Principal::agent();

    assert!(allows(
        &policy,
        &shell,
        FsOperation::WriteContent,
        "/home/strands-box/log"
    ));
    assert!(
        !allows(
            &policy,
            &shell,
            FsOperation::RemoveFile,
            "/home/strands-box/log"
        ),
        "a delete rides fs:delete, which this policy never grants"
    );
    assert!(
        !allows(
            &policy,
            &shell,
            FsOperation::SetPermissions,
            "/home/strands-box/log"
        ),
        "the operation guard forbids set_permissions while writes stay permitted"
    );
}

#[test]
fn an_unnamed_operation_rides_fs_other_and_the_four_verbs_do_not_reach_it() {
    // A kernel operation this vocabulary does not name must be granted explicitly rather
    // than inheriting a permit written for a different verb. `fs:other` is a distinct
    // action, so permitting all four verbs leaves it denied — the fail-closed catch-all.
    let policy = loaded(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
           permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
           permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
           permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);"#,
    );
    let shell = Principal::agent();

    assert!(!allows(
        &policy,
        &shell,
        FsOperation::Other,
        "/home/strands-box/a.txt"
    ));

    // Naming it beside a raised action is what grants it.
    let explicit = loaded(
        r#"permit(principal == Box::Agent::"self",
                  action in [Box::Action::"fs:move", Box::Action::"fs:other"], resource);"#,
    );
    assert!(allows(
        &explicit,
        &shell,
        FsOperation::Other,
        "/home/strands-box/a.txt"
    ));
}

#[test]
fn a_temporal_clause_on_fs_read_counts_every_read_operation() {
    // The flagship win: because `fs:read` is one raised action, a temporal rule on
    // it counts every kind of read, so "no more reads after the secret was read" is one
    // clause. When the vocabulary was fine-grained this needed one clause per read verb.
    // Record a content read of the secret, and every subsequent read closes.
    let policy = loaded(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
           unless temporal {
               formerly within 300s
               Box::Action::"fs:read"::response{ input.path: "/home/strands-box/secret" }
           };"#,
    );
    let shell = Principal::agent();

    // Nothing has happened, so the `unless` does not fire and each read is allowed.
    for &operation in READS {
        assert!(
            allows(&policy, &shell, operation, "/home/strands-box/a.txt"),
            "{operation:?} must be allowed before the guarded read happens"
        );
    }

    // Record the guarded read as a completed effect, and every read closes.
    policy
        .record(
            &GovernedBox::assigned("test-box"),
            &shell,
            &policy::Outcome::Fs {
                path: Path::new("/home/strands-box/secret"),
                operation: FsOperation::ReadContent,
                result: policy::FsResult::Completed,
            },
        )
        .expect("history accepts the outcome");

    for &operation in READS {
        assert!(
            !allows(&policy, &shell, operation, "/home/strands-box/a.txt"),
            "{operation:?} must be refused once the guarded read is in history"
        );
    }
}

#[test]
fn a_failed_effect_raises_an_error_event_and_no_response() {
    // A failed effect records `::error`, so the kind carries how it ended. Two rules
    // read the same recorded failure: the response-keyed step-up must stay closed (a
    // failure is not a completion), and the error-keyed clause must fire (the kind has
    // a producer, not just a declaration).
    let policy = loaded(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
           when temporal {
               formerly within 300s
               Box::Action::"fs:read"::response{ input.path: "/home/strands-box/approval" }
           };
           permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource)
           when temporal {
               formerly within 300s
               Box::Action::"fs:read"::error{ input.path: "/home/strands-box/approval" }
           };"#,
    );
    let shell = Principal::agent();

    policy
        .record(
            &GovernedBox::assigned("test-box"),
            &shell,
            &policy::Outcome::Fs {
                path: Path::new("/home/strands-box/approval"),
                operation: FsOperation::ReadContent,
                result: policy::FsResult::Failed,
            },
        )
        .expect("history accepts the failure");

    assert!(
        !allows(
            &policy,
            &shell,
            FsOperation::WriteContent,
            "/home/strands-box/a.txt"
        ),
        "a failed read must not satisfy a response-keyed precondition"
    );
    assert!(
        allows(
            &policy,
            &shell,
            FsOperation::RemoveFile,
            "/home/strands-box/a.txt"
        ),
        "a failed read must satisfy an error-keyed clause: the error kind has a producer"
    );
}

#[test]
fn a_completed_keyed_rule_reads_the_response_result_and_excludes_the_uncertain() {
    // `output.result` is the one field a response carries beyond its inputs. This
    // proves the spelling the box writes is the spelling a rule matches, and that a
    // completed effect is separable from a dropped permit's guess.
    let policy = loaded(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
           when temporal {
               formerly within 300s
               Box::Action::"fs:read"::response{
                   input.path: "/home/strands-box/approval",
                   output.result: Box::FsResponseResult::"completed"
               }
           };"#,
    );
    let shell = Principal::agent();
    let record = |result| {
        policy
            .record(
                &GovernedBox::assigned("test-box"),
                &shell,
                &policy::Outcome::Fs {
                    path: Path::new("/home/strands-box/approval"),
                    operation: FsOperation::ReadContent,
                    result,
                },
            )
            .expect("history accepts the outcome");
    };

    // An indeterminate read is a response, but not a completed one.
    record(policy::FsResult::Indeterminate);
    assert!(
        !allows(
            &policy,
            &shell,
            FsOperation::WriteContent,
            "/home/strands-box/a.txt"
        ),
        "a dropped permit's guess must not satisfy a completed-keyed precondition"
    );

    record(policy::FsResult::Completed);
    assert!(
        allows(
            &policy,
            &shell,
            FsOperation::WriteContent,
            "/home/strands-box/a.txt"
        ),
        "a completed read must satisfy the completed-keyed precondition"
    );
}

/// One principal serves every boundary, and the **action** is what separates them.
///
/// This test used to assert the opposite: three entity types, one per enforcement point, so a
/// permit naming one did not carry to another. That shape is gone — there is one `Agent`
/// principal now, and a rule cannot grant the script something the shell does not get.
///
/// What replaces it is the property that made the old narrowing unnecessary: **an action is
/// only ever raised by the boundary that owns it.** A `fs:read` permit cannot make a
/// `net:connect` request pass, because the request names a different action. So the
/// separation is structural rather than authored, and this asserts it in both directions.
#[test]
fn one_principal_and_the_action_separates_the_boundaries() {
    let agent = Principal::agent();

    // Only the filesystem is permitted. The two network legs must still be refused.
    let fs_only = loaded(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);"#,
    );
    assert!(allows(
        &fs_only,
        &agent,
        FsOperation::ReadContent,
        "/home/strands-box/a.txt"
    ));
    for request in [
        Request::Connect {
            host: "example.test",
            ip: None,
            port: 443,
        },
        Request::Http {
            host: "example.test",
            port: 443,
            method: "GET",
            path: "/",
            body_bytes: 0,
            intercepted: true,
        },
    ] {
        assert!(
            !matches!(
                fs_only.decide(&GovernedBox::assigned("test-box"), &agent, &request),
                Decision::Allow { .. }
            ),
            "an fs:read permit must not reach {request:?}"
        );
    }

    // And the other direction: the network permits must not reach the filesystem.
    let net_only = loaded(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource);
           permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);"#,
    );
    for request in [
        Request::Connect {
            host: "example.test",
            ip: None,
            port: 443,
        },
        Request::Http {
            host: "example.test",
            port: 443,
            method: "GET",
            path: "/",
            body_bytes: 0,
            intercepted: true,
        },
    ] {
        assert!(
            matches!(
                net_only.decide(&GovernedBox::assigned("test-box"), &agent, &request),
                Decision::Allow { .. }
            ),
            "the net permits must reach {request:?}"
        );
    }
    assert!(
        !allows(
            &net_only,
            &agent,
            FsOperation::ReadContent,
            "/home/strands-box/a.txt"
        ),
        "a network permit must not reach the filesystem"
    );
}

#[test]
fn ordinary_authority_filenames_follow_the_authored_policy() {
    let policy = loaded("permit(principal, action, resource);");
    let shell = Principal::agent();

    for path in [
        "/Users/operator/workspace/box.toml",
        "/Users/operator/workspace/policy.dw",
    ] {
        for &operation in WRITES {
            assert!(
                allows(&policy, &shell, operation, path),
                "the authored catch-all permit must govern {operation:?} on {path}"
            );
        }
        for operation in [
            FsOperation::RemoveFile,
            FsOperation::Rename,
            FsOperation::Other,
        ] {
            assert!(
                allows(&policy, &shell, operation, path),
                "the filename must add no compiled refusal for {operation:?} on {path}"
            );
        }
    }
}

#[test]
fn a_write_budget_on_fs_write_is_not_consumed_by_moves_or_deletes() {
    // A temporal predicate names one action, so a budget keyed on `fs:write::response`
    // counts writes alone: a move rides `fs:move` and a delete rides `fs:delete`, and
    // neither advances the count. An author who wants a family budget writes one clause
    // per member.
    let policy = loaded(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
           permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
           permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
           forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
           when temporal {
               exists (total: Long). (
                   (count for (t: Timepoint). where (
                       formerly within 3600s (
                           Box::Action::"fs:write"::response{ input.path: _ } && tp(t)
                       )
                   )) == total
                   && total >= 3
               )
           };"#,
    );
    let shell = Principal::agent();
    let perform = |operation: FsOperation, path: &str| {
        assert!(
            allows(&policy, &shell, operation, path),
            "{operation:?} on {path} must be permitted"
        );
        policy
            .record(
                &GovernedBox::assigned("test-box"),
                &shell,
                &policy::Outcome::Fs {
                    path: Path::new(path),
                    operation,
                    result: policy::FsResult::Completed,
                },
            )
            .expect("history accepts the outcome");
    };

    perform(FsOperation::WriteContent, "/home/strands-box/one");
    perform(FsOperation::WriteContent, "/home/strands-box/two");
    for index in 0..3 {
        perform(
            FsOperation::Rename,
            &format!("/home/strands-box/moved-{index}"),
        );
    }
    for index in 0..3 {
        perform(
            FsOperation::RemoveFile,
            &format!("/home/strands-box/removed-{index}"),
        );
    }

    perform(FsOperation::WriteContent, "/home/strands-box/three");
    assert!(
        !allows(
            &policy,
            &shell,
            FsOperation::WriteContent,
            "/home/strands-box/four"
        ),
        "three writes have completed, so the budget denies the fourth and no earlier one"
    );
}
