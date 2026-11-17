//! Named locations: a rule reads `context.input.locations` instead of spelling a directory.

#[path = "support/history.rs"]
#[expect(dead_code, reason = "these tests read no request identifier")]
mod history;

use std::path::{Path, PathBuf};

use dogwood_language::Value;
use policy::{
    ApprovedPath, Decision, FsOperation, FsResult, GovernedBox, Operator, Outcome, PathResolver,
    Policy, PolicyEngine, Principal, Request,
};

const PROJECT_WRITE: &str = r#"
@id("project_write")
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.locations.project };
"#;

fn sources(text: &str) -> Vec<Policy> {
    vec![Policy {
        origin: PathBuf::from("policy.dw"),
        text: text.to_string(),
    }]
}

/// The operator home every fixture states, which does not exist on the test host.
const HOME: &str = "/nonexistent-box-home/dev";

/// An operator under [`HOME`] that declares `locations`, or the refusal of the declaration.
fn declare(locations: &[(&str, &[&str])]) -> Result<Operator, policy::PolicyError> {
    Operator::unanchored()
        .anchored_at(HOME)
        .with_locations(locations.iter().map(|(name, directories)| {
            (
                (*name).to_string(),
                directories.iter().map(PathBuf::from).collect(),
            )
        }))
}

fn operator(locations: &[(&str, &[&str])]) -> Operator {
    declare(locations).expect("the locations resolve")
}

fn project() -> Operator {
    operator(&[("project", &["/work"])])
}

fn approved(path: &str) -> ApprovedPath {
    PathResolver::over([PathBuf::from("/")])
        .expect("the root is absolute")
        .approve_virtual(Path::new(path))
        .unwrap_or_else(|refusal| panic!("a fixture path must resolve: {refusal}"))
}

fn open(operator: &Operator, text: &str, history: &Path) -> PolicyEngine {
    PolicyEngine::open_staged(operator, sources(text), history).expect("the policy loads")
}

fn write(engine: &PolicyEngine, path: &str) -> (Decision, Option<policy::RequestId>) {
    let approved = approved(path);
    engine.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &Request::Fs {
            path: &approved,
            operation: FsOperation::WriteContent,
        },
    )
}

fn allows(engine: &PolicyEngine, path: &str) -> bool {
    write(engine, path).0.is_allow()
}

/// Admit and complete one write, and return whether it was allowed.
fn complete_write(engine: &PolicyEngine, path: &str) -> bool {
    let (decision, request_id) = write(engine, path);
    if !decision.is_allow() {
        return false;
    }
    engine
        .record(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &request_id.expect("an allow carries a request id"),
            &Outcome::Fs {
                path: Path::new(path),
                operation: FsOperation::WriteContent,
                result: FsResult::Completed,
            },
        )
        .expect("the outcome records");
    true
}

/// The names whose `input.locations` attribute is true on each recorded event, or `None` when an
/// event has no `locations` record.
fn recorded_locations(history: &Path) -> Vec<Option<Vec<String>>> {
    history::events(history)
        .iter()
        .map(
            |event| match event.field_path(&["input".to_string(), "locations".to_string()]) {
                Some(Value::Object(attributes)) => Some(
                    attributes
                        .iter()
                        .filter_map(|(name, held)| match held {
                            Value::Bool(true) => Some(name.clone()),
                            Value::Bool(false) => None,
                            other => panic!("a location attribute is a Bool: {other:?}"),
                        })
                        .collect(),
                ),
                None => None,
                Some(other) => panic!("`locations` is a record: {other:?}"),
            },
        )
        .collect()
}

#[test]
fn a_permit_on_a_location_allows_a_write_inside_it_and_denies_one_outside() {
    let directory = tempfile::tempdir().expect("history directory");
    let engine = open(&project(), PROJECT_WRITE, &directory.path().join("h.redb"));

    assert!(allows(&engine, "/work/src/main.rs"));
    assert!(allows(&engine, "/work"));
    assert!(!allows(&engine, "/elsewhere/main.rs"));
}

#[test]
fn a_sibling_with_a_shared_prefix_is_not_in_the_location() {
    let directory = tempfile::tempdir().expect("history directory");
    let engine = open(&project(), PROJECT_WRITE, &directory.path().join("h.redb"));

    assert!(!allows(&engine, "/work-old/notes.md"));
    assert!(!allows(&engine, "/workspace"));
}

#[test]
fn a_nested_path_is_in_both_locations_and_a_forbid_on_the_inner_one_wins() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("h.redb");
    let nested = operator(&[("project", &["/work"]), ("docs", &["/work/docs"])]);
    let text = format!(
        r#"{PROJECT_WRITE}
@id("no_docs")
forbid (principal, action == Box::Action::"fs:write", resource)
when {{ context.input.locations.docs }};
"#
    );
    let engine = open(&nested, &text, &history);

    assert!(complete_write(&engine, "/work/src/main.rs"));
    let (decision, _) = write(&engine, "/work/docs/intro.md");
    let Decision::Deny { attribution, .. } = decision else {
        panic!("the forbid on the inner location must deny: {decision:?}");
    };
    assert_eq!(
        attribution
            .iter()
            .filter_map(|rule| rule.annotation_id.as_deref())
            .collect::<Vec<_>>(),
        ["no_docs"]
    );
    assert!(!allows(&engine, "/elsewhere/intro.md"));
    drop(engine);

    let project = Some(vec!["project".to_string()]);
    let both = Some(vec!["docs".to_string(), "project".to_string()]);
    assert_eq!(
        recorded_locations(&history),
        [project.clone(), project, both, Some(Vec::new())],
        "the request and its response carry one record, true for each location that holds the path"
    );
}

#[test]
fn a_box_without_locations_records_an_empty_locations_record() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("h.redb");
    let engine = open(
        &Operator::unanchored(),
        r#"permit (principal, action == Box::Action::"fs:write", resource);"#,
        &history,
    );

    assert!(complete_write(&engine, "/work/src/main.rs"));
    drop(engine);

    assert_eq!(
        recorded_locations(&history),
        [Some(Vec::new()), Some(Vec::new())]
    );
}

#[test]
fn a_misspelled_location_refuses_to_load() {
    let misspelled = PROJECT_WRITE.replace("locations.project", "locations.projcet");
    let directory = tempfile::tempdir().expect("history directory");

    assert!(
        PolicyEngine::open_staged(
            &project(),
            sources(&misspelled),
            &directory.path().join("h.redb")
        )
        .is_err()
    );
    let Err(error) = PolicyEngine::validate(&project(), &sources(&misspelled)) else {
        panic!("validate must refuse a misspelled location");
    };
    assert!(
        error.to_string().contains("input.locations.projcet"),
        "{error}"
    );
    for complete in [true, false] {
        assert!(
            !PolicyEngine::check(&project(), &sources(&misspelled), complete)
                .errors()
                .is_empty(),
            "check (complete: {complete}) must refuse a misspelled location"
        );
    }
}

#[test]
fn a_policy_that_names_a_location_refuses_to_load_when_none_is_declared() {
    let directory = tempfile::tempdir().expect("history directory");
    let none = Operator::unanchored();

    assert!(
        PolicyEngine::open_staged(&none, sources(PROJECT_WRITE), &directory.path().join("a"))
            .is_err()
    );
    assert!(PolicyEngine::open(sources(PROJECT_WRITE), &directory.path().join("b")).is_err());
    let Err(error) = PolicyEngine::validate(&none, &sources(PROJECT_WRITE)) else {
        panic!("validate must refuse an undeclared location");
    };
    assert!(
        error.to_string().contains("input.locations.project"),
        "{error}"
    );
    for complete in [true, false] {
        assert!(
            !PolicyEngine::check(&none, &sources(PROJECT_WRITE), complete)
                .errors()
                .is_empty()
        );
    }
}

#[test]
fn a_bad_declaration_is_refused_by_with_locations() {
    let long = "a".repeat(65);
    let longest = "a".repeat(64);
    let cases: [(&str, &[&str]); 12] = [
        ("1project", &["/work"]),
        ("pro ject", &["/work"]),
        ("my-project", &["/work"]),
        ("in", &["/work"]),
        ("true", &["/work"]),
        ("has", &["/work"]),
        ("", &["/work"]),
        (&long, &["/work"]),
        ("project", &[]),
        ("project", &["work"]),
        ("project", &["/work/./src"]),
        ("project", &["/work/../etc"]),
    ];
    for (name, directories) in cases {
        assert!(
            declare(&[(name, directories)]).is_err(),
            "with_locations must refuse {name:?} = {directories:?}"
        );
    }
    let permit = r#"permit (principal, action == Box::Action::"fs:read", resource);"#;
    for accepted in ["P", "my_project_2", "permit", longest.as_str()] {
        assert!(
            PolicyEngine::validate(&operator(&[(accepted, &["/"])]), &sources(permit)).is_ok(),
            "{accepted:?} is a valid name"
        );
    }
}

#[test]
fn one_history_loads_and_decides_as_locations_are_added_and_then_removed() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("h.redb");
    let by_path = r#"
@id("by_path")
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.path like "/work/*" };
"#;

    let engine = open(&Operator::unanchored(), by_path, &history);
    assert!(complete_write(&engine, "/work/a"));
    assert!(!allows(&engine, "/elsewhere/a"));
    drop(engine);

    let engine = open(&project(), PROJECT_WRITE, &history);
    assert!(complete_write(&engine, "/work/b"));
    assert!(!allows(&engine, "/elsewhere/b"));
    drop(engine);

    let renamed = operator(&[("project", &["/elsewhere"])]);
    let engine = open(&renamed, PROJECT_WRITE, &history);
    assert!(allows(&engine, "/elsewhere/c"));
    assert!(!allows(&engine, "/work/c"));
    drop(engine);

    let engine = open(&Operator::unanchored(), by_path, &history);
    assert!(complete_write(&engine, "/work/d"));
    assert!(!allows(&engine, "/elsewhere/d"));
}

/// A budget keyed on one location attribute counts every write in that location, whatever other
/// locations hold the path.
#[test]
fn a_temporal_budget_on_one_location_counts_writes_that_are_also_in_another() {
    let directory = tempfile::tempdir().expect("history directory");
    let nested = operator(&[("project", &["/work"]), ("docs", &["/work/docs"])]);
    let budget = r#"
permit (principal, action == Box::Action::"fs:write", resource);
@id("project_budget")
forbid (principal, action == Box::Action::"fs:write", resource)
when { context.input.locations.project }
when temporal {
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (
                Box::Action::"fs:write"::response{ input.locations.project: true } && tp(t)
            )
        )) == total
        && total >= 3
    )
};
"#;
    let engine = open(&nested, budget, &directory.path().join("h.redb"));

    assert!(complete_write(&engine, "/work/a"), "{{project}}: one");
    assert!(
        complete_write(&engine, "/work/docs/a.md"),
        "{{project, docs}}: two"
    );
    assert!(complete_write(&engine, "/work/b"), "{{project}}: three");
    assert!(
        !allows(&engine, "/work/c"),
        "writes in {{project}} and in {{project, docs}} spend one budget"
    );
    assert!(!allows(&engine, "/work/docs/b.md"));
    assert!(
        complete_write(&engine, "/elsewhere/a"),
        "a write in no location is outside the budget"
    );
}

/// A rule that names a location with `has` loads in a box that does not declare it, and matches
/// only where it is declared.
#[test]
fn a_portable_rule_loads_without_the_location_and_matches_with_it() {
    let portable = r#"
@id("secrets_read")
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.locations has secrets && context.input.locations.secrets };
"#;
    let read = |engine: &PolicyEngine, path: &str| {
        let approved = approved(path);
        engine
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Fs {
                    path: &approved,
                    operation: FsOperation::ReadContent,
                },
            )
            .0
            .is_allow()
    };
    let directory = tempfile::tempdir().expect("history directory");
    for (label, declared) in [("none", Operator::unanchored()), ("other", project())] {
        let engine = open(&declared, portable, &directory.path().join(label));
        assert!(
            !read(&engine, "/work/a"),
            "{label}: the rule matches nothing"
        );
        assert!(PolicyEngine::validate(&declared, &sources(portable)).is_ok());
        for complete in [true, false] {
            let check = PolicyEngine::check(&declared, &sources(portable), complete);
            assert!(check.errors().is_empty(), "{label}: {:?}", check.errors());
        }
    }
    let secrets = operator(&[("secrets", &["/vault"])]);
    let engine = open(&secrets, portable, &directory.path().join("declared"));
    assert!(
        read(&engine, "/vault/key"),
        "the rule matches where `secrets` is declared"
    );
    assert!(!read(&engine, "/work/a"));
}

/// A `forbid` guarded by `has` loads with no error or warning where the location is missing, and
/// denies where it is declared.
#[test]
fn an_optional_forbid_is_neither_refused_nor_reported_and_applies_where_declared() {
    let policy = r#"
@id("all_reads")
permit (principal, action == Box::Action::"fs:read", resource);

@id("no_secrets_reads")
forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.locations has secrets && context.input.locations.secrets };
"#;
    let read = |engine: &PolicyEngine, path: &str| {
        let approved = approved(path);
        engine
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Fs {
                    path: &approved,
                    operation: FsOperation::ReadContent,
                },
            )
            .0
            .is_allow()
    };
    let directory = tempfile::tempdir().expect("history directory");
    for (label, declared) in [("none", Operator::unanchored()), ("other", project())] {
        for complete in [true, false] {
            let check = PolicyEngine::check(&declared, &sources(policy), complete);
            assert!(check.errors().is_empty(), "{label}: {:?}", check.errors());
            assert!(
                check.warnings().is_empty(),
                "{label}: {:?}",
                check.warnings()
            );
        }
        let engine = open(&declared, policy, &directory.path().join(label));
        assert!(read(&engine, "/vault/key"), "{label}: the forbid is off");
    }
    let secrets = operator(&[("secrets", &["/vault"])]);
    let engine = open(&secrets, policy, &directory.path().join("declared"));
    assert!(
        !read(&engine, "/vault/key"),
        "the forbid applies where declared"
    );
    assert!(read(&engine, "/work/a"));
}

#[test]
fn a_response_named_by_its_home_relative_spelling_carries_its_requests_locations() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("h.redb");
    // A canonical home, because macOS links `/home`, and a root resolves through links.
    let home_dir = directory
        .path()
        .canonicalize()
        .expect("canonical")
        .join("dev");
    let home = Operator::unanchored()
        .anchored_at(&home_dir)
        .with_locations([("project".to_string(), vec![home_dir.join("src/app")])])
        .expect("the locations resolve");
    let engine = open(&home, PROJECT_WRITE, &history);
    let approved = PathResolver::over([home_dir.clone()])
        .expect("the root is absolute")
        .reporting_under(&home_dir)
        .approve_virtual(&home_dir.join("src/app/main.rs"))
        .expect("the path resolves");
    assert_eq!(approved.reported(), "~/src/app/main.rs");

    let (decision, request_id) = engine.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &Request::Fs {
            path: &approved,
            operation: FsOperation::WriteContent,
        },
    );
    assert!(decision.is_allow());
    engine
        .record(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &request_id.expect("an allow carries a request id"),
            &Outcome::Fs {
                path: Path::new("~/src/app/main.rs"),
                operation: FsOperation::WriteContent,
                result: FsResult::Completed,
            },
        )
        .expect("the outcome records");
    drop(engine);

    let project = Some(vec!["project".to_string()]);
    assert_eq!(recorded_locations(&history), [project.clone(), project]);
}

/// A rule that also names a per-tool MCP action is held pending until that server's schema
/// stages; a location it reads must still refuse at load when no location of that name exists.
#[test]
fn a_rule_held_for_an_mcp_schema_refuses_an_undeclared_location_at_load() {
    let held = |condition: &str| {
        format!(
            r#"
permit (principal, action == Box::Action::"fs:write", resource);
@id("guarded")
forbid (principal, action == Box::Action::"fs:write", resource)
when {{ {condition} }}
unless temporal {{ formerly within 1h alpha::Action::"deploy"::response{{}} }};
"#
        )
    };
    let held_in_history = |name: &str| {
        format!(
            r#"
permit (principal, action == Box::Action::"fs:write", resource);
@id("guarded")
forbid (principal, action == Box::Action::"fs:write", resource)
unless temporal {{
    formerly within 1h (
        alpha::Action::"deploy"::response{{}}
        && Box::Action::"fs:write"::response{{ input.locations.{name}: true }}
    )
}};
"#
        )
    };
    let directory = tempfile::tempdir().expect("history directory");
    let cases = [
        (
            "misspelled",
            project(),
            held("context.input.locations.projcet"),
        ),
        (
            "undeclared",
            Operator::unanchored(),
            held("context.input.locations.project"),
        ),
        ("history", project(), held_in_history("projcet")),
    ];
    for (label, declared, text) in cases {
        let opened =
            PolicyEngine::open_staged(&declared, sources(&text), &directory.path().join(label));
        let Err(error) = opened else {
            panic!("{label}: open_staged must refuse the location");
        };
        assert!(
            error.to_string().contains("does not declare"),
            "{label}: {error}"
        );
        let check = PolicyEngine::check(&declared, &sources(&text), false);
        assert!(
            !check.errors().is_empty() && check.unchecked().is_empty(),
            "{label}: check must refuse the rule rather than list it as unchecked: {:?}",
            check.errors()
        );
    }

    for (label, declared, text) in [
        (
            "declared",
            project(),
            held("context.input.locations.project"),
        ),
        ("history", project(), held_in_history("project")),
        (
            "portable",
            Operator::unanchored(),
            held("context.input.locations has secrets && context.input.locations.secrets"),
        ),
    ] {
        let engine = open(
            &declared,
            &text,
            &directory.path().join(format!("{label}-ok")),
        );
        assert!(
            allows(&engine, "/work/a"),
            "{label}: the rule loads and waits for its schema"
        );
        let check = PolicyEngine::check(&declared, &sources(&text), false);
        assert!(check.errors().is_empty(), "{label}: {:?}", check.errors());
        assert_eq!(check.unchecked().len(), 1, "{label}");
    }
}

/// Every outcome names its path `~/…`, as the Shell and Python report one under the home, so
/// its set comes from that spelling and from nothing kept per request.
#[test]
fn more_outstanding_requests_than_any_cap_record_their_own_locations() {
    const OUTSTANDING: usize = 4_200;
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("h.redb");
    let nested = operator(&[
        ("project", &["/nonexistent-box-home/dev/work"]),
        ("docs", &["/nonexistent-box-home/dev/work/docs"]),
    ]);
    let engine = open(
        &nested,
        r#"permit (principal, action == Box::Action::"fs:write", resource);"#,
        &history,
    );
    let resolver = PathResolver::over([PathBuf::from(HOME), PathBuf::from("/elsewhere")])
        .expect("the roots are absolute")
        .reporting_under(HOME);
    let path = |index: usize| match index % 3 {
        0 => format!("{HOME}/work/{index}"),
        1 => format!("{HOME}/work/docs/{index}"),
        _ => format!("/elsewhere/{index}"),
    };
    let admitted: Vec<_> = (0..OUTSTANDING)
        .map(|index| {
            let approved = resolver
                .approve_virtual(Path::new(&path(index)))
                .expect("the path resolves");
            let (decision, request_id) = engine.decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Fs {
                    path: &approved,
                    operation: FsOperation::WriteContent,
                },
            );
            assert!(decision.is_allow());
            (
                approved.reported().into_owned(),
                request_id.expect("an allow carries a request id"),
            )
        })
        .collect();
    assert!(admitted[0].0.starts_with("~/"), "{}", admitted[0].0);
    for (reported, request_id) in &admitted {
        engine
            .record(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                request_id,
                &Outcome::Fs {
                    path: Path::new(reported),
                    operation: FsOperation::WriteContent,
                    result: FsResult::Completed,
                },
            )
            .expect("the outcome records");
    }
    drop(engine);

    let expected = |index: usize| {
        Some(match index % 3 {
            0 => vec!["project".to_string()],
            1 => vec!["docs".to_string(), "project".to_string()],
            _ => Vec::new(),
        })
    };
    let recorded = recorded_locations(&history);
    assert_eq!(recorded.len(), 2 * OUTSTANDING);
    for index in 0..OUTSTANDING {
        assert_eq!(recorded[index], expected(index), "request {index}");
        assert_eq!(
            recorded[OUTSTANDING + index],
            expected(index),
            "response {index}"
        );
    }
}

#[test]
fn a_root_that_does_not_exist_yet_under_a_linked_parent_matches_once_created() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let real = directory.path().join("real");
    std::fs::create_dir(&real).expect("the real directory");
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("the link");
    let root = link.join("new").join("deeper");
    let declared = Operator::unanchored()
        .anchored_at(HOME)
        .with_locations([("project".to_string(), vec![root.clone()])])
        .expect("the locations resolve");
    let engine = open(&declared, PROJECT_WRITE, &directory.path().join("h.redb"));

    std::fs::create_dir_all(&root).expect("the root is created after the box starts");
    // The request carries the canonical path, through the real directory and not the link.
    let approved = PathResolver::over([directory.path().canonicalize().expect("canonical")])
        .expect("the root is absolute")
        .approve_host(
            &real
                .canonicalize()
                .expect("canonical")
                .join("new/deeper/file"),
        )
        .expect("the canonical path resolves");
    let (decision, _) = engine.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &Request::Fs {
            path: &approved,
            operation: FsOperation::WriteContent,
        },
    );
    assert!(
        decision.is_allow(),
        "the root resolves through its linked parent: {decision:?}"
    );
}

#[test]
fn locations_without_an_operator_home_are_refused() {
    let Err(error) = Operator::unanchored()
        .with_locations([("project".to_string(), vec![PathBuf::from("/work")])])
    else {
        panic!("with_locations must refuse locations without a home");
    };
    assert!(error.to_string().contains("no home"), "{error}");
    assert!(
        Operator::unanchored()
            .with_locations(std::iter::empty())
            .is_ok(),
        "no location needs no home"
    );
}

/// The operator states its home through a link, and a location's root resolves through it; a
/// `~/…` outcome is matched under the home's canonical spelling as well.
#[test]
fn a_home_relative_outcome_matches_under_the_canonical_home() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let real = directory.path().join("real-home");
    std::fs::create_dir_all(real.join("work")).expect("the home");
    let link = directory.path().join("home");
    std::os::unix::fs::symlink(&real, &link).expect("the link");
    let canonical = real.canonicalize().expect("canonical");
    let history = directory.path().join("h.redb");
    let declared = Operator::unanchored()
        .anchored_at(&link)
        .with_locations([("project".to_string(), vec![link.join("work")])])
        .expect("the locations resolve");
    let engine = open(&declared, PROJECT_WRITE, &history);
    let approved = PathResolver::over([canonical.clone()])
        .expect("the root is absolute")
        .reporting_under(&canonical)
        .approve_host(&canonical.join("work/file"))
        .expect("the path resolves");
    assert_eq!(approved.reported(), "~/work/file");

    let (decision, request_id) = engine.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &Request::Fs {
            path: &approved,
            operation: FsOperation::WriteContent,
        },
    );
    assert!(decision.is_allow(), "{decision:?}");
    engine
        .record(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &request_id.expect("an allow carries a request id"),
            &Outcome::Fs {
                path: Path::new("~/work/file"),
                operation: FsOperation::WriteContent,
                result: FsResult::Completed,
            },
        )
        .expect("the outcome records");
    drop(engine);

    let project = Some(vec!["project".to_string()]);
    assert_eq!(recorded_locations(&history), [project.clone(), project]);
}

/// Assert that `with_locations` refuses `root` as the `project` location, naming it.
fn assert_root_refused(root: &Path) {
    let Err(error) = Operator::unanchored()
        .anchored_at(HOME)
        .with_locations([("project".to_string(), vec![root.to_path_buf()])])
    else {
        panic!("with_locations must refuse {}", root.display());
    };
    let fragment = format!(
        "location \"project\": {} cannot be resolved",
        root.display()
    );
    assert!(error.to_string().contains(&fragment), "{error}");
}

#[test]
fn a_root_that_is_a_dangling_link_is_refused() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let canonical = directory.path().canonicalize().expect("canonical");
    let link = canonical.join("link");
    std::os::unix::fs::symlink(canonical.join("absent"), &link).expect("the dangling link");
    for root in [link.clone(), link.join("below")] {
        assert_root_refused(&root);
    }
}

#[test]
fn a_root_that_is_a_file_or_a_link_to_one_is_refused() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let canonical = directory.path().canonicalize().expect("canonical");
    let file = canonical.join("file");
    std::fs::write(&file, "not a directory").expect("the file");
    let link = canonical.join("link-to-file");
    std::os::unix::fs::symlink(&file, &link).expect("the link to the file");
    for root in [file.clone(), link.clone(), file.join("below")] {
        assert_root_refused(&root);
    }
}

#[test]
fn a_root_under_a_directory_that_cannot_be_searched_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("a temporary directory");
    let canonical = directory.path().canonicalize().expect("canonical");
    let locked = canonical.join("locked");
    std::fs::create_dir_all(locked.join("project")).expect("the locked tree");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    if std::fs::read_dir(&locked).is_ok() {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        eprintln!("skipping: a privileged user searches a directory with no permission bits");
        return;
    }
    let root = locked.join("project");
    assert_root_refused(&root);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).expect("chmod");
}

#[test]
fn a_home_relative_outcome_matches_under_a_home_that_is_not_utf8() {
    use std::os::unix::ffi::OsStrExt as _;

    let directory = tempfile::tempdir().expect("a temporary directory");
    let home = directory
        .path()
        .canonicalize()
        .expect("canonical")
        .join(std::ffi::OsStr::from_bytes(b"home-\xff"));
    // macOS APFS refuses a non-UTF-8 name (EILSEQ, 92), so this home cannot exist there.
    if let Err(error) = std::fs::create_dir_all(home.join("work")) {
        if cfg!(target_os = "macos") && error.raw_os_error() == Some(92) {
            eprintln!("skipping: this filesystem refuses non-UTF-8 names ({error})");
            return;
        }
        panic!("the home: {error:?}");
    }
    assert!(home.to_str().is_none(), "the home is not UTF-8");
    let history = directory.path().join("h.redb");
    let declared = Operator::unanchored()
        .anchored_at(&home)
        .with_locations([("project".to_string(), vec![home.join("work")])])
        .expect("the locations resolve");
    let engine = open(&declared, PROJECT_WRITE, &history);
    let approved = PathResolver::over([home.clone()])
        .expect("the root is absolute")
        .reporting_under(&home)
        .approve_host(&home.join("work/file"))
        .expect("the path resolves");
    assert_eq!(
        approved.reported(),
        "~/work/file",
        "a path under the home is reported home-relative"
    );

    let (decision, request_id) = engine.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &Request::Fs {
            path: &approved,
            operation: FsOperation::WriteContent,
        },
    );
    assert!(decision.is_allow(), "{decision:?}");
    engine
        .record(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &request_id.expect("an allow carries a request id"),
            &Outcome::Fs {
                path: Path::new("~/work/file"),
                operation: FsOperation::WriteContent,
                result: FsResult::Completed,
            },
        )
        .expect("the outcome records");
    drop(engine);

    let project = Some(vec!["project".to_string()]);
    assert_eq!(recorded_locations(&history), [project.clone(), project]);
}

/// A rule held for an MCP schema that reads a `locations` field of its own tool action is not a
/// location read, so it waits for that schema as before.
#[test]
fn a_held_rule_on_a_tool_action_reads_its_own_locations_field_and_waits() {
    let held = |condition: &str| {
        format!(
            r#"
@id("route")
forbid (principal, action == demo::Action::"route", resource)
{condition};
"#
        )
    };
    let cases = [
        held(r#"when { context.input.locations == "home" }"#),
        held(r#"when { context.input has locations }"#),
        held(r#"when { context.input.locations like "home*" }"#),
        held(r#"unless { context.input.locations == "home" }"#),
        held(r#"when { context.input["locations"] == "home" }"#),
        held(
            r#"when temporal { formerly within 1h demo::Action::"route"::response{ input.target: context.input.locations.home } }"#,
        ),
    ];
    let directory = tempfile::tempdir().expect("history directory");
    for (index, text) in cases.iter().enumerate() {
        for (label, declared) in [("none", Operator::unanchored()), ("project", project())] {
            let opened = PolicyEngine::open_staged(
                &declared,
                sources(text),
                &directory.path().join(format!("{index}-{label}")),
            );
            assert!(opened.is_ok(), "{label}: {text}: {:?}", opened.err());
            let check = PolicyEngine::check(&declared, &sources(text), false);
            assert!(
                check.errors().is_empty(),
                "{label}: {text}: {:?}",
                check.errors()
            );
            assert_eq!(check.unchecked().len(), 1, "{label}: {text}");
        }
    }
}

/// A held rule on a tool action whose history predicate reads a file event's undeclared location
/// still refuses at load.
#[test]
fn a_held_rule_on_a_tool_action_refuses_a_file_events_undeclared_location() {
    let text = r#"
@id("route")
forbid (principal, action == demo::Action::"route", resource)
unless temporal {
    formerly within 1h Box::Action::"fs:write"::response{ input.locations.projcet: true }
};
"#;
    let directory = tempfile::tempdir().expect("history directory");
    let Err(error) =
        PolicyEngine::open_staged(&project(), sources(text), &directory.path().join("h"))
    else {
        panic!("open_staged must refuse the undeclared location");
    };
    assert!(error.to_string().contains("projcet"), "{error}");
    let check = PolicyEngine::check(&project(), &sources(text), false);
    assert!(
        !check.errors().is_empty() && check.unchecked().is_empty(),
        "{:?}",
        check.errors()
    );
}

/// An undeclared location names `[locations]` and both fixes, in an ordinary rule and a held one;
/// another schema error in a held rule is not called a location.
#[test]
fn an_undeclared_location_is_refused_with_the_two_fixes() {
    let ordinary = PROJECT_WRITE.replace("locations.project", "locations.caches");
    let Err(error) = PolicyEngine::validate(&project(), &sources(&ordinary)) else {
        panic!("validate must refuse an undeclared location");
    };
    let error = error.to_string();
    for fragment in [
        "`context.input.locations.caches`",
        "[locations]",
        "declare `caches`",
        "context.input.locations has caches",
    ] {
        assert!(error.contains(fragment), "{fragment}: {error}");
    }
    assert!(!error.contains("did you mean"), "{error}");
    let check = PolicyEngine::check(&project(), &sources(&ordinary), true);
    assert!(
        check
            .errors()
            .iter()
            .any(|finding| finding.message().contains("declare `caches`")),
        "{:?}",
        check.errors()
    );

    let held = |condition: &str| {
        format!(
            r#"
permit (principal, action == Box::Action::"fs:write", resource);
@id("guarded")
forbid (principal, action == Box::Action::"fs:write", resource)
when {{ {condition} }}
unless temporal {{ formerly within 1h alpha::Action::"deploy"::response{{}} }};
"#
        )
    };
    let directory = tempfile::tempdir().expect("history directory");
    let Err(error) = PolicyEngine::open_staged(
        &project(),
        sources(&held("context.input.locations.caches")),
        &directory.path().join("held"),
    ) else {
        panic!("open_staged must refuse an undeclared location");
    };
    let error = error.to_string();
    assert!(error.contains("declare `caches`"), "{error}");

    let Err(error) = PolicyEngine::open_staged(
        &project(),
        sources(&held(
            r#"context.input.locations.project && context.input.pathh == "x""#,
        )),
        &directory.path().join("pathh"),
    ) else {
        panic!("open_staged must refuse an undeclared attribute");
    };
    let error = error.to_string();
    assert!(
        error.contains("fails validation against the Box action schema"),
        "{error}"
    );
    assert!(error.contains("pathh"), "{error}");
    assert!(!error.contains("does not declare"), "{error}");
}

/// `has` makes a Cedar condition on a location optional, but a history predicate on a location is
/// always strict, so it refuses to load where the location is not declared.
#[test]
fn a_history_predicate_on_an_undeclared_location_refuses_even_beside_has() {
    let text = r#"
@id("secrets_budget")
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.locations has secrets && context.input.locations.secrets }
when temporal {
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (
                Box::Action::"fs:read"::response{ input.locations.secrets: true } && tp(t)
            )
        )) == total
        && total < 10
    )
};
"#;
    let directory = tempfile::tempdir().expect("history directory");
    for (label, declared) in [("none", Operator::unanchored()), ("other", project())] {
        let Err(error) =
            PolicyEngine::open_staged(&declared, sources(text), &directory.path().join(label))
        else {
            panic!("{label}: the history predicate must refuse");
        };
        assert!(
            error.to_string().contains("input.locations.secrets"),
            "{label}: {error}"
        );
    }
    let secrets = operator(&[("secrets", &["/vault"])]);
    open(&secrets, text, &directory.path().join("declared"));
}
