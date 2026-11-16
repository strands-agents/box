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
when { context.input.locations.contains(Box::Location::"project") };
"#;

fn sources(text: &str) -> Vec<Policy> {
    vec![Policy {
        origin: PathBuf::from("policy.dw"),
        text: text.to_string(),
    }]
}

/// The operator home every fixture states, which does not exist on the test host.
const HOME: &str = "/nonexistent-box-home/dev";

fn operator(locations: &[(&str, &[&str])]) -> Operator {
    Operator::unanchored()
        .anchored_at(HOME)
        .with_locations(locations.iter().map(|(name, directories)| {
            (
                (*name).to_string(),
                directories.iter().map(PathBuf::from).collect(),
            )
        }))
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

/// The `input.locations` of each recorded event, as location names.
fn recorded_locations(history: &Path) -> Vec<Option<Vec<String>>> {
    history::events(history)
        .iter()
        .map(
            |event| match event.field_path(&["input".to_string(), "locations".to_string()]) {
                Some(Value::Array(values)) => Some(
                    values
                        .iter()
                        .map(|value| match value {
                            Value::Entity { ty, id } if ty == "Box::Location" => id.clone(),
                            other => panic!("a location is a Box::Location entity: {other:?}"),
                        })
                        .collect(),
                ),
                None => None,
                Some(other) => panic!("`locations` is a set: {other:?}"),
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
when {{ context.input.locations.contains(Box::Location::"docs") }};
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
        "the request and its response carry one sorted set, and a path in none an empty one"
    );
}

#[test]
fn a_box_without_locations_records_no_locations_field() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("h.redb");
    let engine = open(
        &Operator::unanchored(),
        r#"permit (principal, action == Box::Action::"fs:write", resource);"#,
        &history,
    );

    assert!(complete_write(&engine, "/work/src/main.rs"));
    drop(engine);

    assert_eq!(recorded_locations(&history), [None, None]);
}

#[test]
fn a_misspelled_location_refuses_to_load() {
    let misspelled = PROJECT_WRITE.replace(r#"Location::"project""#, r#"Location::"projcet""#);
    let directory = tempfile::tempdir().expect("history directory");

    assert!(
        PolicyEngine::open_staged(
            &project(),
            sources(&misspelled),
            &directory.path().join("h.redb")
        )
        .is_err()
    );
    assert!(PolicyEngine::validate(&project(), &sources(&misspelled)).is_err());
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
    assert!(PolicyEngine::validate(&none, &sources(PROJECT_WRITE)).is_err());
    for complete in [true, false] {
        assert!(
            !PolicyEngine::check(&none, &sources(PROJECT_WRITE), complete)
                .errors()
                .is_empty()
        );
    }
}

#[test]
fn a_bad_declaration_is_refused_by_open_validate_and_check() {
    let long = "a".repeat(65);
    let longest = "a".repeat(64);
    let cases: [(&str, &[&str]); 8] = [
        ("1project", &["/work"]),
        ("pro ject", &["/work"]),
        ("", &["/work"]),
        (&long, &["/work"]),
        ("project", &[]),
        ("project", &["work"]),
        ("project", &["/work/./src"]),
        ("project", &["/work/../etc"]),
    ];
    let permit = r#"permit (principal, action == Box::Action::"fs:read", resource);"#;
    for (name, directories) in cases {
        let declared = operator(&[(name, directories)]);
        let directory = tempfile::tempdir().expect("history directory");
        let opened =
            PolicyEngine::open_staged(&declared, sources(permit), &directory.path().join("h"));
        assert!(
            opened.is_err(),
            "open must refuse {name:?} = {directories:?}"
        );
        assert!(PolicyEngine::validate(&declared, &sources(permit)).is_err());
        for complete in [true, false] {
            assert!(
                !PolicyEngine::check(&declared, &sources(permit), complete)
                    .errors()
                    .is_empty(),
                "check (complete: {complete}) must refuse {name:?} = {directories:?}"
            );
        }
    }
    for accepted in ["P", "my_project-2", longest.as_str()] {
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

/// Dogwood refuses an array constant in a temporal predicate, so a rule cannot name a set of
/// locations there.
#[test]
fn a_temporal_predicate_cannot_name_a_set_of_locations() {
    let literal = r#"
permit (principal, action == Box::Action::"fs:write", resource)
when temporal {
    formerly within 1h (
        Box::Action::"fs:write"::response{ input.locations: [Box::Location::"project"] }
    )
};
"#;
    let directory = tempfile::tempdir().expect("history directory");
    let Err(error) =
        PolicyEngine::open_staged(&project(), sources(literal), &directory.path().join("h"))
    else {
        panic!("an array constant refuses to load");
    };
    let error = error.to_string();
    assert!(error.contains("array constants"), "{error}");
}

/// A temporal predicate compares a set field as an ordered whole, so a rule counts the writes
/// whose locations equal the request's own.
#[test]
fn a_temporal_rule_counts_the_writes_in_the_requests_own_locations() {
    let directory = tempfile::tempdir().expect("history directory");
    let nested = operator(&[("project", &["/work"]), ("docs", &["/work/docs"])]);
    let budget = r#"
@id("location_budget")
permit (principal, action == Box::Action::"fs:write", resource)
when temporal {
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (
                Box::Action::"fs:write"::response{ input.locations: context.input.locations }
                && tp(t)
            )
        )) == total
        && total < 2
    )
};
"#;
    let engine = open(&nested, budget, &directory.path().join("h.redb"));

    assert!(complete_write(&engine, "/work/a"));
    assert!(complete_write(&engine, "/work/b"));
    assert!(
        !allows(&engine, "/work/c"),
        "two writes in `project` alone spend its budget"
    );
    assert!(
        complete_write(&engine, "/work/docs/a.md"),
        "a write in `docs` and `project` is counted apart from one in `project` alone"
    );
    assert!(complete_write(&engine, "/work/docs/b.md"));
    assert!(!allows(&engine, "/work/docs/c.md"));
}

#[test]
fn a_response_named_by_its_home_relative_spelling_carries_its_requests_locations() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("h.redb");
    let home = Operator::unanchored()
        .anchored_at("/home/dev")
        .with_locations([(
            "project".to_string(),
            vec![PathBuf::from("/home/dev/src/app")],
        )]);
    let engine = open(&home, PROJECT_WRITE, &history);
    let approved = PathResolver::over([PathBuf::from("/home/dev")])
        .expect("the root is absolute")
        .reporting_under("/home/dev")
        .approve_virtual(Path::new("/home/dev/src/app/main.rs"))
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
/// stages; a location literal it names must still refuse at load.
#[test]
fn a_rule_held_for_an_mcp_schema_refuses_an_undeclared_location_at_load() {
    let held = |location: &str| {
        format!(
            r#"
permit (principal, action == Box::Action::"fs:write", resource);
@id("guarded")
forbid (principal, action == Box::Action::"fs:write", resource)
when {{ context.input.locations.contains(Box::Location::"{location}") }}
unless temporal {{ formerly within 1h alpha::Action::"deploy"::response{{}} }};
"#
        )
    };
    let in_history = r#"
permit (principal, action == Box::Action::"fs:write", resource);
@id("guarded")
forbid (principal, action == Box::Action::"fs:write", resource)
unless temporal {
    formerly within 1h (
        alpha::Action::"deploy"::response{}
        && Box::Action::"fs:write"::response{ input.locations: context.input.locations,
                                              input.operation: Box::FsWriteOperation::"write_content" }
    )
};
"#;
    let directory = tempfile::tempdir().expect("history directory");
    let cases = [
        ("misspelled", project(), held("projcet")),
        ("undeclared", Operator::unanchored(), held("project")),
    ];
    for (label, declared, text) in cases {
        let opened =
            PolicyEngine::open_staged(&declared, sources(&text), &directory.path().join(label));
        let Err(error) = opened else {
            panic!("{label}: open_staged must refuse the location");
        };
        assert!(
            error.to_string().contains("Box::Location"),
            "{label}: {error}"
        );
        let check = PolicyEngine::check(&declared, &sources(&text), false);
        assert!(
            !check.errors().is_empty() && check.unchecked().is_empty(),
            "{label}: check must refuse the rule rather than list it as unchecked: {:?}",
            check.errors()
        );
    }

    let engine = open(
        &project(),
        &held("project"),
        &directory.path().join("valid"),
    );
    assert!(
        allows(&engine, "/work/a"),
        "a declared location loads, and the held rule waits"
    );
    let check = PolicyEngine::check(&project(), &sources(&held("project")), false);
    assert!(check.errors().is_empty(), "{:?}", check.errors());
    assert_eq!(check.unchecked().len(), 1);
    drop(engine);

    let engine = open(&project(), in_history, &directory.path().join("history"));
    assert!(
        allows(&engine, "/work/a"),
        "a rule that names no location literal is held as before"
    );
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
        .with_locations([("project".to_string(), vec![root.clone()])]);
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
fn locations_without_an_operator_home_refuse_to_load() {
    let directory = tempfile::tempdir().expect("history directory");
    let unanchored = Operator::unanchored()
        .with_locations([("project".to_string(), vec![PathBuf::from("/work")])]);
    let permit = r#"permit (principal, action == Box::Action::"fs:read", resource);"#;

    let Err(error) =
        PolicyEngine::open_staged(&unanchored, sources(permit), &directory.path().join("h"))
    else {
        panic!("open_staged must refuse locations without a home");
    };
    assert!(error.to_string().contains("no home"), "{error}");
    assert!(PolicyEngine::validate(&unanchored, &sources(permit)).is_err());
    for complete in [true, false] {
        assert!(
            !PolicyEngine::check(&unanchored, &sources(permit), complete)
                .errors()
                .is_empty()
        );
    }
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
        .with_locations([("project".to_string(), vec![link.join("work")])]);
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
