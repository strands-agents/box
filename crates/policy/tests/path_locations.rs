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

fn operator(locations: &[(&str, &[&str])]) -> Operator {
    Operator::unanchored().with_locations(locations.iter().map(|(name, directories)| {
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
    let home = operator(&[("project", &["/home/dev/src/app"])]);
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
