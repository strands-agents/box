//! End-to-end `[locations]`: a real box decides a Shell write by a rule that names a location.

use std::process::Output;

#[path = "support/fixture.rs"]
mod fixture;

use fixture::Request;

/// What the Shell prints when policy refuses a write.
const DENIED: &str = "policy denied this operation";

/// Every command and every read, and writes only in the `project` location.
const PROJECT_WRITES: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
@id("project_write")
permit(principal, action == Box::Action::"fs:write", resource)
when { context.input.locations.project };
"#;

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_rule_on_a_location_permits_a_write_inside_it_and_denies_one_outside() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_config(
        "locations-project",
        PROJECT_WRITES,
        "[locations]\nproject = [\"~/workspace\"]\n",
    )
    .expect();

    let inside = box_.bash(r#"zsh -lc "printf located > ./inside.txt""#);
    assert!(inside.status.success(), "{inside:?}");
    assert_eq!(
        std::fs::read_to_string(box_.workspace().join("inside.txt")).expect("the write landed"),
        "located"
    );

    let outside = box_.bash(r#"zsh -lc "printf escaped > \"$BOX_HOME/outside.txt\"""#);
    assert!(!outside.status.success(), "{outside:?}");
    assert!(stderr(&outside).contains(DENIED), "{outside:?}");
    assert!(
        !box_.box_home().join("outside.txt").exists(),
        "a write outside every location must not land: {outside:?}"
    );
}

#[test]
fn a_sibling_with_a_shared_prefix_is_not_in_the_location() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = Request::with_config(
        "locations-sibling",
        PROJECT_WRITES,
        "[locations]\nproject = [\"~/workspace/app\"]\n",
    )
    .expect();
    std::fs::create_dir_all(box_.workspace().join("app")).expect("the location's directory");
    std::fs::create_dir_all(box_.workspace().join("app-old")).expect("its sibling");

    let inside = box_.bash(r#"zsh -lc "printf in > ./app/kept.txt""#);
    assert!(inside.status.success(), "{inside:?}");

    let sibling = box_.bash(r#"zsh -lc "printf out > ./app-old/kept.txt""#);
    assert!(!sibling.status.success(), "{sibling:?}");
    assert!(stderr(&sibling).contains(DENIED), "{sibling:?}");
    assert!(!box_.workspace().join("app-old/kept.txt").exists());
}

#[test]
fn a_forbid_on_a_nested_location_beats_a_permit_on_the_outer_one() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let policy = format!(
        "{PROJECT_WRITES}\n\
         @id(\"no_docs_writes\")\n\
         forbid(principal, action == Box::Action::\"fs:write\", resource)\n\
         when {{ context.input.locations.docs }};\n"
    );
    let box_ = Request::with_config(
        "locations-nested",
        &policy,
        "[locations]\nproject = [\"~/workspace\"]\ndocs = [\"~/workspace/docs\"]\n",
    )
    .expect();
    std::fs::create_dir_all(box_.workspace().join("docs")).expect("the nested directory");

    let docs = box_.bash(r#"zsh -lc "printf no > ./docs/intro.md""#);
    assert!(!docs.status.success(), "{docs:?}");
    assert!(!box_.workspace().join("docs/intro.md").exists());
    assert!(
        stderr(&docs).contains("no_docs_writes"),
        "the denial names the forbid: {docs:?}"
    );

    let elsewhere = box_.bash(r#"zsh -lc "printf yes > ./notes.md""#);
    assert!(elsewhere.status.success(), "{elsewhere:?}");
}

#[test]
fn a_misspelled_location_stops_the_box_before_the_workload_starts() {
    let (_box, output) = Request::with_config(
        "locations-typo",
        &PROJECT_WRITES.replace("locations.project", "locations.projcet"),
        "[locations]\nproject = [\"~/workspace\"]\n",
    )
    .attempt();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        stderr(&output).contains("projcet"),
        "the refusal names the misspelled location: {}",
        stderr(&output)
    );
}

#[test]
fn a_policy_that_names_a_location_stops_a_box_that_declares_none() {
    let (_box, output) = Request::with_policy("locations-none", PROJECT_WRITES).attempt();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        stderr(&output).contains("input.locations.project"),
        "the refusal names the undeclared location: {}",
        stderr(&output)
    );
}

#[test]
fn startup_discloses_each_location() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (_box, output) = Request::with_config(
        "locations-disclosed",
        PROJECT_WRITES,
        "[locations]\nproject = [\"~/workspace\"]\n",
    )
    .attempt();
    assert!(output.status.success(), "{output:?}");
    assert!(
        stderr(&output).contains("[locations] project: ~/workspace  "),
        "{}",
        stderr(&output)
    );
}
