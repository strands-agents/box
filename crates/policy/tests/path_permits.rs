//! The paths an installed `permit` names, as `PolicyEngine::path_permits` reports them.

use std::path::PathBuf;

use policy::{Operator, Policy, PolicyEngine};

fn open(text: &str) -> (tempfile::TempDir, PolicyEngine) {
    let directory = tempfile::tempdir().expect("a history directory");
    let home = directory.path().canonicalize().expect("a canonical home");
    let engine = PolicyEngine::open_staged(
        &Operator::unanchored().anchored_at(&home),
        vec![Policy {
            origin: PathBuf::from("permits.dw"),
            text: text.to_string(),
        }],
        &directory.path().join("history.redb"),
    )
    .expect("the policy loads");
    (directory, engine)
}

fn spellings(engine: &PolicyEngine) -> Vec<(String, Vec<String>, String)> {
    engine
        .path_permits()
        .into_iter()
        .map(|permit| {
            (
                permit.rule().to_string(),
                permit.actions().to_vec(),
                permit.spelling(),
            )
        })
        .collect()
}

#[test]
fn a_permit_reports_each_path_its_when_clause_names() {
    let (_home, engine) = open(
        r#"
        @id("aws_config")
        permit (principal, action == Box::Action::"fs:read", resource)
        when { context.input.path == "~/.aws/config" || context.input.path like "~/.ssh/*.pub" };
        @id("listed")
        permit (principal, action in [Box::Action::"fs:write", Box::Action::"fs:delete"], resource)
        when { ["~/.kube/config", "~/.netrc"].contains(context.input.path) };
        "#,
    );
    assert_eq!(
        spellings(&engine),
        vec![
            (
                r#"rule @id("aws_config")"#.to_string(),
                vec!["fs:read".to_string()],
                "~/.aws/config".to_string()
            ),
            (
                r#"rule @id("aws_config")"#.to_string(),
                vec!["fs:read".to_string()],
                "~/.ssh/*.pub".to_string()
            ),
            (
                r#"rule @id("listed")"#.to_string(),
                vec!["fs:write".to_string(), "fs:delete".to_string()],
                "~/.kube/config".to_string()
            ),
            (
                r#"rule @id("listed")"#.to_string(),
                vec!["fs:write".to_string(), "fs:delete".to_string()],
                "~/.netrc".to_string()
            ),
        ]
    );
}

#[test]
fn a_negated_comparison_a_forbid_and_an_unless_clause_name_no_path() {
    let (_home, engine) = open(
        r#"
        permit (principal, action == Box::Action::"fs:read", resource)
        when { !(context.input.path == "~/.aws/config") };
        permit (principal, action == Box::Action::"fs:read", resource)
        when { context.input.path like "~/project/*" }
        unless { context.input.path like "~/.ssh/*" };
        permit (principal, action == Box::Action::"fs:read", resource)
        when { if context.input.path == "~/.netrc" then true else false };
        forbid (principal, action == Box::Action::"fs:read", resource)
        when { context.input.path == "~/.kube/config" };
        "#,
    );
    let named: Vec<String> = engine
        .path_permits()
        .iter()
        .map(policy::PathPermit::spelling)
        .collect();
    assert_eq!(named, vec!["~/project/*".to_string()]);
}

#[test]
fn a_pattern_matches_as_like_reads_it_and_states_its_fixed_text() {
    let (_home, engine) = open(
        r#"
        permit (principal, action == Box::Action::"fs:read", resource)
        when { context.input.path like "~/.ssh/*.pub" };
        permit (principal, action == Box::Action::"fs:read", resource)
        when { context.input.path like "*/.aws/config" };
        "#,
    );
    let permits = engine.path_permits();
    let [keys, anywhere] = permits.as_slice() else {
        panic!("two permits, got {permits:?}");
    };
    assert_eq!(keys.fixed_text(), "~/.ssh/");
    assert!(keys.matches("~/.ssh/id_ed25519.pub"));
    assert!(keys.matches("~/.ssh/nested/key.pub"));
    assert!(!keys.matches("~/.ssh/id_ed25519"));
    assert!(!keys.matches("~/.sshx/key.pub"));
    assert_eq!(anywhere.fixed_text(), "");
    assert!(anywhere.matches("~/.aws/config"));
}

#[test]
fn a_reload_replaces_the_named_paths() {
    let (_home, engine) = open(
        r#"
        permit (principal, action == Box::Action::"fs:read", resource)
        when { context.input.path == "~/.aws/config" };
        "#,
    );
    engine
        .reload(&[Policy {
            origin: PathBuf::from("permits.dw"),
            text: r#"
            permit (principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "~/.netrc" };
            "#
            .to_string(),
        }])
        .expect("the reload installs");
    let named: Vec<String> = engine
        .path_permits()
        .iter()
        .map(policy::PathPermit::spelling)
        .collect();
    assert_eq!(named, vec!["~/.netrc".to_string()]);
}

#[test]
fn a_pattern_with_many_wildcards_matches_a_long_path_in_linear_time() {
    let (_home, engine) = open(
        r#"
        permit (principal, action == Box::Action::"fs:read", resource)
        when { context.input.path like "~/.aws/*/*/*/*/x*y" };
        "#,
    );
    let permits = engine.path_permits();
    let [permit] = permits.as_slice() else {
        panic!("one permit, got {permits:?}");
    };
    let long = format!("~/.aws/{}", "/".repeat(500_000));
    let started = std::time::Instant::now();
    assert!(!permit.matches(&long));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "the match took {:?}",
        started.elapsed()
    );
    assert!(permit.matches("~/.aws/a/b/c/d/xzy"));
    assert!(permit.matches("~/.aws/a/b/c/d/e/xy"));
    assert!(!permit.matches("~/.aws/a/b/c/xy"));
    assert!(!permit.matches("~/.aws/a/b/c/d/yx"));
}
