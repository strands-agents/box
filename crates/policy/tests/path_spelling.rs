//! A rule's path literal is judged at load against the spelling a decision reads.

use std::path::PathBuf;

use policy::{
    ApprovedPath, FsOperation, GovernedBox, Operator, PathResolver, Policy, PolicyEngine,
    PolicyError, PolicyStagingError, PolicyWarning, Principal, Request,
};

struct Home {
    directory: tempfile::TempDir,
    canonical: PathBuf,
}

impl Home {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("an operator home");
        let canonical = directory.path().canonicalize().expect("a canonical home");
        std::fs::create_dir_all(canonical.join("project")).expect("a project directory");
        std::fs::write(canonical.join("project/secrets.env"), "s").expect("a secret");
        std::fs::write(canonical.join("project/notes.md"), "n").expect("a note");
        Self {
            directory,
            canonical,
        }
    }

    fn operator(&self) -> Operator {
        Operator::unanchored().anchored_at(&self.canonical)
    }

    fn approved(&self, relative: &str) -> ApprovedPath {
        PathResolver::over([self.canonical.clone()])
            .expect("an absolute root")
            .reporting_under(self.canonical.clone())
            .approve_host(&self.canonical.join(relative))
            .expect("a path under the home")
    }

    fn history(&self, name: &str) -> PathBuf {
        self.directory.path().join(format!("{name}.redb"))
    }

    fn open(&self, name: &str, text: &str) -> Result<PolicyEngine, PolicyStagingError> {
        PolicyEngine::open_staged(&self.operator(), vec![source(text)], &self.history(name))
    }
}

fn source(text: &str) -> Policy {
    Policy {
        origin: PathBuf::from("spelling.dw"),
        text: text.to_string(),
    }
}

fn refusal(result: Result<PolicyEngine, PolicyStagingError>) -> String {
    match result {
        Ok(_) => panic!("the inert literal must refuse the load"),
        Err(PolicyStagingError::Policy(PolicyError::Spelling(reason))) => reason,
        Err(other) => panic!("expected a spelling refusal, got {other}"),
    }
}

fn reads(engine: &PolicyEngine, path: &ApprovedPath) -> bool {
    engine
        .decide(
            &GovernedBox::assigned("spelling"),
            &Principal::agent(),
            &Request::Fs {
                path,
                operation: FsOperation::ReadContent,
            },
        )
        .is_allow()
}

fn spawns(engine: &PolicyEngine, program: &str) -> bool {
    engine
        .decide(
            &GovernedBox::assigned("spelling"),
            &Principal::agent(),
            &Request::ShellSpawn {
                command: "curl https://example.com",
                program,
                program_path: "/usr/bin/curl",
                credential_reads: &[],
                args: &["https://example.com".to_string()],
                cwd: "/workspace",
            },
        )
        .is_allow()
}

const READ_ALL: &str =
    r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);"#;

#[test]
fn an_absolute_path_under_the_home_is_refused_and_its_home_relative_form_forbids() {
    let home = Home::new();
    let absolute = format!(
        r#"{READ_ALL}
        @id("no_secrets")
        forbid(principal, action == Box::Action::"fs:read", resource)
        when {{ context.input.path == "{}" }};"#,
        home.canonical.join("project/secrets.env").display()
    );
    let reason = refusal(home.open("absolute", &absolute));
    assert!(reason.contains("rule @id(\"no_secrets\")"), "{reason}");
    assert!(
        reason.contains("write \"~/project/secrets.env\""),
        "{reason}"
    );

    let control = format!(
        r#"{READ_ALL}
        forbid(principal, action == Box::Action::"fs:read", resource)
        when {{ context.input.path == "~/project/secrets.env" }};"#
    );
    let engine = home.open("tilde", &control).expect("the ~ spelling loads");
    assert!(!reads(&engine, &home.approved("project/secrets.env")));
    assert!(reads(&engine, &home.approved("project/notes.md")));
}

#[test]
fn a_forbid_over_every_action_is_judged_too() {
    let home = Home::new();
    let absolute = format!(
        r#"{READ_ALL}
        forbid(principal, action, resource)
        when {{ context has input && context.input has path
            && context.input.path == "{}" }};"#,
        home.canonical.join("project/secrets.env").display()
    );
    let reason = refusal(home.open("broad-absolute", &absolute));
    assert!(
        reason.contains("write \"~/project/secrets.env\""),
        "{reason}"
    );

    let control = format!(
        r#"{READ_ALL}
        forbid(principal, action, resource)
        when {{ context has input && context.input has path
            && context.input.path == "~/project/secrets.env" }};"#
    );
    let engine = home
        .open("broad-tilde", &control)
        .expect("the ~ spelling loads");
    assert!(!reads(&engine, &home.approved("project/secrets.env")));
    assert!(reads(&engine, &home.approved("project/notes.md")));
}

#[test]
fn a_spelling_refusal_survives_staging_classification() {
    let home = Home::new();
    let per_tool = r#"permit(principal, action == alpha::Action::"read", resource);"#;
    let absolute = format!(
        r#"{per_tool}
        {READ_ALL}
        forbid(principal, action == Box::Action::"fs:read", resource)
        when {{ context.input.path == "{}" }};"#,
        home.canonical.join("project/secrets.env").display()
    );
    let reason = refusal(home.open("classified-absolute", &absolute));
    assert!(
        reason.contains("write \"~/project/secrets.env\""),
        "{reason}"
    );

    let control = format!(
        r#"{per_tool}
        {READ_ALL}
        forbid(principal, action == Box::Action::"fs:read", resource)
        when {{ context.input.path == "~/project/secrets.env" }};"#
    );
    let engine = home
        .open("classified-tilde", &control)
        .expect("the ~ spelling stages while the tool schema is pending");
    assert!(!reads(&engine, &home.approved("project/secrets.env")));
    assert!(reads(&engine, &home.approved("project/notes.md")));
}

#[test]
fn a_trailing_slash_is_refused_and_the_bare_directory_matches() {
    let home = Home::new();
    let reason = refusal(home.open(
        "trailing",
        r#"permit(principal, action == Box::Action::"fs:read", resource)
        when { context.input.path == "~/project/" };"#,
    ));
    assert!(reason.contains("write \"~/project\""), "{reason}");

    let engine = home
        .open(
            "directory",
            r#"permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "~/project" };"#,
        )
        .expect("the bare directory loads");
    assert!(reads(&engine, &home.approved("project")));
    assert!(!reads(&engine, &home.approved("project/notes.md")));
}

#[test]
fn a_program_spelled_as_a_path_warns_because_it_matches_only_that_spelling() {
    let home = Home::new();
    let engine = home
        .open(
            "program-path",
            r#"@id("full_path")
            permit(principal, action == Box::Action::"shell:spawn", resource)
            when { context.input.program == "/usr/bin/curl" };"#,
        )
        .expect("a program path loads with a warning");
    let [warning] = engine.warnings() else {
        panic!("exactly one warning, got {:?}", engine.warnings());
    };
    assert!(
        matches!(warning, PolicyWarning::ProgramSpelledAsPath { rule, .. } if rule == "rule @id(\"full_path\")"),
        "{warning:?}"
    );
    assert!(
        spawns(&engine, "/usr/bin/curl"),
        "the spelled invocation matches"
    );
    assert!(
        !spawns(&engine, "curl"),
        "and the bare invocation slips past it"
    );

    let engine = home
        .open(
            "program",
            r#"permit(principal, action == Box::Action::"shell:spawn", resource)
            when { context.input.program == "curl" };"#,
        )
        .expect("the bare name loads");
    assert!(engine.warnings().is_empty());
    assert!(spawns(&engine, "curl"));
    assert!(!spawns(&engine, "wget"));
}

#[test]
fn a_pattern_over_a_sibling_of_the_home_loads_without_a_finding() {
    let home = Home::new();
    let engine = home
        .open(
            "sibling",
            &format!(
                r#"forbid(principal, action == Box::Action::"fs:read", resource)
                when {{ context.input.path like "{}-other/*" }};"#,
                home.canonical.display()
            ),
        )
        .expect("a sibling of the home is a canonical spelling");
    assert!(engine.warnings().is_empty());
}

#[test]
fn a_pattern_naming_the_home_after_a_wildcard_warns_and_loads() {
    let home = Home::new();
    let engine = home
        .open(
            "wildcard",
            &format!(
                r#"@id("later_home")
                permit(principal, action == Box::Action::"fs:read", resource)
                when {{ context.input.path like "*{}/project/*" }};"#,
                home.canonical.display()
            ),
        )
        .expect("an uncertain pattern loads");
    let [warning] = engine.warnings() else {
        panic!("exactly one warning, got {:?}", engine.warnings());
    };
    assert!(
        matches!(warning, PolicyWarning::HomeAfterWildcard { rule, .. } if rule == "rule @id(\"later_home\")"),
        "{warning:?}"
    );
}

#[test]
fn an_absolute_path_outside_the_home_loads_without_a_finding() {
    let home = Home::new();
    let engine = home
        .open(
            "outside",
            r#"forbid(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path == "/etc/hosts" };"#,
        )
        .expect("a path outside the home is a canonical spelling");
    assert!(engine.warnings().is_empty());
}

#[test]
fn an_unanchored_operator_judges_no_literal_against_a_home() {
    let home = Home::new();
    let absolute = format!(
        r#"permit(principal, action == Box::Action::"fs:read", resource)
        when {{ context.input.path == "{}" }};"#,
        home.canonical.join("project/notes.md").display()
    );
    PolicyEngine::open(vec![source(&absolute)], &home.history("unanchored"))
        .expect("without a home there is nothing to judge the literal against");
    assert!(
        PolicyEngine::validate(&Operator::unanchored(), &[source(&absolute)]).is_ok(),
        "validate agrees with open"
    );
    assert!(
        PolicyEngine::validate(&home.operator(), &[source(&absolute)]).is_err(),
        "and refuses once the operator is anchored"
    );
}

fn requests(engine: &PolicyEngine, path: &str) -> bool {
    engine
        .decide(
            &GovernedBox::assigned("spelling"),
            &Principal::agent(),
            &Request::Http {
                host: "api.example.test",
                port: 443,
                method: "GET",
                path,
                body_bytes: 0,
                intercepted: true,
            },
        )
        .is_allow()
}

const REQUEST_ALL: &str =
    r#"permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);"#;

#[test]
fn an_operation_guard_keeps_a_filesystem_path_rule_off_an_http_request_with_the_same_path() {
    // `context.input.path` carries a URL path on `http:request` and a filesystem path on
    // `fs:*`, so a forbid over every action that compares `path` fires on both. Every
    // filesystem input declares `operation` and no other input does, so `context.input has
    // operation` is the guard that keeps the rule on the filesystem.
    let home = Home::new();
    let unguarded = format!(
        r#"{READ_ALL}
        {REQUEST_ALL}
        forbid(principal, action, resource)
        when {{ context has input && context.input has path
            && context.input.path like "*/secrets.env" }};"#
    );
    let engine = home
        .open("unguarded", &unguarded)
        .expect("the forbid loads");
    assert!(!reads(&engine, &home.approved("project/secrets.env")));
    assert!(reads(&engine, &home.approved("project/notes.md")));
    assert!(
        !requests(&engine, "/v1/secrets.env"),
        "the unguarded rule denies a request whose URL path matches the filesystem pattern"
    );
    assert!(requests(&engine, "/v1/notes"));

    let guarded = format!(
        r#"{READ_ALL}
        {REQUEST_ALL}
        forbid(principal, action, resource)
        when {{ context has input && context.input has path && context.input has operation
            && context.input.path like "*/secrets.env" }};"#
    );
    let engine = home
        .open("guarded", &guarded)
        .expect("the guarded forbid loads");
    assert!(!reads(&engine, &home.approved("project/secrets.env")));
    assert!(reads(&engine, &home.approved("project/notes.md")));
    assert!(
        requests(&engine, "/v1/secrets.env"),
        "the guard leaves the request to the permit"
    );
}

#[test]
fn a_cross_type_operation_comparison_loads_without_a_finding_and_never_matches() {
    // KNOWN GAP, pinned so it cannot change silently. Cedar permits `==` across entity
    // types, so an `fs:read` rule that compares `operation` with a `FsWriteOperation` value
    // is statically false: it loads, raises no finding, and never matches.
    let home = Home::new();
    let engine = home
        .open(
            "cross-type",
            r#"@id("cross_type")
            permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.operation == Box::FsWriteOperation::"write_content" };"#,
        )
        .expect("KNOWN GAP: a cross-type comparison loads");
    assert!(
        engine.warnings().is_empty(),
        "KNOWN GAP: no finding names the comparison; got {:?}",
        engine.warnings()
    );
    assert!(
        !reads(&engine, &home.approved("project/notes.md")),
        "the permit the author believes exists matches no read"
    );
}

#[test]
fn a_multi_word_program_literal_loads_without_a_finding_and_never_matches() {
    // KNOWN GAP, pinned so it cannot change silently. `program` carries one word, so a
    // literal with a space loads, raises no finding, and never matches.
    let home = Home::new();
    let engine = home
        .open(
            "multi-word",
            r#"@id("git_status")
            permit(principal, action == Box::Action::"shell:spawn", resource)
            when { context.input.program == "git status" };"#,
        )
        .expect("KNOWN GAP: a multi-word program literal loads");
    assert!(
        engine.warnings().is_empty(),
        "KNOWN GAP: no finding names the literal; got {:?}",
        engine.warnings()
    );
    let decision = engine.decide(
        &GovernedBox::assigned("spelling"),
        &Principal::agent(),
        &Request::ShellSpawn {
            command: "git status",
            program: "git",
            program_path: "/usr/bin/git",
            credential_reads: &[],
            args: &["status".to_string()],
            cwd: "/workspace",
        },
    );
    assert!(
        !decision.is_allow(),
        "the permit the author believes exists matches no spawn: {decision:?}"
    );
}
