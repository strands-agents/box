use super::source::{ConvertedStatement, StaticPathRewrite};
use super::temporal::LegacyForm;
use super::*;
use dogwood_language::{ParsedPolicySet, ServiceSchema};

fn service() -> ServiceSchema {
    ServiceSchema::builder()
        .event_schema_str(include_str!("fixtures/events.dwschema"))
        .build()
        .expect("checked Box event schema")
}
fn policy(body: &str) -> String {
    format!("permit(principal, action, resource) when {{ {body} }};")
}
fn convert(source: &str) -> Result<ConvertedStatement, MigrationError> {
    convert_saved_statement(source, &service())
}
fn prediction(source: &str) -> Result<Option<LegacyForm>, MigrationError> {
    let schema = service();
    let parsed = ParsedPolicySet::parse(source, &schema).expect("fixture must parse");
    let policies: Vec<_> = parsed.policies().collect();
    assert_eq!(policies.len(), 1);
    legacy_form(&policies[0])
}

#[test]
fn existing_harmless_collision_reproduces_actual_1_0_statement() {
    let source = include_str!("fixtures/collision.dw");
    let legacy = prediction(source)
        .unwrap()
        .expect("known generated-name collision");
    assert_eq!(
        legacy.statement.trim(),
        include_str!("fixtures/collision-old.dw").trim()
    );
    let schema = service();
    let current = ParsedPolicySet::parse(source, &schema).unwrap();
    assert_ne!(
        legacy.statement,
        current.policies().next().unwrap().expanded_source()
    );
}

#[test]
fn active_capture_refuses_instead_of_returning_a_candidate() {
    let failure = prediction(include_str!("fixtures/capture.dw")).unwrap_err();
    assert_eq!(failure.kind, MigrationErrorKind::BindingCapture);
    assert!(failure.detail.contains("active binder"));
}

fn original_prediction(source: &str, old_compiled: &str) -> Result<String, MigrationError> {
    let schema = service();
    let parsed = ParsedPolicySet::parse(source, &schema).expect("fixture must parse");
    let policies: Vec<_> = parsed.policies().collect();
    assert_eq!(policies.len(), 1);
    original_statement(
        &policies[0],
        &policies[0].expanded_source(),
        Some(old_compiled),
        &schema,
    )
}

// The old statements were captured from the separately pinned 1.0.0 compiler.
// These tests exercise statement selection without running a helper or opening a store.
#[test]
fn old_compiler_output_still_checks_original_bindings() {
    let failure = original_prediction(
        include_str!("fixtures/capture.dw"),
        include_str!("fixtures/capture-old.dw"),
    )
    .unwrap_err();
    assert_eq!(failure.kind, MigrationErrorKind::BindingCapture);
    assert!(failure.detail.contains("active binder"));
}

#[test]
fn old_compiler_output_accepts_distinct_original_bindings() {
    let source = include_str!("fixtures/capture.dw").replace("t_93", "t_94");
    let old = include_str!("fixtures/capture-control-old.dw");
    assert_eq!(original_prediction(&source, old).unwrap(), old);
}

#[test]
fn authored_shadowing_and_sibling_scopes_remain_supported() {
    assert!(
        prediction(include_str!("fixtures/shadow.dw"))
            .unwrap()
            .is_some()
    );
    assert!(
        prediction(include_str!("fixtures/collision.dw"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn edits_do_not_match_the_original_rule() {
    let source = include_str!("fixtures/collision.dw");
    let baseline = prediction(source).unwrap().unwrap().statement;
    for edited in [
        source.replace("t_33", "t_34"),
        source.replace("86400s", "86401s"),
        source.replace("http:request", "http:changed"),
        source.replacen("permit", "forbid", 1),
        source.replace("total < 100", "total < 101"),
    ] {
        let schema = service();
        let parsed = ParsedPolicySet::parse(&edited, &schema).unwrap();
        let candidate = parsed.policies().next().unwrap();
        let statement = legacy_form(&candidate)
            .unwrap()
            .map(|form| form.statement)
            .unwrap_or_else(|| candidate.expanded_source());
        assert_ne!(
            statement, baseline,
            "edit unexpectedly retained old statement"
        );
    }
}

#[test]
fn static_has_path_requires_conversion_and_preserves_other_bytes() {
    let source = policy(r#"context has "input".x"#);
    assert!(ParsedPolicySet::parse(&source, &service()).is_err());
    let result = convert(&source).unwrap();
    assert_eq!(result.statement, policy("context has input.x"));
    assert_eq!(result.rewrites.len(), 1);
    let edit: &StaticPathRewrite = &result.rewrites[0];
    assert_eq!(&source[edit.start..edit.end], "\"input\"");
    assert_eq!(edit.identifier, "input");
    assert!(ParsedPolicySet::parse(&result.statement, &service()).is_ok());
}

#[test]
fn multiple_paths_and_reserved_later_segments_are_structured() {
    let source =
        policy(r#"context has "input".x && context has "if".then.true && context has "_x".def"#);
    let result = convert(&source).unwrap();
    assert_eq!(result.rewrites.len(), 3);
    assert_eq!(
        result.statement,
        policy("context has input.x && context has if.then.true && context has _x.def")
    );
}

#[test]
fn quoted_policy_text_annotations_and_comments_stay_literal() {
    let source = "@note(\"has \\\"a\\\".b temporal { }\")\npermit(principal, action, resource) when {\n// has \"comment\".path\ncontext.note == \"has \\\"literal\\\".path \\\\ temporal { }\" && context has \"input\".x\n};";
    let result = convert(source).unwrap();
    assert_eq!(result.rewrites.len(), 1);
    assert_eq!(
        result.statement,
        source.replace("context has \"input\".x", "context has input.x")
    );
}

#[test]
fn comments_between_path_tokens_are_preserved() {
    let source = policy("context has // a\n\"input\" // b\n. // c\nx");
    let result = convert(&source).unwrap();
    assert_eq!(result.statement, source.replace("\"input\"", "input"));
    assert_eq!(result.rewrites.len(), 1);
}

#[test]
fn valid_current_rules_are_byte_exact_noops() {
    for source in [
        policy("context has input.x"),
        policy(r#"context has "input""#),
        policy("context.def == true"),
        policy(r#"context.note == "café has \"x\".y""#),
    ] {
        let converted = convert(&source).unwrap();
        assert_eq!(converted.statement, source);
        assert!(converted.rewrites.is_empty());
    }
}

#[test]
fn nonidentifier_or_escaped_legacy_heads_refuse() {
    for path in [
        r#""a b".x"#,
        r#""true".x"#,
        r#""false".x"#,
        r#""\u{78}".y"#,
        r#""".x"#,
        r#""é".x"#,
        r#""1x".y"#,
    ] {
        let error = convert(&policy(&format!("context has {path}"))).unwrap_err();
        assert_eq!(error.kind, MigrationErrorKind::UnsupportedSyntax, "{path}");
    }
}

#[test]
fn partial_paths_and_computed_or_operator_tails_refuse() {
    for path in [
        r#""x"."#,
        r#""x"."y""#,
        r#""x".1"#,
        r#""x".y["z"]"#,
        r#""x".y()"#,
        r#""x".y + z"#,
        r#""x".y::z"#,
    ] {
        assert!(
            convert(&policy(&format!("context has {path}"))).is_err(),
            "{path}"
        );
    }
}

#[test]
fn malformed_quotes_comments_and_multiple_policies_refuse() {
    assert_eq!(
        convert("permit(principal, action, resource) when { context has \"x };")
            .unwrap_err()
            .kind,
        MigrationErrorKind::Lexical
    );
    assert_eq!(
        convert(&policy("true /* unsupported */")).unwrap_err().kind,
        MigrationErrorKind::UnsupportedSyntax
    );
    assert_eq!(
        convert("permit(principal, action, resource); permit(principal, action, resource);")
            .unwrap_err()
            .kind,
        MigrationErrorKind::PolicyCount
    );
}

#[test]
fn parser_tightening_is_not_repaired_as_attribute_migration() {
    for body in ["1 < 2 < 3", "9223372036854775808 == 1", "context has a + b"] {
        assert!(convert(&policy(body)).is_err(), "{body}");
    }
}

#[test]
fn static_conversion_keeps_temporal_identity_text_exact() {
    let original = include_str!("fixtures/collision-old.dw").trim();
    let with_path = original.replacen("when {", "when { context has \"input\".x &&", 1);
    // The recorded fixture can use `when temporal`; introduce an extra Cedar
    // condition without rewriting the temporal body in that representation.
    let with_path = if with_path == original {
        original.replacen(";", " when { context has \"input\".x };", 1)
    } else {
        with_path
    };
    let converted = convert(&with_path).unwrap();
    assert_eq!(
        converted.statement,
        with_path.replace("context has \"input\".x", "context has input.x")
    );
    assert_eq!(converted.rewrites.len(), 1);
    assert!(converted.statement.contains("t_33"));
    assert!(!converted.statement.contains("t_33_1"));
}

#[test]
fn converted_old_published_rendering_matches_current_published_rendering() {
    let cases = [
        (
            include_str!("fixtures/static-ordinary.old.dw"),
            include_str!("fixtures/static-ordinary.current.dw"),
        ),
        (
            include_str!("fixtures/static-deep.old.dw"),
            include_str!("fixtures/static-deep.current.dw"),
        ),
        (
            include_str!("fixtures/static-keyword.old.dw"),
            include_str!("fixtures/static-keyword.current.dw"),
        ),
        (
            include_str!("fixtures/static-multi.old.dw"),
            include_str!("fixtures/static-multi.current.dw"),
        ),
        (
            include_str!("fixtures/static-literals.old.dw"),
            include_str!("fixtures/static-literals.current.dw"),
        ),
    ];
    for (old, current) in cases {
        assert_ne!(old, current, "control must discriminate the old renderer");
        assert!(ParsedPolicySet::parse(old, &service()).is_err());
        let converted = convert(old).unwrap();
        assert_eq!(converted.statement, current);
        assert!(!converted.rewrites.is_empty());
    }
}

#[test]
fn macro_definitions_refuse_but_named_attributes_and_annotations_do_not() {
    let source = "def cedar always() = true; permit(principal, action, resource);";
    assert_eq!(
        convert(source).unwrap_err().kind,
        MigrationErrorKind::UnsupportedSyntax
    );
    let current =
        "@def(\"migration\") permit(principal, action, resource) when { context.def == true };";
    assert_eq!(convert(current).unwrap().statement, current);
}
