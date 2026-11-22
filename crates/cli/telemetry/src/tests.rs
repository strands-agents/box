use crate::{ContextBuilder, Pack, RunContext};
use serde_json::{Value, json};

fn builder() -> ContextBuilder {
    ContextBuilder::new("1.2.3").unwrap()
}

fn snapshot(builder: ContextBuilder) -> Value {
    serde_json::to_value(builder.finish()).unwrap()
}

const BASE: &[u8] = include_bytes!("../../../../resources/packs/base/pack.toml");
const CLAUDE: &[u8] = include_bytes!("../../../../resources/packs/claude/pack.toml");

fn pack<'a>(id: Option<&'a str>, bytes: &'a [u8], bundled_location: Option<bool>) -> Pack<'a> {
    Pack {
        id,
        bytes,
        grammar: None,
        bundled_location,
    }
}

fn validator() -> jsonschema::Validator {
    let schema: Value =
        serde_json::from_str(include_str!("../tests/fixtures/box.schema.json")).unwrap();
    jsonschema::draft4::new(&schema["definitions"]["run_context"]).unwrap()
}

#[test]
fn context_contains_normalized_metadata_and_explicit_unknowns() {
    for (os, family) in [
        ("macos", "macos"),
        ("linux", "linux"),
        ("windows", "windows"),
        ("freebsd", "other"),
        ("", "other"),
    ] {
        for (arch, target) in [
            ("aarch64", "aarch64"),
            ("x86_64", "x86_64"),
            ("arm", "other"),
        ] {
            let context = RunContext::new("9.8.7", os, Some("14.5".to_owned()), arch).unwrap();
            assert_eq!(context, context.clone());
            let value = serde_json::to_value(context).unwrap();
            assert_eq!(
                value,
                json!({
                    "box_version": "9.8.7",
                    "os_family": family,
                    "os_version": "14.5",
                    "build_arch": target,
                    "builtin_packs": null,
                    "mcp_configured": null,
                    "has_custom_packs": null,
                    "profile_policy_present": null,
                    "profile_hash": null
                })
            );
            assert!(validator().is_valid(&value));
        }
    }
}

#[test]
fn version_is_normalized_and_bounded_by_the_schema() {
    for valid in ["0.0.0", "1.2.3", "9999.9999.9999"] {
        assert!(ContextBuilder::new(valid).is_ok());
    }
    for invalid in [
        "",
        "1.2",
        "1.2.3.4",
        "01.2.3",
        "1.2.3-rc.1",
        "1.2.3+build",
        "1.10000.3",
        "10000.2.3",
        "1.2.10000",
        "1.2.-3",
        "1.2.+3",
        "1.2.3\n",
    ] {
        assert!(ContextBuilder::new(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn profile_hashes_saved_bytes_and_retains_no_source() {
    let mut context = builder();
    let mut bytes = b"abc".to_vec();
    context.profile(&bytes);
    bytes.clear();
    let value = snapshot(context);
    assert_eq!(
        value["profile_hash"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(!value.to_string().contains("abc"));

    let mut context = builder();
    context.profile(b"abc\n");
    assert_eq!(
        snapshot(context)["profile_hash"],
        "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb"
    );
}

#[test]
fn policy_observation_reads_the_declared_list_and_preserves_unknowns() {
    for (bytes, expected) in [
        (b"".as_slice(), Some(false)),
        (b"policies = []", Some(false)),
        (b"policies = ['rules.dw']", Some(true)),
        (b"policies = ['rules.dw', 'extra.dw']", Some(true)),
        (b"policies = ['missing.dw']", Some(true)),
        (b"policies = 'rules.dw'", None),
        (b"policies = [false]", None),
        (b"policies = ['']", None),
        (b"policies = ['${{ root }}/rules.dw']", None),
        (b"[", None),
        (b"\xff", None),
    ] {
        let mut context = builder();
        context.profile(bytes);
        assert_eq!(
            snapshot(context)["profile_policy_present"],
            json!(expected),
            "{bytes:?}"
        );
    }
}

#[test]
fn pack_graph_is_sorted_unique_and_excludes_custom_names() {
    let mut context = builder();
    context.packs([
        pack(Some("claude"), CLAUDE, Some(true)),
        pack(None, b"secret profile text", Some(false)),
        pack(Some("private-customer"), b"private", Some(true)),
        pack(Some("base"), BASE, Some(true)),
        pack(Some("claude"), CLAUDE, Some(true)),
    ]);
    let value = snapshot(context);
    assert_eq!(value["builtin_packs"], json!(["base", "claude"]));
    assert_eq!(value["has_custom_packs"], true);
    assert!(!value.to_string().contains("private"));
    assert!(!value.to_string().contains("secret"));
    assert!(validator().is_valid(&value));
}

#[test]
fn pack_membership_requires_both_matching_bytes_and_bundled_location() {
    for (bytes, location, custom) in [
        (BASE, Some(true), false),
        (b"edited".as_slice(), Some(true), true),
        (BASE, Some(false), true),
        (b"edited".as_slice(), None, true),
    ] {
        let mut context = builder();
        context.packs([pack(Some("base"), bytes, location)]);
        let value = snapshot(context);
        assert_eq!(
            value["builtin_packs"],
            if custom { json!([]) } else { json!(["base"]) }
        );
        assert_eq!(value["has_custom_packs"], custom);
    }
}

#[test]
fn adding_a_grammar_changes_a_catalog_pack() {
    for grammar in [b"".as_slice(), b"version = 1\n", b"version = 2\n"] {
        let mut context = builder();
        context.packs([Pack {
            grammar: Some(grammar),
            ..pack(Some("base"), BASE, Some(true))
        }]);
        let value = snapshot(context);
        assert_eq!(value["builtin_packs"], json!([]));
        assert_eq!(value["has_custom_packs"], true);
    }
}

#[test]
fn unknown_pack_location_replaces_a_previous_graph_with_null() {
    let mut known = builder();
    known.packs([pack(Some("base"), BASE, Some(true))]);
    assert_eq!(snapshot(known)["builtin_packs"], json!(["base"]));
    let mut context = builder();
    context.packs([pack(Some("base"), BASE, Some(true))]);
    context.packs([
        pack(Some("base"), BASE, Some(true)),
        pack(Some("claude"), CLAUDE, None),
        pack(None, b"custom", Some(false)),
    ]);
    let value = snapshot(context);
    assert_eq!(value["builtin_packs"], Value::Null);
    assert_eq!(value["has_custom_packs"], Value::Null);
}

#[test]
fn resolved_empty_graph_is_known_empty() {
    let mut context = builder();
    context.packs([]);
    let value = snapshot(context);
    assert_eq!(value["builtin_packs"], json!([]));
    assert_eq!(value["has_custom_packs"], false);
}
