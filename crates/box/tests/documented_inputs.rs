//! The README's input table must name only keys the parser accepts.
//!
//! Not platform-gated, and it reads files rather than linking the crate — the config
//! parser is `[[bin]]`-private, so a test cannot call it, but it can compare the two
//! documents that must agree.
//!
//! This exists because the table drifted: it advertised a `shell` config key that has
//! never been a field, so an operator following box's own README wrote a config the
//! parser refuses. A README that documents a key the code rejects is worse than one
//! that omits it — the operator trusts the doc and blames the tool.
//!
//! **Now executed, and the second test exists because the first missed a real drift.**
//! `every_documented_config_key_exists_in_the_parser` matches only the spelling
//! `` `x` in the config file ``, which appears in the four-input table alone. So renaming
//! the egress destination key from `endpoint` to `host` in the parser while leaving
//! `` | `endpoint` | `` in the README's egress table left this suite green — measured on
//! 2026-08-10 by reverting exactly that one row.
//!
//! That table is the one an operator copies from most, so it needed covering too. Both
//! tests are proven to fire: reinstating the stale `shell` row fails the first, and a
//! README credential key with no `EgressEntry` field fails the second.

use std::path::Path;

#[path = "support/parser_source.rs"]
mod parser_source;

use parser_source::fields_of;

/// Every `key` the README's input table claims lives "in the config file" must be a
/// field on the parser's wire record.
#[test]
fn every_documented_config_key_exists_in_the_parser() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = std::fs::read_to_string(crate_root.join("README.md")).expect("read README.md");
    let config = parser_source::config_source();

    // The wire record is the contract. Take only its field names, so a key named in a
    // doc comment elsewhere in the file cannot vouch for itself.
    let record = config
        .split_once("struct ConfigFile {")
        .expect("config.rs declares `struct ConfigFile`")
        .1
        .split_once("\n}")
        .expect("the struct closes")
        .0;

    let mut missing = Vec::new();
    for line in readme.lines() {
        // Rows spell a key as `` `name` in the config file ``.
        for fragment in line.split('`') {
            let claimed = fragment.trim();
            if claimed.is_empty() || claimed.contains(' ') {
                continue;
            }
            // A `[[table.path]]` spelling names a nested section, not a field on the
            // top-level record, so it is out of this check's reach.
            if claimed.starts_with('[') {
                continue;
            }
            if !line.contains(&format!("`{claimed}` in the config file")) {
                continue;
            }
            let declared = record
                .lines()
                .any(|field| field.trim().starts_with(&format!("{claimed}:")));
            if !declared {
                missing.push(claimed.to_string());
            }
        }
    }

    assert!(
        missing.is_empty(),
        "README documents config keys the parser has no field for: {missing:?} — \
         either add the field or stop advertising it"
    );
}

/// Every key in the README's credential table must be a field on `EgressEntry`.
///
/// This is the table an operator copies a `[[credential]]` block from, so a key here
/// that the parser refuses fails the run at `configure` with `unknown field`.
#[test]
fn every_documented_credential_key_exists_in_the_entry() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = std::fs::read_to_string(crate_root.join("README.md")).expect("read README.md");
    let config = parser_source::config_source();

    let declared = fields_of(&config, "struct EgressEntry {");
    assert!(
        declared.contains(&"destinations".to_string()),
        "the field reader found no `destinations` on EgressEntry, so it is matching nothing \
         and this test would pass vacuously: {declared:?}"
    );

    // Scoped to the section that documents the keys, because a leading `` | `x` | `` row is
    // not unique to it: the `## Commands` table has the same shape, and an unscoped scan
    // reported every verb as a missing egress field.
    let section = readme
        .split_once("## Egress targets")
        .expect("README has an `## Egress targets` section")
        .1;
    let section = section
        .split_once("\n## ")
        .map_or(section, |(body, _)| body);

    // **A documented key may be dotted, and the filter must accept that or check nothing.**
    //
    // `secret` became a table on 2026-08-19, so four of the five keys are now spelled
    // `secret.<field>`. The filter here rejected any name containing `.`, which meant it *skipped*
    // all four and passed while checking one key — the "a criterion passes because a check went
    // missing" failure this suite exists to prevent. `EgressSecret`'s fields are read for the same
    // reason `EgressEntry`'s are, and the probe below proves each reader found something.
    let nested = fields_of(&config, "struct EgressSecret {");
    assert!(
        nested.iter().any(|name| name == "reference"),
        "the field reader found no `reference` on EgressSecret, so the nested keys are unchecked \
         and this test would pass vacuously: {nested:?}"
    );

    // A key row leads with the key: `| `name` | default | meaning |`.
    let mut missing = Vec::new();
    let mut checked = 0;
    for line in section.lines() {
        let Some(rest) = line.trim().strip_prefix("| `") else {
            continue;
        };
        let Some((claimed, _)) = rest.split_once("` |") else {
            continue;
        };
        if claimed.is_empty()
            || !claimed.chars().all(|character| {
                character.is_ascii_lowercase() || character == '_' || character == '.'
            })
        {
            continue;
        }
        checked += 1;
        // `secret.ref` is the file's spelling; `reference` is the Rust field, because `ref` is a
        // keyword. The doc is the operator's contract, so the doc's spelling is what maps.
        let found = match claimed.split_once('.') {
            Some(("secret", "ref")) => nested.iter().any(|name| name == "reference"),
            Some(("secret", field)) => nested.iter().any(|name| name == field),
            Some(_) => false,
            None => declared.iter().any(|name| name == claimed),
        };
        if !found {
            missing.push(claimed.to_string());
        }
    }

    // The whole table, not one row. It documented five keys when this was written, and a filter
    // that silently stopped matching is what this counts against.
    assert!(
        checked >= 5,
        "only {checked} documented key rows were checked, so the row filter has stopped matching \
         the table it reads"
    );

    assert!(
        missing.is_empty(),
        "the README's credential table documents keys `EgressEntry` has no field for: \
         {missing:?} — an operator copying that row gets `unknown field` at configure"
    );
}
