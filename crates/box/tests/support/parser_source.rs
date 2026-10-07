//! Reading the config parser's field names out of its source.
//!
//! Three suites — `four_inputs.rs`, `documented_inputs.rs`, and `shipped_examples.rs` —
//! all have to answer "which keys does box accept?", and none of them can call the parser
//! to find out: `record::config` is `[[bin]]`-private, so an integration test cannot name
//! its types. Reading the source is the available answer, and it lives here once rather
//! than three times.
//!
//! This module was extracted after the second copy appeared, which is the same defect this
//! branch exists to remove — a second copy of one rule drifts toward weaker, and nothing
//! observes it.

#![allow(dead_code)] // Each suite uses a different part of this.

use std::path::{Path, PathBuf};

/// The repository root, from this crate's manifest directory.
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits at <root>/crates/box")
        .to_path_buf()
}

/// The config parser's source text: every file the `box.toml` vocabulary is declared across.
///
/// **Concatenated, not one file.** `telemetry.rs` was split out of `config.rs`, and a check that
/// scanned only `config.rs` would pass silently on a declaration that had moved. The same reason
/// `cli_source` exists beside this.
pub fn config_source() -> String {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    [
        "src/record/config/mod.rs",
        "src/record/config/process.rs",
        "src/record/config/egress.rs",
        "src/record/config/env.rs",
        "src/record/config/mcp.rs",
        "src/record/config/telemetry.rs",
    ]
    .iter()
    .map(|relative| {
        std::fs::read_to_string(crate_root.join(relative))
            .unwrap_or_else(|error| panic!("read {relative}: {error}"))
    })
    .collect::<Vec<_>>()
    .join("\n")
}

/// The argv parser's source text: `Cli`, `Command`, and their clap derives.
///
/// Split out of `config.rs`, so a suite asking "which FLAGS does box declare?" must read this
/// file. **A suite asking that question should read both**, with `config_source()`, because a
/// check that scans one file passes silently when a declaration moves to the other.
pub fn cli_source() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/command/cli.rs"))
        .expect("read src/command/cli.rs")
}

// `mcp_source` is gone: `config_source` spans the whole `config/` folder, so `McpEntry` is in it.

/// The field names a struct declares, in source order.
///
/// Takes only the field names, so a key named in a doc comment elsewhere in the file
/// cannot vouch for itself.
pub fn fields_of(config: &str, declaration: &str) -> Vec<String> {
    let body = config
        .split_once(declaration)
        .unwrap_or_else(|| panic!("config.rs declares `{declaration}`"))
        .1
        .split_once("\n}")
        .expect("the struct closes")
        .0;
    body.lines()
        .filter_map(|line| {
            let field = line.trim().strip_suffix(',')?;
            let (name, _) = field.split_once(": ")?;
            // A field may carry a visibility, as in `pub(crate) work_dir: …`. Take the
            // last token, so the visibility does not hide the name — an earlier version
            // matched the whole prefix and a `pub(crate)` field walked straight past it.
            let name = name.rsplit(' ').next()?;
            name.chars()
                .all(|character| character.is_ascii_lowercase() || character == '_')
                .then(|| name.to_string())
        })
        .collect()
}

/// Every config key box accepts, from every record, in the operator's spelling.
///
/// **A guard has to know every record it checks against.** `Bind`'s keys were once missing, and
/// the omission read as the *example* being wrong: a shipped config declaring a bind was reported
/// as assigning `path` and `at`, keys the parser accepts perfectly well. So each nested section's
/// record is listed, and each has a probe below proving the reader found one of its keys.
pub fn accepted_keys(config: &str) -> Vec<String> {
    let mut accepted = fields_of(config, "struct ConfigFile {");
    accepted.extend(fields_of(config, "struct EgressEntry {"));
    // `[agent]` and every `[tool.<name>]` share one record, and its `filesystem` is a second.
    accepted.extend(fields_of(config, "struct ProcessSpec {"));
    accepted.extend(fields_of(config, "struct Filesystem {"));
    // `[mcp.<name>]`'s record lives in `record/config/mcp.rs` rather than `config.rs`, because that
    // module owns the MCP vocabulary. It is read from there for the same reason `Bind`'s keys were
    // once missing: a record this reader does not know reads as the *example* being wrong.
    //
    // **`McpEntry`, not `McpServer`.** The operator writes the entry, whose keys are the ones a
    // shipped config may name. `McpServer` is the record shape and carries a `name` field that
    // comes from the table header rather than from a key, so reading it here would accept a key no
    // operator can write.
    //
    // **`McpEntry` is a `#[serde(tag = "type")]` enum**, so its keys are the union of its variants'
    // fields (`command` for stdio; `destinations`/`secret` for http). The `type` tag that selects
    // the variant is an attribute rather than a field, so the reader cannot see it — add it here.
    accepted.extend(fields_of(config, "enum McpEntry {"));
    accepted.push("type".to_string());

    // A reader that matches nothing would make every caller pass vacuously, so prove it
    // found one key from each record before anyone relies on it.
    for (key, record) in [
        ("policy", "ConfigFile"),
        ("destinations", "EgressEntry"),
        ("workspace", "ProcessSpec"),
        ("read_file", "Filesystem"),
        ("command", "McpEntry"),
    ] {
        assert!(
            accepted.iter().any(|found| found == key),
            "no `{key}` among {record}'s fields, so the field reader is matching nothing: \
             {accepted:?}"
        );
    }
    accepted
}
