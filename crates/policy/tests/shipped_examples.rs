//! Every policy shipped under `examples/` must load against the real schema.
//!
//! An example that does not load is worse than no example: it is the first thing an operator
//! copies. The sweep discovers the files rather than listing them, because an enumerated list
//! covered two and left six shipping actions that no longer exist.

mod support;

use std::path::{Path, PathBuf};

use policy::Policy;

/// The repository root, from this crate's manifest directory.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits at <root>/crates/policy")
        .to_path_buf()
}

/// Every authored policy under `examples/`, whatever extension it carries.
fn shipped_policies(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            shipped_policies(&path, found);
            continue;
        }
        let is_policy = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.ends_with(".dw") || name.ends_with(".cedar") || name.ends_with(".dw.in")
            });
        if is_policy {
            found.push(path);
        }
    }
}

/// Every shipped example policy loads.
///
/// One test over every file rather than one test per file, so adding an example needs no edit
/// here. The count assertion is what stops the sweep passing vacuously: a moved directory or a
/// changed extension would otherwise find nothing and report success.
#[test]
fn every_shipped_example_policy_loads() {
    let mut policies = Vec::new();
    shipped_policies(&repository_root().join("examples"), &mut policies);
    policies.sort();

    assert!(
        !policies.is_empty(),
        "the sweep found no policies under examples/; has the tree moved or has an extension changed?"
    );

    for path in &policies {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        // An empty policy is a legitimate example — it states that nothing is permitted — and
        // `open` accepts it, so no file is skipped.
        support::open_policy(vec![Policy {
            origin: path.clone(),
            text,
        }])
        .unwrap_or_else(|error| {
            panic!(
                "the shipped example {} must load against the real schema: {error}",
                path.display()
            )
        });
    }
}
