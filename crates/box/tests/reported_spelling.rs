//! The test fixture's `~` mapping must equal the spelling a decision carries.
//!
//! **The fixture authors policies, so its mapping decides whether a rule fires.** It substitutes
//! `{box_home}` and `{workspace}` into an authored `policy.dw`, and a rule is matched against
//! `context.input.path` — which the interpreters report as `~/<relative>`. A fixture that wrote the
//! host path wrote a rule that loads, strict-validates, and matches nothing.
//!
//! That failure mode is not hypothetical, and it is worse than a red test: it produces a **real
//! finding shape**. Measured while consolidating these mappings,
//! `reading_a_secret_through_the_alias_closes_egress` reported egress staying open after a secret
//! read, which reads as two `Policy` instances rather than as a fixture defect.
//!
//! There are three copies of this mapping, and each is checked against `policy` rather than against
//! the others:
//!
//! | Copy | What it is for | Checked by |
//! |---|---|---|
//! | `policy`'s `ApprovedPath::reported` | what a decision reads | it is the reference |
//! | `box`'s `layout::reported_under_home` | what a generated `policy.dw` says | `layout.rs`'s `the_generated_spelling_is_the_spelling_a_decision_reads` |
//! | the fixture's `reported_under_home` | what an authored fixture policy says | this file |
//!
//! `policy` is the reference in both, so the two consumers cannot agree with each other and be
//! wrong together.

mod support {
    pub mod fixture;
}

use std::path::Path;

use policy::PathResolver;

/// What a decision reads for `path`, through `policy`'s own public resolver.
fn policy_reports(path: &Path, home: &Path) -> String {
    PathResolver::over([home.to_path_buf()])
        .expect("the home is one absolute root")
        .reporting_under(home.to_path_buf())
        .approve_host(path)
        .expect("a path under the declared root")
        .reported()
        .into_owned()
}

/// Every shape a fixture substitutes reports identically on both sides.
#[test]
fn the_fixture_writes_the_spelling_policy_reports() {
    let home = tempfile::tempdir().expect("a home");
    // The resolver canonicalizes, so compare against a canonical home.
    let canonical = home.path().canonicalize().expect("canonical home");
    let workspace = canonical.join("service");
    std::fs::create_dir_all(workspace.join("src")).expect("a workspace");
    std::fs::write(workspace.join("src/main.rs"), "fn main() {}\n").expect("a file in it");

    for path in [
        canonical.clone(),
        workspace.clone(),
        workspace.join("src"),
        workspace.join("src/main.rs"),
    ] {
        let text = path.display().to_string();
        assert_eq!(
            support::fixture::reported_under_home(&text, &canonical),
            policy_reports(&path, &canonical),
            "the fixture substitutes one spelling for {text} and policy reports another, so an \
             authored rule names a path no decision carries"
        );
    }

    // The home itself is `~` and not `~/`. A trailing slash is the same directory spelled worse,
    // and `like "~/*"` does not match `~`, so a rule scoped to the home would behave differently
    // on the two sides for the one path an operator is most likely to name.
    let text = canonical.display().to_string();
    assert_eq!(
        support::fixture::reported_under_home(&text, &canonical),
        "~"
    );
    assert_eq!(policy_reports(&canonical, &canonical), "~");
}

/// A path outside the home keeps its host spelling.
///
/// **The paired negative, and it is what makes the comparison above measure the mapping.** Without
/// it, an implementation that abbreviated nothing at all would satisfy every assertion there by
/// returning the host path twice.
#[test]
fn a_path_outside_the_home_is_not_abbreviated() {
    let home = tempfile::tempdir().expect("a home");
    let outside = tempfile::tempdir().expect("a directory beside it");
    let canonical_home = home.path().canonicalize().expect("canonical home");
    let canonical_outside = outside.path().canonicalize().expect("canonical outside");
    let text = canonical_outside.display().to_string();

    let reported = support::fixture::reported_under_home(&text, &canonical_home);
    assert_eq!(
        reported, text,
        "a path outside the home has no `~` spelling, so it keeps the host path"
    );
    assert!(
        !reported.starts_with('~'),
        "an abbreviation outside the home would name the wrong file"
    );
}
