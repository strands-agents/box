//! The classification source kinds this build implements, and how each checks and opens its
//! endpoint.

use std::sync::Arc;

use super::Source;

/// The test kind, which answers from a JSON file.
#[cfg(feature = "test-support")]
const IN_MEMORY: &str = "in-memory";

/// The kinds a release build implements: none, so a release build sends no name anywhere.
#[cfg_attr(
    all(feature = "test-support", not(test)),
    expect(
        dead_code,
        reason = "a test-support build implements the test kind, and only its tests read this"
    )
)]
const RELEASE: &[&str] = &[];

/// Every kind this build implements.
#[cfg(feature = "test-support")]
const IMPLEMENTED: &[&str] = &[IN_MEMORY];
/// Every kind this build implements.
#[cfg(not(feature = "test-support"))]
const IMPLEMENTED: &[&str] = RELEASE;

/// Refuse a kind this build does not implement, or an endpoint its kind cannot use.
pub(crate) fn check(kind: &str, endpoint: &str) -> Result<(), String> {
    check_in(IMPLEMENTED, kind, endpoint)
}

/// Open the source that `kind` names at `endpoint`.
pub(crate) fn open(kind: &str, endpoint: &str) -> Result<Arc<dyn Source>, String> {
    open_in(IMPLEMENTED, kind, endpoint)
}

/// [`check`] for a build that implements the kinds in `implemented`.
fn check_in(implemented: &[&str], kind: &str, endpoint: &str) -> Result<(), String> {
    if !implemented.contains(&kind) {
        return Err(unimplemented(kind, implemented));
    }
    match kind {
        #[cfg(feature = "test-support")]
        IN_MEMORY => super::memory::fixture_path(endpoint).map(drop),
        _ => {
            let _ = endpoint;
            Err(unimplemented(kind, implemented))
        }
    }
}

/// [`open`] for a build that implements the kinds in `implemented`.
fn open_in(implemented: &[&str], kind: &str, endpoint: &str) -> Result<Arc<dyn Source>, String> {
    if !implemented.contains(&kind) {
        return Err(unimplemented(kind, implemented));
    }
    match kind {
        #[cfg(feature = "test-support")]
        IN_MEMORY => {
            let path = super::memory::fixture_path(endpoint)?;
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("cannot read its in-memory fixture: {error}"))?;
            Ok(Arc::new(super::memory::InMemorySource::from_json(&text)?))
        }
        _ => {
            let _ = endpoint;
            Err(unimplemented(kind, implemented))
        }
    }
}

/// The refusal of `kind` by a build that implements `implemented`.
fn unimplemented(kind: &str, implemented: &[&str]) -> String {
    let offered = if implemented.is_empty() {
        "this build implements no enrichment kind".to_string()
    } else {
        format!(
            "this build implements {}",
            implemented
                .iter()
                .map(|kind| format!("{kind:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!("names kind {kind:?}, which this build of Box does not implement; {offered}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A release build implements no kind, so it refuses the test kind like any other, whatever
    /// features this test build has.
    #[test]
    fn a_release_build_refuses_every_kind() {
        assert!(RELEASE.is_empty());
        let refusal = "names kind \"in-memory\", which this build of Box does not implement; this \
                       build implements no enrichment kind";
        assert_eq!(
            check_in(RELEASE, "in-memory", "file:///srv/fixture.json"),
            Err(refusal.to_string())
        );
        assert_eq!(
            open_in(RELEASE, "in-memory", "file:///srv/fixture.json").err(),
            Some(refusal.to_string())
        );
    }
}
