//! quarantine.rs — the TEMPORARY, exact, compiled allowlist of (case, platform) cells that record an
//! authorized `SKIP` instead of running, and the one note text that authorizes it.
//!
//! Why this exists: CN-W-05 and CN-W-06 author a `[tool.<name>.filesystem] exec` list, which a box
//! refuses at load (docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds).
//! Broad exec ships on macOS only, and broad exec for a Linux tool leaf is a currently-missing
//! feature. Both cases run only on linux, so the maintainers approved a temporary SKIP there until
//! that Linux broad-exec feature lands and the fixtures are aligned to it.
//!
//! What this is NOT: it is not a platform declaration, not a retry, and not suppression of a failure
//! anywhere else; any other case that fails stays FAIL/ERROR and turns the suite RED. A GREEN produced while this
//! list is non-empty is the explicitly REDUCED merge gate, not full qualification: `verdict.json`
//! carries `coverage_gate` and the `quarantine` array so reviewers see the exact gap.
//!
//! Runner and reducer read this ONE list: `run_case_on` writes the SKIP row with exactly
//! [`note`]'s text; `verdict::Summary::build` accepts a SKIP on an applicable platform only for a
//! listed cell with exactly that note, and turns a PASS/FAIL/ERROR for a listed cell (runner and
//! reducer disagreeing) into an integrity problem. Any SKIP on an unlisted cell, any note that
//! differs, a missing or duplicate row, a malformed row, a nonzero cargo exit, or any other failure
//! remains RED. See test-integ/QUARANTINE.md for how to remove the exception.

use serde::Serialize;

/// One authorized temporary exception: exactly one case on exactly one platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Quarantine {
    /// The case id as the manifest spells it.
    pub id: &'static str,
    /// The platform (`"macos"` / `"linux"`) on which the case records SKIP instead of running.
    pub platform: &'static str,
    /// What was observed, in one sentence.
    pub reason: &'static str,
    /// The tracked issue / evidence pointer.
    pub issue: &'static str,
    /// Who owns removing this entry.
    pub owner: &'static str,
    /// The condition under which the entry is deleted and the cell runs again.
    pub restore_when: &'static str,
}

/// The note prefix every authorized quarantine SKIP row carries. Distinct from
/// [`crate::verdict::SKIP_NOTE_PREFIX`] (declared-inapplicable platform) so the two kinds of SKIP
/// can never be confused in a report.
pub const QUARANTINE_NOTE_PREFIX: &str = "TEMPORARY QUARANTINE: ";

const TOOL_EXEC_ISSUE: &str = "the fixture authors [tool.<name>.filesystem] exec, which a box \
refuses at load: a tool leaf runs its toolchain through broad exec, and broad exec ships on macOS \
only. Broad exec for a Linux tool leaf is a currently-missing feature; until it lands, a Linux tool leaf cannot run a \
multi-binary toolchain the way this case needs";

const TOOL_EXEC_RESTORE_WHEN: &str = "broad exec for a Linux tool leaf is built (the currently-missing feature), the \
fixtures are aligned to it, these entries are deleted, and the full Linux deterministic suite passes with both cases \
enabled";

/// The exact, authorized list. Edit ONLY with the authorization recorded in test-integ/QUARANTINE.md;
/// the unit test `the_quarantine_is_exactly_the_authorized_set` pins its contents so any change is a
/// visible diff. When it is empty, GREEN means full coverage again with no other change.
pub const TEMPORARY_QUARANTINE: &[Quarantine] = &[
    Quarantine {
        id: "CN-W-05",
        platform: "linux",
        reason: "authors [tool.git.filesystem] exec, refused at load; the case runs only on linux, \
so it records a SKIP there pending broad exec for a Linux tool leaf",
        issue: TOOL_EXEC_ISSUE,
        owner: "box-maintainers",
        restore_when: TOOL_EXEC_RESTORE_WHEN,
    },
    Quarantine {
        id: "CN-W-06",
        platform: "linux",
        reason: "authors [tool.cargo.filesystem] and [tool.hello.filesystem] exec, refused at load; \
the case runs only on linux, so it records a SKIP there pending broad exec for a Linux tool leaf",
        issue: TOOL_EXEC_ISSUE,
        owner: "box-maintainers",
        restore_when: TOOL_EXEC_RESTORE_WHEN,
    },
];

/// The authorized entry for `(id, platform)`, if any. Exact string match on both.
pub fn lookup(id: &str, platform: &str) -> Option<&'static Quarantine> {
    TEMPORARY_QUARANTINE
        .iter()
        .find(|q| q.id == id && q.platform == platform)
}

/// Every entry that applies to `platform`, in list order.
pub fn for_platform(platform: &str) -> Vec<&'static Quarantine> {
    TEMPORARY_QUARANTINE
        .iter()
        .filter(|q| q.platform == platform)
        .collect()
}

/// The ONE note text an authorized SKIP row carries for `q`. The runner writes exactly this; the
/// reducer requires exactly this. It names the case, the platform, the reason, the issue, the owner
/// and the restoration condition, so the row is self-describing in `verdict.json`.
pub fn note(q: &Quarantine) -> String {
    format!(
        "{QUARANTINE_NOTE_PREFIX}{} on {}: {}; issue: {}; owner: {}; restore when: {}",
        q.id, q.platform, q.reason, q.issue, q.owner, q.restore_when
    )
}

/// What `verdict.json` reports for one entry that applies to the current platform.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QuarantineReport {
    pub id: &'static str,
    pub platform: &'static str,
    pub reason: &'static str,
    pub issue: &'static str,
    pub owner: &'static str,
    pub restore_when: &'static str,
    /// Whether a SKIP row with exactly the authorized note was recorded for this cell.
    pub applied: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_quarantine_is_exactly_the_authorized_set() {
        // Pinned on purpose: adding, widening or re-platforming an entry must show up here.
        let cells: Vec<(&str, &str)> = TEMPORARY_QUARANTINE
            .iter()
            .map(|q| (q.id, q.platform))
            .collect();
        assert_eq!(cells, vec![("CN-W-05", "linux"), ("CN-W-06", "linux")]);
        // The Linux tool-exec entries.
        for q in TEMPORARY_QUARANTINE
            .iter()
            .filter(|q| q.platform == "linux")
        {
            assert_eq!(q.owner, "box-maintainers");
            assert!(
                q.reason.contains("exec") && q.reason.contains("only on linux"),
                "{}",
                q.reason
            );
            assert!(
                q.issue.contains("refuses at load") && q.issue.contains("broad exec"),
                "{}",
                q.issue
            );
            assert!(
                q.restore_when.contains("broad exec for a Linux tool leaf")
                    && q.restore_when.contains("deleted"),
                "{}",
                q.restore_when
            );
        }
    }

    #[test]
    fn lookup_is_exact_on_case_and_platform() {
        assert!(lookup("CN-W-05", "linux").is_some() && lookup("CN-W-06", "linux").is_some());
        assert!(
            lookup("CN-W-05", "macos").is_none() && lookup("CN-W-06", "macos").is_none(),
            "the tool-exec cases are linux-only"
        );
        assert!(
            lookup("CN-E-01", "macos").is_none(),
            "an unlisted case cannot skip"
        );
        assert!(
            lookup("cn-w-05", "linux").is_none() && lookup("CN-W-05", "Linux").is_none(),
            "no case folding"
        );
        assert_eq!(for_platform("linux").len(), 2);
        assert!(for_platform("macos").is_empty());
    }

    #[test]
    fn the_note_is_self_describing_and_prefixed() {
        let text = note(lookup("CN-W-05", "linux").unwrap());
        assert!(text.starts_with(QUARANTINE_NOTE_PREFIX));
        for needle in [
            "CN-W-05 on linux",
            "broad exec",
            "owner: box-maintainers",
            "restore when:",
        ] {
            assert!(text.contains(needle), "{text}");
        }
        assert!(
            !text.starts_with(crate::verdict::SKIP_NOTE_PREFIX),
            "never confusable with a platform SKIP"
        );
    }
}
