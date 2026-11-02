//! Exact temporary exceptions shared by the runner and verdict reducer.

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

/// No current case has an authorized quarantine exception.
pub const TEMPORARY_QUARANTINE: &[Quarantine] = &[];

#[cfg(test)]
pub(crate) const TEST_QUARANTINE: &[Quarantine] = &[Quarantine {
    id: "CN-Q-01",
    platform: "linux",
    reason: "synthetic runner and reducer fixture",
    issue: "test-only exception",
    owner: "box-maintainers",
    restore_when: "the synthetic exception is removed",
}];

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
    fn the_quarantine_is_empty() {
        assert!(TEMPORARY_QUARANTINE.is_empty());
    }

    #[test]
    fn the_note_is_self_describing_and_prefixed() {
        let text = note(&TEST_QUARANTINE[0]);
        assert!(text.starts_with(QUARANTINE_NOTE_PREFIX));
        for needle in [
            "CN-Q-01 on linux",
            "test-only exception",
            "owner: box-maintainers",
            "restore when:",
        ] {
            assert!(text.contains(needle), "{text}");
        }
        assert!(!text.starts_with(crate::verdict::SKIP_NOTE_PREFIX));
    }
}
