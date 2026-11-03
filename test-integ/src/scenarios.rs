//! Shared scenario setup and assertions for independently reported integration cases.

use crate::{BoxFixture, RunResult};

/// A move to a new path succeeds while replacement preserves both existing files.
pub struct MoveReplacement;

impl MoveReplacement {
    /// Permit moves under the fixture's existing deletion floor.
    pub fn permit(b: &BoxFixture) {
        b.apply_policy(
            r#"@id("mv") permit (principal, action == Box::Action::"fs:move", resource);"#,
        );
    }

    /// Verify the successful move, the replacement refusal, and the resulting contents.
    pub fn assert_result(r: &RunResult) {
        r.assert_mediated_permitted("fs:move", "fresh.txt");
        r.assert_contains("FRESH=n");
        assert!(
            r.decisions.iter().any(|d| d.denied()
                && d.resource.ends_with("/b.txt")
                && d.forbidden_by("no_deletes")),
            "the move onto b.txt must be refused by no_deletes; out=[{}]",
            r.snippet()
        );
        r.assert_contains("STATE=new,old");
    }
}
