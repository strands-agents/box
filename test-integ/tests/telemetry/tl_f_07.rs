use strands_det_harness::det_case;
use strands_det_harness::telemetry::{POLICY_SCOPE, REDACTED};

/// The value planted in the workspace, which the record must never hold.
const SECRET: &str = "TL_SECRET_c0ffee";

// The Shell holds its arguments POST-expansion, so `echo $(cat file)` puts the file's CONTENTS in
// the argument vector. A target may ship that record to a vendor endpoint with a credential
// attached, so a secret read inside the box must not leave inside the record of reading it.
//
// What decides reportability is PROVENANCE, not shape. A word that was literal in the script is
// already in a file the operator can read, so it is reported; an expanded word is redacted unless it
// is a path or a plain flag. Shape alone was tried and is useless — `pipefail` and a password are
// the same shape.
//
// The two halves are asserted together on purpose. The absence alone passes against a box that
// redacts every argument, which would lose the audit trail; the presence of the literal `cat`
// argument is what shows the record still names what was read.
det_case! {
    name: tl_f_07,
    id:   "TL-F-07",
    desc: "An expanded argument never reaches the record, and a literal one still does",
    run: |b| {
        b.reset_policy();
        let planted = b.workspace().join("tl-secret.txt");
        std::fs::write(&planted, format!("{SECRET}\n"))
            .unwrap_or_else(|error| panic!("DET_ERROR: plant the secret: {error}"));

        let r = b.run_mediated("echo $(cat tl-secret.txt)");
        // The control: the substitution ran and the Shell really read the file. Without this the
        // absence below would hold for a run that never read anything.
        r.assert_contains(SECRET);
        r.assert_mediated_permitted("fs:read", "tl-secret.txt");

        let journal = b.telemetry();
        journal.assert_recorded();
        journal.assert_well_formed();
        journal.assert_absent(
            SECRET,
            "an expanded argument carries the file's contents, so the record must redact it",
        );
        journal.assert_present(
            "tl-secret.txt",
            "the literal argument to `cat` was in the script, so the record still names what was read",
        );

        // The `echo` whose argument was expanded holds the marker instead of the value. The run's own
        // `echo DET_MEDIATED` is literal and is not that record, so the search is by the marker.
        let records = journal.logs_under(POLICY_SCOPE);
        let redacted: Vec<_> = records
            .iter()
            .filter(|record| {
                record
                    .lists
                    .get("process.command_args")
                    .is_some_and(|args| args.iter().any(|arg| arg == REDACTED))
            })
            .collect();
        assert_eq!(
            redacted.len(),
            1,
            "one argument was expanded, so one record holds {REDACTED}; the records hold {:?}",
            records
                .iter()
                .map(|record| (
                    record.attribute("process.command"),
                    record.lists.get("process.command_args")
                ))
                .collect::<Vec<_>>(),
        );
        let echo = redacted[0];
        echo.assert_attribute("process.command", "echo");
        echo.assert_attribute("strands.box.policy.action", "shell:exec");

        // The `cat` record keeps both of its literal words, which is the audit data the gate preserves.
        let read = records
            .iter()
            .find(|record| {
                record.attribute("process.command") == Some("cat")
                    && record
                        .lists
                        .get("process.command_args")
                        .is_some_and(|args| args.iter().any(|arg| arg == "tl-secret.txt"))
            })
            .unwrap_or_else(|| panic!("no `cat` record names its literal argument"));
        assert!(
            read.lists
                .get("process.command_args")
                .is_some_and(|args| args.iter().all(|arg| arg != REDACTED)),
            "every word of `cat tl-secret.txt` was literal, so none is redacted: {:?}",
            read.lists.get("process.command_args"),
        );
        b.record_note(format!(
            "{SECRET} absent; echo args {:?}, cat args {:?}",
            echo.lists.get("process.command_args"),
            read.lists.get("process.command_args"),
        ));
    }
}
