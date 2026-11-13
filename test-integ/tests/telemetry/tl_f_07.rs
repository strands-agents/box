use strands_det_harness::det_case;
use strands_det_harness::telemetry::{POLICY_SCOPE, REDACTED};

/// The value planted in the workspace, which the record must never hold.
const SECRET: &str = "TL_SECRET_c0ffee";

// The Shell holds its arguments POST-expansion, so `echo $(cat file)` puts the file's CONTENTS in
// the argument vector. A target may ship that record to a vendor endpoint with a credential
// attached, so a secret read inside the box must not leave inside the record of reading it.
//
// The Shell does not say which words the script stated, so the record redacts every argument that
// is not a plain flag. What was read is still named, by the `fs:read` decision on its path.
det_case! {
    name: tl_f_07,
    id:   "TL-F-07",
    desc: "An expanded argument never reaches the record, and the read it made is still named",
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
        journal.assert_decision("fs:read", "tl-secret.txt", "permit");

        let records = journal.logs_under(POLICY_SCOPE);
        for program in ["echo", "cat"] {
            let record = records
                .iter()
                .find(|record| {
                    record.attribute("process.command") == Some(program)
                        && record.attribute("strands.box.policy.action") == Some("shell:exec")
                        && record
                            .lists
                            .get("process.command_args")
                            .is_some_and(|args| args.iter().any(|arg| arg == REDACTED))
                })
                .unwrap_or_else(|| panic!("no `{program}` record with a redacted argument"));
            assert!(
                record
                    .lists
                    .get("process.command_args")
                    .is_some_and(|args| args.iter().skip(1).all(|arg| arg == REDACTED)),
                "every argument of `{program}` is redacted: {:?}",
                record.lists.get("process.command_args")
            );
        }
    }
}
