use strands_det_harness::telemetry::{POLICY_SCOPE, SOURCE_BOX};
use strands_det_harness::{det_case, sh_quote};

// A declared `[telemetry.<name>]` REPLACES the box's default destination; it does not add a second
// one. An operator who declares a target and still finds records under `private/telemetry/` has two
// files to merge and no statement of which is complete.
//
// The default file is not asserted absent, because the fixture preflight is a run of its own and
// writes it before any configuration edit. What this case asserts is stronger and states the
// replacement directly: the default file does not GROW across the declared run, and the run ids in
// the two files are disjoint.
//
// The mediated entry proof moves with the records, so this case takes the NATIVE route and invokes
// the box's `zsh` alias itself. Every `RunResult` assertion on a mediated run first requires a
// journaled `shell:exec` read from the DEFAULT destination, so against a working replacement each one
// reports "no shell:exec decision was journaled" — which is the replacement working. The alias still
// enters the broker, and `Journal::assert_mediated_entry` reads that same proof off the declared
// file.
det_case! {
    name: tl_f_04,
    id:   "TL-F-04",
    desc: "A declared file target replaces the default destination: records land there, and the default file does not grow",
    run: |b| {
        b.reset_policy();
        let declared = b
            .workspace()
            .parent()
            .expect("the workspace has a parent")
            .join("declared-records.jsonl");

        // The preflight wrote the default destination, and this read is what makes "it did not grow"
        // a comparison of real content rather than one absence against another.
        let default_before = b.telemetry();
        default_before.assert_recorded();
        let preflight_runs = default_before.run_ids();
        let bytes_before = default_before.text.len();
        assert!(!preflight_runs.is_empty(), "the preflight is a run and names an id");

        let r = b.run_sh_with_config(
            b.with_telemetry_file(&declared, &[]),
            &format!(
                "zsh -lc {}",
                sh_quote("echo DET_MEDIATED; echo TL_DECLARED; cat readable.txt")
            ),
        );
        r.assert_contains("TL_DECLARED");
        r.assert_contains("LISTED_CONTENT");

        let journal = b.telemetry_at(&declared);
        journal.assert_recorded();
        journal.assert_well_formed();
        journal.assert_scopes_are_the_boxs_own();
        journal.assert_mediated_entry();
        journal.assert_decision("fs:read", "readable.txt", "permit");
        let runs = journal.assert_identity(&b.box_id(), SOURCE_BOX);
        assert!(
            !journal.logs_under(POLICY_SCOPE).is_empty(),
            "the declared target names no `include`, so it receives every signal, decisions included",
        );

        let default_after = b.telemetry();
        assert_eq!(
            default_after.text.len(),
            bytes_before,
            "the default destination held {bytes_before} byte(s) and now holds {}; a declared target \
             replaces it",
            default_after.text.len(),
        );
        for run in &runs {
            assert!(
                !preflight_runs.contains(run),
                "run {run} wrote to both destinations; a declared target replaces the default",
            );
        }
        b.record_note(format!(
            "{} request(s) at {}; the default held {bytes_before} byte(s) before and after",
            journal.lines.len(),
            declared.display(),
        ));
    }
}
