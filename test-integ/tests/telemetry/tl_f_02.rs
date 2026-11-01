use strands_det_harness::det_case;
use strands_det_harness::telemetry::{CONTROL_OPERATION_KEY, CONTROL_SCOPE, SOURCE_BOX};

// A merged store holds records from many boxes and many runs, so every record must say which box
// and which run produced it. The attribute is spelled `strands.box.name` and holds the box ID the
// box minted, never the `name` key the operator authored — a reader matching on the authored name
// finds nothing, which is why this case reads the id out of the stored record.
//
// One `strands-box run` is one `strands.box.run.id`. The fixture preflight is a run of its own, so
// the file holds two ids and each names one `box_started`. That count is what proves the id tracks a
// run rather than a box: an id minted per box would appear once for both runs.
det_case! {
    name: tl_f_02,
    id:   "TL-F-02",
    desc: "Every record names this box's own id, the producer `box`, and one run id per `strands-box run`",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated("echo TL_RAN");
        r.assert_contains("TL_RAN");

        let journal = b.telemetry();
        journal.assert_recorded();
        let box_id = b.box_id();
        let runs = journal.assert_identity(&box_id, SOURCE_BOX);

        // The preflight and this case's own run, and nothing else ran.
        assert_eq!(
            runs.len(),
            2,
            "the preflight and this case are two runs, and the file names {runs:?}",
        );

        // One run starts once. A second `box_started` under one id would mean two runs shared an id.
        for run in &runs {
            let started = journal
                .logs_under(CONTROL_SCOPE)
                .into_iter()
                .filter(|record| {
                    record.producer.run_id.as_deref() == Some(run.as_str())
                        && record.attributes.get(CONTROL_OPERATION_KEY).map(String::as_str)
                            == Some("box_started")
                })
                .count();
            assert_eq!(
                started, 1,
                "run {run} names {started} `box_started` operations; one run starts once",
            );
        }
        b.record_note(format!("box_id {box_id}, runs {runs:?}"));
    }
}
