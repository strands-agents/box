use strands_det_harness::det_case;
use strands_det_harness::telemetry::{CONTROL_SCOPE, POLICY_SCOPE, Payload};

// The file format is this crate's own: `opentelemetry-stdout` writes a debug format, not the
// Collector's. So a reader cannot be told "it is OTLP" and left to guess the framing. This case
// states the framing a `jq` recipe depends on: one line is one request, a line names exactly one of
// the three signal keys, and no line is blank or partial.
//
// Shape no longer tells a box record from a harness payload, so a reader selects on the scope. The
// box writes two scopes and no third, and a query that names neither reads the wrong record shape.
det_case! {
    name: tl_f_01,
    id:   "TL-F-01",
    desc: "The default destination is one OTLP-JSON request per line, under the box's own two scopes and no third",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated("echo TL_RAN; cat readable.txt");
        r.assert_contains("TL_RAN");
        r.assert_contains("LISTED_CONTENT");

        let journal = b.telemetry();
        journal.assert_recorded();
        journal.assert_well_formed();
        journal.assert_scopes_are_the_boxs_own();

        // Both halves of one decision reach the file: the record, and the span derived from it.
        assert!(
            journal.count_of(Payload::Logs) > 0 && journal.count_of(Payload::Spans) > 0,
            "the file holds {} log request(s) and {} span request(s); a run records both",
            journal.count_of(Payload::Logs),
            journal.count_of(Payload::Spans),
        );
        assert!(
            !journal.logs_under(POLICY_SCOPE).is_empty(),
            "no decision reached {POLICY_SCOPE}: scopes are {:?}",
            journal.scopes(),
        );
        assert!(
            !journal.logs_under(CONTROL_SCOPE).is_empty(),
            "no control operation reached {CONTROL_SCOPE}: scopes are {:?}",
            journal.scopes(),
        );
        b.record_note(format!(
            "{} request(s): {} logs, {} spans; scopes {:?}",
            journal.lines.len(),
            journal.count_of(Payload::Logs),
            journal.count_of(Payload::Spans),
            journal.scopes(),
        ));
    }
}
