use serde_json::json;
use strands_det_harness::telemetry::{
    AGENT_CLAIMED, POLICY_SCOPE, SOURCE_AGENT, SOURCE_BOX, post_as_workload,
};
use strands_det_harness::{det_case, sh_quote};

/// A harness attribute outside the box's reserve, which must survive the relay.
const MARKER_KEY: &str = "tl.forged.marker";

/// The marker's value, which is how this case finds the relayed record again.
const MARKER: &str = "TL_FORGED_MARKER";

/// The box name the payload claims. The reserve is stripped, so it must reach no file.
const FORGED_BOX: &str = "TL_FORGED_BOX";

/// The resource the payload's forged permit names.
const FORGED_RESOURCE: &str = "TL_FORGED_RESOURCE";

/// One OTLP-JSON log request claiming to be the box's own permit.
fn forged_payload() -> String {
    let attribute =
        |key: &str, value: &str| json!({"key": key, "value": {"stringValue": value}});
    json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [
                    attribute("strands.box.source", SOURCE_BOX),
                    attribute("strands.box.name", FORGED_BOX),
                    attribute("strands.box.run.id", "TL_FORGED_RUN"),
                ],
            },
            "scopeLogs": [{
                "scope": { "name": POLICY_SCOPE },
                "logRecords": [{
                    "attributes": [
                        attribute("strands.box.policy.action", "fs:read"),
                        attribute("strands.box.policy.resource", FORGED_RESOURCE),
                        attribute("strands.box.policy.verdict", "permit"),
                        attribute(MARKER_KEY, MARKER),
                    ],
                    "severityText": "permit",
                    "severityNumber": 9,
                }],
            }],
        }],
    })
    .to_string()
}

// The collector binds a loopback port and the box hands the workload its address in
// OTEL_EXPORTER_OTLP_ENDPOINT, with no credential. So the receiver is reachable by a process the box
// treats as untrusted, and a payload it posts reaches the same file the box's own refusals reach.
//
// The route is `bash`'s own `/dev/tcp` redirection rather than a program, so the workload needs no
// exec grant and nothing passes the broker. That is the point: this is the reach the workload holds
// by construction, not one the case grants it.
//
// Three properties must hold on the file, and an agent forging a permit was a real defect here:
//
//  1. The `strands.box.` reserve is stripped at every level, so the forged box name, run id and
//     decision attributes reach no file.
//  2. A scope claiming the box's namespace is renamed, so a reader selecting on the policy scope
//     never reads the payload as a decision.
//  3. Each resource is stamped `strands.box.source = "agent"`, and the strip and the stamp are one
//     function, so no route can do one without the other.
//
// Two controls stop the absences being vacuous. An attribute outside the reserve survives, so a
// receiver that dropped the whole payload would satisfy every absence and record nothing at all. And
// the run makes one REAL decision through the `zsh` alias first, so the file holds a genuine record
// under the policy scope beside the payload — without it, "no decision names the forged resource"
// holds in a file that holds no decision at all.
det_case! {
    name: tl_f_08,
    id:   "TL-F-08",
    desc: "A payload the workload posts to the receiver is stripped, renamed and stamped `agent`, and forges no decision",
    run: |b| {
        b.reset_policy();
        // One real decision first, then the forged payload, in one run and one file.
        let real_read = format!(
            "zsh -lc {}; ",
            sh_quote("echo DET_MEDIATED; cat readable.txt")
        );
        let r = b.run_sh(&format!(
            "{real_read}{}",
            post_as_workload("/v1/logs", &forged_payload())
        ));
        r.assert_entered();
        r.assert_contains("LISTED_CONTENT");
        r.assert_absent("TL_DIAL_FAILED");
        r.assert_contains("TL_POSTED");
        // The receiver answers a fixed `{}` on every status, so the status line is the only reply
        // that says it accepted the payload.
        r.assert_contains("200");

        let journal = b.telemetry();
        journal.assert_recorded();
        journal.assert_well_formed();

        // The payload arrived, and it arrived as the agent's.
        let relayed = journal
            .logs()
            .into_iter()
            .find(|record| record.attribute(MARKER_KEY) == Some(MARKER))
            .unwrap_or_else(|| {
                panic!(
                    "the posted payload reached no record; the file names scopes {:?} and sources \
                     {:?}",
                    journal.scopes(),
                    journal.sources(),
                )
            });
        assert_eq!(
            relayed.producer.source.as_deref(),
            Some(SOURCE_AGENT),
            "every relayed resource is stamped as the agent's, whatever it claimed",
        );
        assert_eq!(
            relayed.scope,
            format!("{AGENT_CLAIMED}{POLICY_SCOPE}"),
            "a scope claiming the box's namespace is renamed",
        );
        for stripped in [
            "strands.box.policy.action",
            "strands.box.policy.resource",
            "strands.box.policy.verdict",
        ] {
            assert_eq!(
                relayed.attribute(stripped),
                None,
                "the reserve is stripped, so the payload keeps no {stripped}: {:?}",
                relayed.attributes,
            );
        }

        // The box's own decision is here, which is what makes the two absences below mean something.
        journal.assert_mediated_entry();
        journal.assert_decision("fs:read", "readable.txt", "permit");

        // No reader can mistake the payload for a decision: it is under no policy scope, and the
        // shared decision parser finds nothing.
        let under_policy = journal.logs_under(POLICY_SCOPE);
        assert!(
            !under_policy.is_empty(),
            "the run's own decision must be under {POLICY_SCOPE}, or the next check reads an empty set",
        );
        assert!(
            under_policy
                .iter()
                .all(|record| record.attribute(MARKER_KEY).is_none()),
            "the payload must reach no record under {POLICY_SCOPE}",
        );
        let decisions = journal.decisions();
        assert!(
            !decisions.is_empty(),
            "the run decided something, or the next check reads an empty set",
        );
        assert!(
            decisions
                .iter()
                .all(|decision| decision.resource != FORGED_RESOURCE),
            "the payload forged a permit, and no decision may name {FORGED_RESOURCE}; the parser \
             read {:?}",
            decisions
                .iter()
                .map(|decision| (&decision.action, &decision.resource, &decision.verdict))
                .collect::<Vec<_>>(),
        );
        journal.assert_absent(
            FORGED_BOX,
            "the payload claimed another box's name, and the reserve is stripped",
        );
        journal.assert_absent(
            "TL_FORGED_RUN",
            "the payload claimed a run id, and the reserve is stripped",
        );
        b.record_note(format!(
            "relayed under {:?} as {:?}; sources {:?}",
            relayed.scope, relayed.producer.source, journal.sources(),
        ));
    }
}
