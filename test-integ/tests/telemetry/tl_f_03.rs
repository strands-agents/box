use strands_det_harness::det_case;
use strands_det_harness::telemetry::{
    CAUSE_KEY, DEFAULT_DENY_RULE, NO_PERMIT_REASON, POLICY_SCOPE,
};

/// The attributes every decision record carries, whatever its verdict.
const DECISION_KEYS: [&str; 7] = [
    "strands.box.policy.principal",
    "strands.box.policy.action",
    "strands.box.policy.resource",
    "strands.box.policy.verdict",
    "strands.box.policy.cause",
    "strands.box.policy.rule",
    "strands.box.policy.category",
];

// A record is only useful if an auditor can read the decision back off it. So this case runs one
// permitted read and one denied read in the same run, and states every value both records hold.
//
// The pair is deliberate. A check that reads only a deny passes against a box that denies
// everything, and a check that reads only a permit passes against a box that permits everything.
// The pair also pins the two spellings apart: a permit names its own authored `@id`
// (`workspace_read`), while an absent permit names `<default-deny>` with the `no_match` cause.
//
// The resource is the spelling the box REPORTS, not the host path: a path under the operator home
// reads `~/…`, which is what makes an authored rule hold in every clone. `/etc/hosts` is outside
// that home, so it reads verbatim — both sides of one rule, in one case.
det_case! {
    name: tl_f_03,
    id:   "TL-F-03",
    desc: "A permit and a deny each carry the whole decision attribute set, with the reported resource, the cause and the rule",
    run: |b| {
        b.reset_policy();
        let before = unix_nanos_now();

        let r = b.run_mediated("cat readable.txt; cat /etc/hosts");
        r.assert_contains("LISTED_CONTENT");
        r.assert_mediated_permitted("fs:read", "readable.txt");
        r.assert_mediated_denied("fs:read", "/etc/hosts");

        let journal = b.telemetry();
        journal.assert_recorded();
        journal.assert_well_formed();
        let after = unix_nanos_now();

        let decisions = journal.logs_under(POLICY_SCOPE);
        let find = |action: &str, resource: &str| {
            decisions
                .iter()
                .find(|record| {
                    record.attribute("strands.box.policy.action") == Some(action)
                        && record
                            .attribute("strands.box.policy.resource")
                            .is_some_and(|held| held.contains(resource))
                })
                .unwrap_or_else(|| {
                    panic!(
                        "no {action} record names {resource}; {POLICY_SCOPE} holds {:?}",
                        decisions
                            .iter()
                            .map(|record| (
                                record.attribute("strands.box.policy.action"),
                                record.attribute("strands.box.policy.resource"),
                                record.attribute("strands.box.policy.verdict"),
                            ))
                            .collect::<Vec<_>>(),
                    )
                })
        };

        let permit = find("fs:read", "readable.txt");
        let deny = find("fs:read", "/etc/hosts");

        for record in [permit, deny] {
            for key in DECISION_KEYS {
                assert!(
                    record.attribute(key).is_some_and(|value| !value.is_empty()),
                    "line {}: every decision carries {key}, and this one holds {:?}",
                    record.line,
                    record.attributes,
                );
            }
            record.assert_attribute("strands.box.policy.principal", "agent:self");
            record.assert_attribute("strands.box.policy.category", "fs");
            assert_eq!(
                record.event_name, "strands.box.policy.decision",
                "line {}: a decision names its own event", record.line,
            );
            // The record sits on a span of its own, which TL-F-06 matches to `resourceSpans`.
            assert_eq!(
                record.trace_id.len(),
                32,
                "line {}: a decision carries a 16-byte trace id, and it reads {:?}",
                record.line,
                record.trace_id,
            );
            assert_eq!(
                record.span_id.len(),
                16,
                "line {}: a decision carries an 8-byte span id, and it reads {:?}",
                record.line,
                record.span_id,
            );
            assert!(
                record.at_unix_nano >= before && record.at_unix_nano <= after,
                "line {}: the record time {} is outside the run ({before}..{after})",
                record.line,
                record.at_unix_nano,
            );
        }

        // The permit names the rule that granted it, by the id the policy author wrote.
        permit.assert_attribute("strands.box.policy.verdict", "permit");
        permit.assert_attribute(CAUSE_KEY, "permitted");
        permit.assert_attribute("strands.box.policy.rule", "workspace_read");
        assert_eq!(
            permit.severity_text, "permit",
            "severity is what routes a record to its lane",
        );
        assert_eq!(
            permit.lists.get("strands.box.policy.determining.ids"),
            Some(&vec!["workspace_read".to_string()]),
            "the permit must name the rule that determined it: {:?}",
            permit.lists,
        );
        let reported = permit
            .attribute("strands.box.policy.resource")
            .expect("the permit names a resource");
        assert!(
            reported.starts_with("~/") && reported.ends_with("/readable.txt"),
            "a path under the operator home is reported `~`-relative, and it reads {reported:?}",
        );
        assert_eq!(
            permit.attribute("file.path"),
            Some(reported),
            "`file.path` and the policy resource are one path",
        );

        // The deny names no rule, because no permit matched. The reason is the refusal class, and it
        // is not the forbid class — no `forbid` in the fixture policy covers this path.
        deny.assert_attribute("strands.box.policy.verdict", "deny");
        deny.assert_attribute(CAUSE_KEY, "no_match");
        deny.assert_attribute("strands.box.policy.reason", NO_PERMIT_REASON);
        deny.assert_attribute("strands.box.policy.rule", DEFAULT_DENY_RULE);
        deny.assert_attribute("strands.box.policy.resource", "/etc/hosts");
        deny.assert_attribute("file.path", "/etc/hosts");
        assert_eq!(
            deny.severity_text, "deny",
            "severity is what routes a record to its lane",
        );
        assert!(
            deny.lists
                .get("strands.box.policy.determining.ids")
                .is_none_or(Vec::is_empty),
            "default-deny is no rule, so it names no determining id: {:?}",
            deny.lists,
        );
        assert_ne!(
            permit.severity_number, deny.severity_number,
            "two signals may never share a severity, because severity is what selects the lane",
        );

        b.record_note(format!(
            "permit {} rule={:?}; deny {} rule={:?}",
            reported,
            permit.attribute("strands.box.policy.rule"),
            deny.attribute("strands.box.policy.resource").unwrap_or_default(),
            deny.attribute("strands.box.policy.rule"),
        ));
    }
}

/// The wall clock in the units a record carries.
fn unix_nanos_now() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_nanos(),
    )
    .expect("the epoch fits a u64 until the year 2554")
}
