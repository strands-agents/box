use strands_det_harness::telemetry::{CONTROL_SCOPE, DEFAULT_DENY_RULE, POLICY_SCOPE};
use strands_det_harness::{det_case, sh_quote};

/// Planted outside the workspace, so no rule permits reading it.
const DENIED_CONTENT: &str = "TL_DENIED_CONTENT";

// `include` is how an operator narrows a target, and the five words it takes are not the six signal
// names a record carries: the box expands `deny` into `policy_denied` alone. So a target naming
// `deny` must receive every refusal and nothing else — no permit, and no control-plane operation.
//
// Narrowing is the half that fails quietly. A target receiving everything would still hold every
// deny, so a case asserting only the deny's presence passes against a box that ignores `include`
// completely. The absences are therefore the claim, and the deny is the control that stops them being
// vacuous: a file holding nothing satisfies every absence.
//
// The deny also carries the entry proof. A deny-only target holds no `shell:exec` permit, so neither
// `RunResult::assert_mediated_permitted` nor `Journal::assert_mediated_entry` can be used here. An
// `fs:read` deny is a record only the broker produces, and the planted content is absent from the
// output, so together they state that the hosted Shell ran and was refused — a host zsh would have
// read the file and journaled nothing.
//
// The route is NATIVE and the case invokes the `zsh` alias itself, for the reason TL-F-04 states:
// every `RunResult` assertion on a mediated run reads its entry proof from the DEFAULT destination,
// which a declared target replaces.
det_case! {
    name: tl_f_05,
    id:   "TL-F-05",
    desc: "A target declaring include = [\"deny\"] receives every refusal and no permit, and no control-plane record",
    run: |b| {
        b.reset_policy();
        let outside = b
            .workspace()
            .parent()
            .expect("the workspace has a parent")
            .join("tl-denied.txt");
        std::fs::write(&outside, format!("{DENIED_CONTENT}\n"))
            .unwrap_or_else(|error| panic!("DET_ERROR: plant the unreadable file: {error}"));
        let declared = outside.with_file_name("denies-only.jsonl");

        let r = b.run_sh_with_config(
            b.with_telemetry_file(&declared, &["deny"]),
            &format!(
                "zsh -lc {}",
                sh_quote(&format!(
                    "echo DET_MEDIATED; cat readable.txt; cat {}",
                    outside.display()
                ))
            ),
        );
        // The permitted read printed, and the refused one did not.
        r.assert_contains("LISTED_CONTENT");
        r.assert_absent(DENIED_CONTENT);

        let journal = b.telemetry_at(&declared);
        journal.assert_recorded();
        journal.assert_well_formed();

        // The refusal reached the target, and only the broker produces this record.
        let deny = journal.assert_decision("fs:read", "tl-denied.txt", "deny");
        deny.assert_attribute("strands.box.policy.rule", DEFAULT_DENY_RULE);

        let records = journal.logs_under(POLICY_SCOPE);
        let verdicts: Vec<Option<&str>> = records
            .iter()
            .map(|record| record.attribute("strands.box.policy.verdict"))
            .collect();
        assert!(
            verdicts.iter().all(|verdict| *verdict == Some("deny")),
            "every record this target holds is a refusal, and it holds {verdicts:?}",
        );
        // The same run permitted a read and ran `shell:exec`, and neither is here.
        journal.assert_absent(
            "readable.txt",
            "the permitted read is a permit, and a target naming `deny` receives none",
        );
        journal.assert_absent(
            "shell:exec",
            "every `shell:exec` of this run was permitted, so none may reach a deny-only target",
        );
        journal.assert_absent(
            CONTROL_SCOPE,
            "`trace` is the word carrying the control plane, and `deny` is not it",
        );
        assert!(
            journal.logs_under(CONTROL_SCOPE).is_empty(),
            "a deny-only target receives no control-plane record",
        );
        b.record_note(format!(
            "{} refusal(s) and no permit at {}",
            records.len(),
            declared.display(),
        ));
    }
}
