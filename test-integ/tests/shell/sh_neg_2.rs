use strands_det_harness::det_case;

// A program that exists nowhere is a not-found, not a policy denial: the Shell reports
// `command not found` and the operation's own status is 127, and no `effect denied` marker
// appears. This is the control that separates "the Shell could not resolve it" from "policy
// refused it" — the deny cases (SH-3, spawn-gate) rely on that distinction being real.
// Measured green on macOS 2026-09-22 (cargo test --test shell): `command not found` and
// `RC=127` returned, with no `effect denied` marker.
det_case! {
    name: sh_neg_2,
    id:   "SH-NEG-2",
    desc: "Negative: an unknown command is a not-found (127), never a policy denial",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated("nosuchcmd_sh_neg_2 2>&1; echo RC=$?");
        r.assert_entered();
        r.assert_contains("command not found");
        r.assert_contains("RC=127\n");
        r.assert_absent("effect denied");
        // Airtight "not a policy denial": the journal holds no deny decision (only the
        // DET_MEDIATED shell:exec permit). A not-found never reaches a deny; a regression that
        // turned it into a refusal — whatever its wording — records a deny and turns this RED.
        assert!(
            !r.decisions.iter().any(|d| !d.permitted()),
            "a not-found must journal no deny decision; decisions: {:?}",
            r.decisions
        );
    }
}
