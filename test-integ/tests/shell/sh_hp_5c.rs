use strands_det_harness::det_case;

// The bound on SH-HP-5B: `mv` is an `fs:move`, and the baseline names no `fs:move` permit, so an
// ungranted move is refused by default-deny — the broker journals the deny, the Shell prints
// `effect denied`, mv fails nonzero, and the destination is never created. This is the deny half
// that makes SH-HP-5B's allow meaningful (a happy path alone cannot prove the box refuses the
// ungranted case).
// Measured green on macOS 2026-09-22 (cargo test --test shell): journaled fs:move default-deny,
// `MVRC` nonzero, `LS=0` (no destination).
det_case! {
    name: sh_hp_5c,
    id:   "SH-HP-5C",
    desc: "Effect refusal: mv with no fs:move grant is default-denied and creates no destination",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated(
            "touch src.txt; mv src.txt dst.txt 2>&1; echo MVRC=$?; echo LS=$(ls | grep -c dst.txt)",
        );
        r.assert_entered();
        let rule = r.assert_mediated_denied("fs:move", "dst.txt");
        assert!(
            rule.contains("default-deny"),
            "the move must be refused by default-deny, not a rule of the case's own: {rule}"
        );
        r.assert_contains("LS=0");
        r.assert_absent("MVRC=0");
    }
}
