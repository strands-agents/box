use strands_det_harness::det_case;

// One Shell is built per request
// (docs/design/decisions.md#no-state-crosses-a-call-boundary), so Shell state does not persist
// across requests:
// a variable exported in one mediated request is gone in the next. Two `run_mediated` calls share
// one box but get two fresh Shells, so the second must not see the first's `CARRY`.
// Measured green on macOS 2026-09-22 (cargo test --test shell): request 1 printed
// `SET=SESSION1`; request 2 printed `GOT=[]`.
det_case! {
    name: sh_sec_9,
    id:   "SH-SEC-9",
    desc: "Security: Shell state does not persist across requests (a var set in one is gone in the next)",
    run: |b| {
        b.reset_policy();
        let r1 = b.run_mediated("export CARRY=SESSION1; echo SET=$CARRY");
        r1.assert_entered();
        r1.assert_contains("SET=SESSION1");
        let r2 = b.run_mediated("echo GOT=[$CARRY]");
        r2.assert_entered();
        r2.assert_contains("GOT=[]");
        r2.assert_absent("GOT=[SESSION1]");
    }
}
