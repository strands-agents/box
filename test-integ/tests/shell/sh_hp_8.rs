use strands_det_harness::det_case;

// `find … -exec` runs a nested command per match, and each nested `cat` is its own admitted
// event: the two seeded files are created under an `fs:write` the baseline permits, and each
// `cat` reads under `fs:read`. Both file bodies coming back proves the traversal ran and each
// nested command was judged and performed.
// Measured green on macOS 2026-09-22 (cargo test --test shell): `A1` and `A2` both returned.
det_case! {
    name: sh_hp_8,
    id:   "SH-HP-8",
    desc: "Happy path: find -exec runs a nested command per match, each judged and performed",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated(
            "printf A1 > a.log; printf A2 > b.log; find . -maxdepth 1 -name '*.log' -exec cat {} ';'",
        );
        r.assert_entered();
        // Pin mediation: each nested `cat` must read through the broker, so a regression that
        // ran the built-ins natively (unmediated) turns this RED rather than staying GREEN on
        // the same A1/A2 output.
        r.assert_mediated_permitted("fs:read", "a.log");
        r.assert_mediated_permitted("fs:read", "b.log");
        r.assert_contains("A1");
        r.assert_contains("A2");
        r.assert_allow();
    }
}
