use strands_det_harness::det_case;

// Control flow and variables behave per bash through the vendored parser: a `for` loop,
// `export`, `test`, and an `if [ -f ]` branch are all `shell:exec` the baseline permits,
// with no filesystem effect (the `if` tests a file that does not exist and takes the else).
// Measured green on macOS 2026-09-22 (cargo test --test shell): `123`, `X=42`, `TESTOK`, and
// `NOFILE` all returned.
det_case! {
    name: sh_hp_7,
    id:   "SH-HP-7",
    desc: "Happy path: control flow and variables (for/export/test/if) behave as in bash",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated(
            "for i in 1 2 3; do printf '%s' \"$i\"; done; echo; \
             export X=42; echo X=$X; \
             test 1 -eq 1 && echo TESTOK; \
             if [ -f nope-does-not-exist.txt ]; then echo HASFILE; else echo NOFILE; fi",
        );
        r.assert_entered();
        r.assert_contains("123");
        r.assert_contains("X=42");
        r.assert_contains("TESTOK");
        r.assert_contains("NOFILE");
    }
}
