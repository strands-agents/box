use strands_det_harness::det_case;

// One scenario: the Shell's own `curl` validates its command line before any egress decision, so a
// usage error is a usage error — not a policy denial and not a crash. No URL is `no URL` (exit 2);
// an unknown flag is `invalid option` (exit 1). Neither raises `effect denied`.
// Measured green on macOS 2026-09-22 (cargo test --test shell): `no URL`/`RC=2` and
// `invalid option`/`RC=1`, no `effect denied`.
det_case! {
    name: sh_neg_curl,
    id:   "SH-NEG-CURL",
    desc: "Negative: curl usage errors (no URL, unknown flag) are usage errors, not policy denials",
    run: |b| {
        b.reset_policy();
        let no_url = b.run_mediated("curl 2>&1; echo RC=$?");
        no_url.assert_entered();
        no_url.assert_contains("no URL");
        no_url.assert_contains("RC=2\n");
        no_url.assert_absent("effect denied");
        assert!(
            !no_url.decisions.iter().any(|d| !d.permitted()),
            "a curl usage error must journal no deny decision; decisions: {:?}",
            no_url.decisions
        );
        let bad_flag = b.run_mediated("curl --nope-not-a-flag https://x 2>&1; echo RC=$?");
        bad_flag.assert_entered();
        bad_flag.assert_contains("invalid option");
        bad_flag.assert_contains("RC=1\n");
        bad_flag.assert_absent("effect denied");
        assert!(
            !bad_flag.decisions.iter().any(|d| !d.permitted()),
            "a curl usage error must journal no deny decision; decisions: {:?}",
            bad_flag.decisions
        );
    }
}
