use strands_det_harness::{AUTHORITY_REFUSAL, PROTECTED_CONFIG_MARKER, det_case};

// Self-defense is a floor of the broker's reach, so the read is made where the broker sees it:
// the hosted Shell's `cat` (mediated route). The broad `fs:read` permit is what the policy engine
// judges, so the refusal that follows can only be the reach floor, which the journal names and
// the Shell states as "resolves to an authority source that this run loaded, which no policy may
// open or change" (measured on the native Linux run). The proof the content never reached the
// workload is a marker line the fixture writes into box.toml and nowhere else — the box's own
// startup disclosure repeats the section names, so "[agent]" is not evidence of a leak.
// (The native bash's own read of the same file is CN-W-07's subject: the kernel view.)
det_case! {
    name: po_4a,
    id:   "PO-4a",
    desc: "Self-defense: the Shell reading .strands-box/box.toml under a broad fs:read permit is refused by the reach floor as an authority source",
    run: |b| {
        b.apply_policy(r#"@id("broad_read") permit (principal, action == Box::Action::"fs:read", resource);"#);
        let target = b.workspace().join(".strands-box/box.toml");
        let on_host = std::fs::read_to_string(&target).expect("DET_ERROR: read box.toml on the host");
        assert!(
            on_host.contains(PROTECTED_CONFIG_MARKER),
            "DET_ERROR: the fixture's box.toml does not carry the protected-content marker"
        );
        let r = b.run_mediated(&format!("cat {}; echo done", target.display()));
        let rule = r.assert_mediated_denied("fs:read", "box.toml");
        assert!(
            rule.contains("reach-floor"),
            "the broad permit must be overridden by the reach floor, not refused by policy: {rule}"
        );
        r.assert_contains(AUTHORITY_REFUSAL);
        r.assert_absent(PROTECTED_CONFIG_MARKER);
        r.assert_contains("done");
    }
}
