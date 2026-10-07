use strands_det_harness::det_case;

// The write is a hosted-Shell redirection (mediated route), judged under a broad `fs:write`
// permit and refused by the self-defense floor, which the journal names. The host-side effect
// is the proof: the policy file's bytes are unchanged after the run.
det_case! {
    name: po_4b,
    id:   "PO-4b",
    desc: "Self-defense: the Shell writing .strands-box/policy.dw under a broad fs:write permit is refused by the reach floor and the file is unchanged",
    run: |b| {
        b.apply_policy(r#"@id("broad_write") permit (principal, action == Box::Action::"fs:write", resource);"#);
        let before = std::fs::read_to_string(b.policy_path()).expect("DET_ERROR: read policy.dw before the run");
        let r = b.run_mediated(&format!(
            "echo tampered >> {} && echo WROTE; echo done",
            b.policy_path().display()
        ));
        let after = std::fs::read_to_string(b.policy_path()).expect("DET_ERROR: read policy.dw after the run");
        let rule = r.assert_mediated_denied("fs:write", "policy.dw");
        assert!(
            rule.contains("reach-floor"),
            "the broad permit must be overridden by the reach floor, not refused by policy: {rule}"
        );
        r.assert_absent("WROTE");
        r.assert_contains("done");
        assert_eq!(before, after, "policy.dw changed on the host");
        assert!(!after.contains("tampered"), "the tampering reached policy.dw");
    }
}
