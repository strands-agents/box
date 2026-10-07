use strands_det_harness::det_case;

// Containment CN-W (Linux workload, act 7)
//
// The box's own `.strands-box/policy.dw` inside the granted project is unreadable through the
// agent's own syscall while a sibling file reads.
det_case! {
    name: cn_w_07,
    id:   "CN-W-07",
    desc: "Workload act 7: the project's own policy.dw is unreadable inside the granted project; a sibling reads",
    run: |b| {
        b.reset_policy();
        let policy = b.workspace().join(".strands-box/policy.dw");
        let sibling = b.workspace().join("readable.txt");
        let r = b.run_sh(&format!(
            "read -r v < '{}' 2>/dev/null && printf 'POLICY=%s\\n' \"$v\"; read -r v < '{}' && printf 'SIBLING=%s\\n' \"$v\"; printf done",
            policy.display(),
            sibling.display()
        ));
        r.assert_absent("POLICY=");
        r.assert_absent("permit (");
        r.assert_contains("SIBLING=LISTED_CONTENT");
        r.assert_contains("done");
    }
}
