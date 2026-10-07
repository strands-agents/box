use strands_det_harness::det_case;

// The spawn gate lives in the hosted Shell, so the command runs there (mediated route). `git` is
// not a Shell command, so the Shell asks the broker for a `shell:spawn`; with no permit the gate
// refuses it and the Shell prints `effect denied` and answers status 126 (EFFECT_DENIED_STATUS).
// The journal row is the proof of admission; git's own status is echoed and judged explicitly,
// so the echo that follows it cannot mask the result (the native Linux run showed the whole
// script exiting 0 with `GIT_RC=126` printed). git's own output (`fatal: not a git repository`
// in an empty workspace, or `On branch`) is what would prove it ran — its absence is the proof
// it did not. From the NATIVE bash the same `git` would be a plain exec the kernel view decides,
// with no gate involved (see CN-R-01).
det_case! {
    name: po_9,
    id:   "PO-9",
    desc: "Shell gate: with no shell:spawn permit, 'git status' in the hosted Shell is refused at the broker (status 126) and git never runs",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated("git status; echo GIT_RC=$?");
        r.assert_spawn_denied("git");
        r.assert_contains("GIT_RC=126");
        r.assert_absent("GIT_RC=0");
        r.assert_absent("fatal:");
        r.assert_absent("On branch");
    }
}
