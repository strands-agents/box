use strands_det_harness::det_case;

// One scenario: the Shell's workspace filesystem effects go through the Kernel, not a raw syscall.
// A write then read, the creation built-ins mkdir/touch/cp, and chmod each
// run as an `fs:*` the baseline permits. Each effect is pinned to the broker by a journaled permit
// on a DISTINCT path — `note.txt` (write+read), `onlydir` (mkdir), `tf.txt` (touch), `cf.txt` (cp)
// — so a regression that ran any of those built-ins natively (unmediated) turns this RED rather
// than staying GREEN on the FS_OK marker. `chmod` runs in the same mediated pipeline on `cf.txt`;
// its refusal counterpart (setuid) is CN-F-02, and delete/move are SH-HP-5C / MO-DEL.
// Measured green on macOS 2026-09-22 (cargo test --test shell): journaled fs:write on note.txt,
// onlydir, tf.txt, cf.txt and fs:read on note.txt; `INSIDE` and `FS_OK` returned.
det_case! {
    name: sh_hp_fs,
    id:   "SH-HP-FS",
    desc: "Happy path: workspace fs built-ins (write/read/mkdir/touch/cp) are each pinned mediated; chmod rides the same pipeline",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated(
            "echo INSIDE > note.txt && cat note.txt && mkdir onlydir && touch tf.txt \
             && cp tf.txt cf.txt && chmod 700 cf.txt && echo FS_OK",
        );
        r.assert_entered();
        r.assert_mediated_permitted("fs:write", "note.txt"); // echo >
        r.assert_mediated_permitted("fs:read", "note.txt");  // cat
        r.assert_mediated_permitted("fs:write", "onlydir");  // mkdir
        r.assert_mediated_permitted("fs:write", "tf.txt");   // touch
        r.assert_mediated_permitted("fs:write", "cf.txt");   // cp (and chmod rides this path)
        r.assert_contains("INSIDE");
        r.assert_contains("FS_OK");
        r.assert_allow();
    }
}
