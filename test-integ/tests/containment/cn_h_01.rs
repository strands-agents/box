use strands_det_harness::{det_case, user_home};

// Containment CN-H (reach under the operator home is only what is listed)
//
// The agent's HOME is the operator's. A file the fixture lists (the workspace) reads through the
// agent's own syscall, and an unlisted file beside it in the operator home does not. Bash's own
// redirect is used rather than `cat`, so the probe measures the boundary and not the exec of a
// coreutil.
det_case! {
    name: cn_h_01,
    id:   "CN-H-01",
    desc: "Operator home: a listed file reads through the agent's own syscall and an unlisted sibling under HOME does not",
    run: |b| {
        b.reset_policy();
        let listed = b.workspace().join("readable.txt");
        let unlisted = user_home().join(format!(".det-unlisted-{}", std::process::id()));
        std::fs::write(&unlisted, "UNLISTED_CONTENT\n").expect("DET_ERROR: plant the unlisted file");
        let r = b.run_sh(&format!(
            "read -r v < '{}' && printf 'LISTED=%s\\n' \"$v\"; read -r v < '{}' 2>/dev/null && printf 'UNLISTED=%s\\n' \"$v\"; printf done",
            listed.display(),
            unlisted.display()
        ));
        let _ = std::fs::remove_file(&unlisted);
        r.assert_contains("LISTED=LISTED_CONTENT");
        r.assert_absent("UNLISTED=");
        r.assert_absent("UNLISTED_CONTENT");
        r.assert_contains("done");
    }
}
