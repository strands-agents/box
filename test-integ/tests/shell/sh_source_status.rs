use strands_det_harness::{det_case, sh_quote};

// A parse error ends `lash <file>` with status 1, names the file and line, and runs nothing after
// it. In the box `sh` is the host `/bin/sh`, which default-deny refuses, so the Shell's own script
// runner is `lash`. A statement that is still open at end of a sourced file is reported at the line
// where it starts, with status 1.
det_case! {
    name: sh_source_status,
    id:   "SH-SOURCE-STATUS",
    desc: "lash <file> stops at a statement that cannot parse, names its file and line, and returns 1; an unclosed quote at end of a sourced file is reported at its start line with status 1",
    run: |b| {
        b.reset_policy();
        let bad = b.workspace().join("bad.sh");
        std::fs::write(&bad, "echo ONE\necho )\necho THREE\n")
            .expect("DET_ERROR: write the script");
        let open = b.workspace().join("open.sh");
        std::fs::write(&open, "echo FIRST\necho \"open\necho SECOND\n")
            .expect("DET_ERROR: write the sourced file");
        let r = b.run_mediated(&format!(
            "lash {}; echo LASH_RC=$?; . {}; echo DOT_RC=$?",
            sh_quote(&bad.to_string_lossy()),
            sh_quote(&open.to_string_lossy())
        ));
        r.assert_entered();
        r.assert_contains("ONE\n");
        r.assert_contains("bad.sh: line 2: unexpected ')'");
        r.assert_contains("LASH_RC=1\n");
        r.assert_absent("THREE");
        r.assert_contains("FIRST\n");
        r.assert_contains("open.sh: line 2: unterminated double quote");
        r.assert_contains("DOT_RC=1\n");
        r.assert_absent("SECOND");
    }
}
