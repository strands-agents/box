use strands_det_harness::{det_case, sh_quote};

// A sourced file stops at the first statement the Shell cannot parse. Each line before it runs
// and its definitions load. No line after it runs, so a read on a later line reaches no policy
// decision. The error names the file and the line where the statement starts, and `.` returns 1.
// The file ends with an unclosed quote: a loop that consumes to end of file reports that quote.
det_case! {
    name: sh_source_stop,
    id:   "SH-SOURCE-STOP",
    desc: "source stops at a statement that cannot parse: earlier lines run, later lines never reach policy, the error names the file and line 3, and the status is 1",
    run: |b| {
        b.reset_policy();
        let never_read = b.workspace().join("never-read.txt");
        std::fs::write(&never_read, "NEVER_READ_MARKER\n")
            .expect("DET_ERROR: write the file no line may read");
        let script = b.workspace().join("stop.sh");
        std::fs::write(
            &script,
            format!(
                "echo BEFORE_RAN\n\
                 before() {{ echo BEFORE_FN; }}\n\
                 bad() {{ echo *(N); }}\n\
                 after() {{ echo AFTER_FN; }}\n\
                 cat {}\n\
                 echo \"never closed\n",
                sh_quote(&never_read.to_string_lossy())
            ),
        )
        .expect("DET_ERROR: write the sourced file");
        let r = b.run_mediated(&format!(
            ". {}; echo RC=$?; before; after; echo DONE",
            sh_quote(&script.to_string_lossy())
        ));
        r.assert_entered();
        r.assert_contains("BEFORE_RAN\n");
        r.assert_contains("stop.sh: line 3: Opened parentheses without closing");
        r.assert_contains("RC=1\n");
        r.assert_contains("BEFORE_FN\n");
        r.assert_contains("after: command not found");
        r.assert_contains("DONE\n");
        r.assert_absent("AFTER_FN");
        r.assert_absent("NEVER_READ_MARKER");
        r.assert_absent("unterminated double quote");
        assert!(
            !r.decisions.iter().any(|d| d.resource.ends_with("never-read.txt")),
            "a line after the invalid statement reached policy; decisions: {:?}",
            r.decisions
        );
    }
}
