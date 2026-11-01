use strands_det_harness::{det_case, sh_quote};

// A sourced file still joins the lines of a statement that is not complete yet: a multi-line
// function, `if`, `for`, `$(`, `case`, a heredoc, a `|` at end of line, and `&&` and `||` at end of
// line. `false &&` at end of a line skips the command on the next line, as `false && cmd` does.
det_case! {
    name: sh_source_join,
    id:   "SH-SOURCE-JOIN",
    desc: "source joins the lines of an incomplete statement (function, if, for, $(, case, heredoc, trailing |, && and ||) and runs the file to the end with status 0",
    run: |b| {
        b.reset_policy();
        let script = b.workspace().join("join.sh");
        std::fs::write(
            &script,
            "f() {\n\
             \x20 if true; then\n\
             \x20   echo IN_F\n\
             \x20 fi\n\
             }\n\
             for i in 1 2\n\
             do echo FOR_$i; done\n\
             x=$(\n\
             echo SUB)\n\
             echo \"$x\"\n\
             echo PIPE |\n\
             \x20 tr E O\n\
             cat <<EOF\n\
             HEREDOC\n\
             EOF\n\
             case q in\n\
             \x20 q) echo CASE;;\n\
             esac\n\
             false &&\n\
             echo AND_SKIPPED\n\
             true ||\n\
             echo OR_SKIPPED\n\
             true &&\n\
             \x20 echo AND_RAN\n\
             f\n",
        )
        .expect("DET_ERROR: write the sourced file");
        let r = b.run_mediated(&format!(
            ". {}; echo RC=$?",
            sh_quote(&script.to_string_lossy())
        ));
        r.assert_entered();
        r.assert_contains("FOR_1\nFOR_2\nSUB\nPIPO\nHEREDOC\nCASE\nAND_RAN\nIN_F\nRC=0\n");
        r.assert_absent("AND_SKIPPED");
        r.assert_absent("OR_SKIPPED");
        r.assert_absent("strands-shell:");
    }
}
