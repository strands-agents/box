use strands_det_harness::det_case;

// The fixture carries the starter policy's one prohibition, `@id("no_deletes") forbid fs:delete`.
// The Shell's `rm` is `RemoveFile`/`RemoveDir` → `fs:delete`, so `rm -f` on a file and `rm -rf` on
// a directory with an entry are each refused by that forbid: the journal holds the forbid's deny
// on the file, the entry, and the directory, `rm` prints the policy message naming the forbid and
// exits 1 (`-f` quiets only a missing operand), and the file, the directory, and its entry remain.
det_case! {
    name: sh_neg_rm,
    id:   "SH-NEG-RM",
    desc: "Delete refusal: rm -f and rm -rf under the fixture's forbid fs:delete exit 1 with the policy message naming the forbid, and the file and the directory remain",
    run: |b| {
        b.reset_policy();
        let file = b.workspace().join("sh-neg-rm-file.txt");
        let dir = b.workspace().join("sh-neg-rm-dir");
        let entry = dir.join("inner.txt");
        std::fs::write(&file, "KEEP\n").expect("DET_ERROR: plant the file");
        std::fs::create_dir(&dir).expect("DET_ERROR: plant the directory");
        std::fs::write(&entry, "KEEP\n").expect("DET_ERROR: plant the entry");
        let r = b.run_mediated(
            "rm -f sh-neg-rm-file.txt; echo RMF_RC=$?; rm -rf sh-neg-rm-dir; echo RMRF_RC=$?",
        );
        r.assert_entered();
        r.assert_forbidden_by("fs:delete", "sh-neg-rm-file.txt", "no_deletes");
        r.assert_forbidden_by("fs:delete", "sh-neg-rm-dir/inner.txt", "no_deletes");
        assert!(
            r.decisions.iter().any(|d| d.is_action("fs:delete")
                && d.resource.ends_with("/sh-neg-rm-dir")
                && d.forbidden_by("no_deletes")),
            "rm -rf must ask to remove the directory itself and be refused by the forbid; decisions: {:?}",
            r.decisions
        );
        r.assert_contains("rm: sh-neg-rm-file.txt: policy denied this operation on '");
        r.assert_contains("rm: sh-neg-rm-dir/inner.txt: policy denied this operation on '");
        r.assert_contains("[policy: no_deletes]");
        r.assert_contains("RMF_RC=1\n");
        r.assert_contains("RMRF_RC=1\n");
        assert!(file.is_file(), "rm -f removed the file although the forbid refused it");
        assert!(entry.is_file(), "rm -rf removed the entry although the forbid refused it");
        assert!(dir.is_dir(), "rm -rf removed the directory although the forbid refused it");
    }
}
