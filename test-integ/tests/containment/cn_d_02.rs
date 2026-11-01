use strands_det_harness::det_case;

// Containment CN-D (a file deny holds for a path created later)
//
// macOS only, as CN-D-01. The companion measurement: the deny refuses the CREATE inside a writable
// tree, so the workload cannot bring the denied path into being, and the host sees no file.
det_case! {
    name: cn_d_02,
    id:   "CN-D-02",
    platforms: [Macos],
    desc: "Deny: a denied path that does not exist yet cannot be created from inside its writable tree",
    run: |b| {
        b.reset_policy();
        let later = b.workspace().join("later.env");
        let beside = b.workspace().join("beside.env");
        let _ = std::fs::remove_file(&later);
        let _ = std::fs::remove_file(&beside);
        let r = b.run_sh(&format!(
            "printf 'SECRET_VALUE\\n' > '{denied}' 2>/dev/null && printf 'WROTE_DENIED\\n'; \
             printf 'OK\\n' > '{beside}' && printf 'WROTE_BESIDE\\n'; printf done",
            denied = later.display(),
            beside = beside.display()
        ));
        let denied_exists = later.exists();
        let beside_exists = beside.exists();
        let _ = std::fs::remove_file(&later);
        let _ = std::fs::remove_file(&beside);
        // The control: a sibling in the same writable tree is created, so the tree is writable and
        // the denied path alone is refused.
        r.assert_contains("WROTE_BESIDE");
        assert!(beside_exists, "the control file was created in the writable tree");
        r.assert_absent("WROTE_DENIED");
        assert!(!denied_exists, "the denied path was not created on the host");
        r.assert_contains("done");
    }
}
