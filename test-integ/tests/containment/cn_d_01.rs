use strands_det_harness::det_case;

// Containment CN-D (a file deny holds for a path created later)
//
// macOS only: the Linux namespace backend cannot refuse a path that is not there yet, and the box
// refuses such a `deny` entry by name at load, so the fixture writes the entry on macOS alone.
//
// The denied file does not exist when the box starts. The HOST creates it while the workload is
// live, so the file is really there with real content when the workload reads it, and the
// read is what the deny refuses. The wait is bash builtins only, so no coreutil exec is measured.
// An in-box write cannot arrange this: the deny refuses the write
// too (CN-D-02), so the file would never exist and an absent read would prove nothing.
det_case! {
    name: cn_d_01,
    id:   "CN-D-01",
    platforms: [Macos],
    desc: "Deny: a denied path the host creates after startup inside a writable tree stays unreadable",
    run: |b| {
        b.reset_policy();
        let later = b.workspace().join("later.env");
        let _ = std::fs::remove_file(&later);
        let r = b.run_sh_meanwhile(
            &format!(
                ": > '{ready}'; while [ ! -e '{go}' ]; do read -rt 1 <> <(:) || :; done; \
                 read -r v < '{p}' 2>/dev/null && printf 'READ=%s\\n' \"$v\"; printf done",
                ready = b.ready_marker().display(),
                go = b.go_marker().display(),
                p = later.display()
            ),
            || {
                std::fs::write(&later, "SECRET_VALUE\n").expect("DET_ERROR: plant later.env from the host");
            },
        );
        // The file exists with its content on the host, so an absent READ line is the deny at work.
        let planted = std::fs::read_to_string(&later).expect("DET_ERROR: later.env exists on the host");
        assert_eq!(planted, "SECRET_VALUE\n", "the host-planted file holds its content");
        let _ = std::fs::remove_file(&later);
        r.assert_absent("READ=SECRET_VALUE");
        r.assert_absent("SECRET_VALUE");
        r.assert_contains("done");
    }
}
