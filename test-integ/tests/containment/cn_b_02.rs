use strands_det_harness::det_case;

// See docs/design/decisions.md#one-trusted-process-per-box. The box root holds four
// children, and Box creates nothing beside it.
//
// **This pins the layout contract; it is not a regression pin for the withdrawn default.** It passes
// against a box that still defaults `box_dir`, because this fixture always names one explicitly and
// such a box created the same four children. `CN-B-01` is the case that discriminates.
//
// What it does bound is worth bounding: a fifth child, or anything appearing beside the box
// directory, is a box that has grown state the reachability classes do not describe.
//
// Asserted against the fixture's own tree rather than against `~/.strands-box`, because a developer
// machine carries that directory for its own reasons and its mere presence would make this case pass
// or fail for the wrong reason.
det_case! {
    name: cn_b_02,
    id:   "CN-B-02",
    desc: "The box creates the four children of box_dir and nothing beside it",
    run: |b| {
        b.reset_policy();
        let r = b.run_sh("printf RAN");
        // The positive control: without it every assertion below would hold for a box that never ran.
        r.assert_contains("RAN");

        let entries = |directory: &std::path::Path| {
            let mut names: Vec<String> = std::fs::read_dir(directory)
                .unwrap_or_else(|error| panic!("DET_ERROR: cannot read {}: {error}", directory.display()))
                .map(|entry| entry.expect("a directory entry").file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };

        let box_dir = b.box_dir();
        assert_eq!(
            entries(box_dir),
            ["bin", "private", "run", "trust"],
            "box_dir must hold one child per reachability class and nothing else: {}",
            box_dir.display()
        );

        // And nothing beside it: the parent holds only the directory the configuration named.
        let parent = box_dir.parent().expect("box_dir has a parent");
        let own = box_dir
            .file_name()
            .expect("box_dir has a final component")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            entries(parent),
            [own.as_str()],
            "Box created something beside box_dir in {}",
            parent.display()
        );
    }
}
