use strands_det_harness::det_case;

// See docs/design/decisions.md#box-is-a-process-and-reads-one-complete-configuration and
// docs/design/decisions.md#one-trusted-process-per-box. `box_dir` is a required key, and Box sites
// no box itself.
//
// The default `~/.strands-box/b/<name>` is withdrawn, so a configuration that names no `box_dir`
// has nowhere to put its state. The box must say which key is missing and start nothing: a
// configuration this incomplete must not reach a workload.
det_case! {
    name: cn_b_01,
    id:   "CN-B-01",
    desc: "A configuration naming no box_dir is refused at load, by the key's own name",
    run: |b| {
        b.reset_policy();
        // Strip the one `box_dir` line the fixture authors, and change nothing else.
        let r = b.run_sh_with_config(
            |text| {
                text.lines()
                    .filter(|line| !line.starts_with("box_dir = "))
                    .collect::<Vec<_>>()
                    .join("\n")
            },
            "printf RAN",
        );
        r.assert_refused_at_load(&["missing field `box_dir`"], "RAN");
    }
}
