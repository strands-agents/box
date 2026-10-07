use strands_det_harness::det_case;

// Containment CN-W (Linux workload, act 3)
//
// Linux has no lowering for `list` or for a `deny` of a path that does not exist yet, so the
// configuration is refused at load, by the entry's value, with the platform named.
det_case! {
    name: cn_w_03,
    id:   "CN-W-03",
    platforms: [Linux],
    desc: "Workload act 3: list and a future-file deny are refused at load on Linux, naming the entry",
    run: |b| {
        b.reset_policy();
        let quoted = |path: &std::path::Path| serde_json::to_string(&path.to_string_lossy()).unwrap();
        let listed = quoted(&b.listed_tree());
        let r = b.run_sh_with_config(
            move |text| text.replacen("read_file = [", &format!("list = [{listed}]\nread_file = ["), 1),
            "printf RAN",
        );
        // A load refusal is the expected outcome here: the box must have refused (not failed
        // some other way), named the entry, and never started the workload.
        r.assert_refused_at_load(
            &["cannot be listed without its contents on Linux", "has no lowering for `list`"],
            "RAN",
        );
        let later = quoted(&b.workspace().join("later.env"));
        let r = b.run_sh_with_config(
            move |text| text.replacen("read_file = [", &format!("deny = [{later}]\nread_file = ["), 1),
            "printf RAN",
        );
        r.assert_refused_at_load(&["does not exist yet", "cannot refuse a path that is not there"], "RAN");
    }
}
