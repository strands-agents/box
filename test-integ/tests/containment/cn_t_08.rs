use strands_det_harness::{Platform, det_case, sh_quote};

// A tool's `deny`, `list`, and `write_file` lists, each beside the grant it narrows. `deny` takes one
// file out of a `read` tree; `list` enumerates a tree and grants none of its content; `write_file`
// writes one file and no neighbour in its directory. Each refusal has its granted counterpart in the
// same run, and the host proves the writes. On Linux a `list` entry has no lowering, so a tool that
// declares one is refused at load; the `deny` and `write_file` half runs there without it.
const PROBE: &str = include_str!("../probes/fs_probe.rs");
include!("../probes/probe_lines.rs");

det_case! {
    name: cn_t_08,
    id:   "CN-T-08",
    desc: "Tool deny, list, write_file: a denied file in a read tree yields no bytes while its sibling reads; a list tree enumerates and its content is refused (macOS; refused at load on Linux); write_file writes its file and no neighbour",
    run: |b| {
        let probe = b.compile_probe("fsprobe-t08", PROBE);
        let root = b.workspace().parent().unwrap().join("t08");
        let tree = root.join("read-tree");
        let listed = root.join("listed");
        let file_dir = root.join("file-dir");
        for dir in [&tree, &listed, &file_dir] {
            std::fs::create_dir_all(dir).expect("DET_ERROR: t08 directory");
        }
        let open = tree.join("open.txt");
        let denied = tree.join("denied.txt");
        let entry = listed.join("entry.txt");
        let target = file_dir.join("target.txt");
        let neighbour = file_dir.join("neighbour.txt");
        std::fs::write(&open, "DET_OPEN_T08\n").unwrap();
        std::fs::write(&denied, "DET_DENIED_T08\n").unwrap();
        std::fs::write(&entry, "DET_LISTED_T08\n").unwrap();
        std::fs::write(&target, "").unwrap();
        let quoted = |p: &std::path::Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
        let with_list = Platform::current() == Platform::Macos;
        let edit = |list: bool| {
            let lists = format!(
                "read = [{}]\ndeny = [{}]\nwrite_file = [{}]\n{}",
                quoted(&tree), quoted(&denied), quoted(&target),
                if list { format!("list = [{}]\n", quoted(&listed)) } else { String::new() },
            );
            let probe = quoted(&probe);
            move |text: String| format!("{text}\n[tool.t08]\ncommand = [{probe}]\n\n[tool.t08.filesystem]\n{lists}")
        };
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);

        if !with_list {
            let refused = b.run_mediated_with_config(edit(true), "echo RAN_T08");
            refused.assert_refused_at_load(&["has no lowering for `list`"], "RAN_T08");
        }

        let p = sh_quote(&probe.to_string_lossy());
        let s = |path: &std::path::Path| sh_quote(&path.to_string_lossy());
        let mut script = format!(
            "{p} read {o}; {p} read {d}; {p} append {t} DET_WRITTEN_T08; {p} create {n} DET_NEIGHBOUR_T08",
            o = s(&open), d = s(&denied), t = s(&target), n = s(&neighbour),
        );
        if with_list {
            script.push_str(&format!("; {p} list {l}; {p} read {e}", l = s(&listed), e = s(&entry)));
        }
        let r = b.run_mediated_with_config(edit(with_list), &script);
        r.assert_mediated_permitted("shell:spawn", "fsprobe-t08");

        // deny: the sibling reads, the denied file yields no bytes.
        assert!(
            probe_line(&r.out, "READ_OK", &subject(&open)).is_some_and(|l| l.contains("DET_OPEN_T08")),
            "the tool did not read its read tree; out=[{}]", r.snippet()
        );
        match Platform::current() {
            Platform::Macos => {
                refused_as(&r.out, "READ", &subject(&denied), &[EPERM])
                    .unwrap_or_else(|why| panic!("the denied file read: {why}; out=[{}]", r.snippet()));
            }
            // Linux binds an empty read-only file over a denied file, so it reads empty.
            Platform::Linux => assert!(
                probe_line(&r.out, "READ_", &subject(&denied))
                    .is_some_and(|l| l.starts_with(&format!("READ_OK {} len=0 ::", subject(&denied)))),
                "the denied file did not read empty on Linux; out=[{}]",
                r.snippet()
            ),
        }
        r.assert_absent("DET_DENIED_T08");

        // write_file: the file takes the write, the neighbour is not created.
        assert!(
            probe_line(&r.out, "APPEND_OK", &subject(&target)).is_some(),
            "the tool did not write its write_file; out=[{}]", r.snippet()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "DET_WRITTEN_T08\n", "the host did not see the write_file write");
        let neighbour_denials: &[i32] = match Platform::current() {
            Platform::Macos => &[EPERM],
            Platform::Linux => &[EROFS],
        };
        refused_as(&r.out, "CREATE", &subject(&neighbour), neighbour_denials)
            .unwrap_or_else(|why| panic!("the tool created a neighbour of its write_file: {why}; out=[{}]", r.snippet()));
        assert!(!neighbour.exists(), "the neighbour landed on the host");
        assert_eq!(std::fs::read_to_string(&denied).unwrap(), "DET_DENIED_T08\n");

        // list: the tree enumerates, its content is refused.
        if with_list {
            assert!(
                probe_line(&r.out, "LIST_OK", &subject(&listed)).is_some_and(|l| l.ends_with("names=entry.txt")),
                "the tool did not enumerate its list tree; out=[{}]", r.snippet()
            );
            refused_as(&r.out, "READ", &subject(&entry), &[EPERM])
                .unwrap_or_else(|why| panic!("the list tree's content read: {why}; out=[{}]", r.snippet()));
            r.assert_absent("DET_LISTED_T08");
        }
    }
}
