use strands_det_harness::{Platform, det_case, sh_quote};

// Two tools, two grants, no sharing. `[tool.a]` holds `write = [a-work]` and `[tool.b]` holds
// `read_file = [b-dir/b-only.txt]`. Tool a cannot read b's file or create a file in b's directory,
// and tool b cannot create a file in a's directory. Each reaches its own grant in the same run: a
// writes a witness the host finds, and b returns its file's bytes. Each tool is its own copy of the
// fs probe, so the `[tool.<name>] command` that matches names one table.
const PROBE: &str = include_str!("../probes/fs_probe.rs");
include!("../probes/probe_lines.rs");

/// On Linux a path outside a leaf's binds is not in its view; on macOS Seatbelt refuses it.
fn denials() -> &'static [i32] {
    match Platform::current() {
        Platform::Linux => &[ENOENT],
        Platform::Macos => &[EPERM],
    }
}

det_case! {
    name: cn_t_07,
    id:   "CN-T-07",
    desc: "Two tools hold disjoint grants: tool a (write=[a-work]) cannot read tool b's read_file or write b's directory, tool b cannot write a-work, and each reaches its own grant (host witness, file bytes)",
    run: |b| {
        let probe_a = b.compile_probe("fsprobe-t07a", PROBE);
        let probe_b = b.compile_probe("fsprobe-t07b", PROBE);
        let root = b.workspace().parent().unwrap().to_path_buf();
        let a_work = root.join("a-work");
        let b_dir = root.join("b-dir");
        let b_only = b_dir.join("b-only.txt");
        std::fs::create_dir(&a_work).expect("DET_ERROR: a-work");
        std::fs::create_dir(&b_dir).expect("DET_ERROR: b-dir");
        std::fs::write(&b_only, "DET_B_ONLY_T07\n").expect("DET_ERROR: b-only");
        let witness = a_work.join("witness");
        let a_intrusion = b_dir.join("from-a");
        let b_intrusion = a_work.join("from-b");
        let quoted = |p: &std::path::Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
        let edit = |text: String| format!(
            "{text}\n[tool.a]\ncommand = [{}]\n\n[tool.a.filesystem]\nwrite = [{}]\n\n\
             [tool.b]\ncommand = [{}]\n\n[tool.b.filesystem]\nread_file = [{}]\n",
            quoted(&probe_a), quoted(&a_work), quoted(&probe_b), quoted(&b_only)
        );
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        let (pa, pb) = (sh_quote(&probe_a.to_string_lossy()), sh_quote(&probe_b.to_string_lossy()));
        let s = |p: &std::path::Path| sh_quote(&p.to_string_lossy());
        let r = b.run_mediated_with_config(edit, &format!(
            "{pa} create {w} DET_A_WITNESS_T07; {pa} read {bo}; {pa} create {ai} DET_FROM_A_T07; \
             {pb} read {bo}; {pb} create {bi} DET_FROM_B_T07",
            w = s(&witness), bo = s(&b_only), ai = s(&a_intrusion), bi = s(&b_intrusion),
        ));
        r.assert_mediated_permitted("shell:spawn", "fsprobe-t07a");
        r.assert_mediated_permitted("shell:spawn", "fsprobe-t07b");

        // Each tool reaches its own grant.
        assert!(
            probe_line(&r.out, "CREATE_OK", &subject(&witness)).is_some(),
            "tool a did not write its own grant; out=[{}]", r.snippet()
        );
        assert_eq!(
            std::fs::read_to_string(&witness).ok().as_deref(), Some("DET_A_WITNESS_T07\n"),
            "the host did not find tool a's witness"
        );
        let reads: Vec<&str> = r.out.lines()
            .filter(|l| l.starts_with(&format!("READ_OK {}", subject(&b_only))))
            .collect();
        assert_eq!(reads.len(), 1, "exactly one tool must read b-only; out=[{}]", r.snippet());
        assert!(reads[0].contains("DET_B_ONLY_T07"), "tool b did not read its own file: {}", reads[0]);

        // Neither reaches the other's grant. The order of the script fixes which tool made which
        // attempt: a's read of b-only comes first, and the one success above is b's.
        let first = r.out.lines()
            .find(|l| l.starts_with("READ_") && l.contains(&subject(&b_only)))
            .unwrap_or_default();
        assert!(first.starts_with("READ_REFUSED"), "tool a read tool b's file: {first}; out=[{}]", r.snippet());
        refused_as(&r.out, "READ", &subject(&b_only), denials())
            .unwrap_or_else(|why| panic!("tool a read b-only: {why}; out=[{}]", r.snippet()));
        refused_as(&r.out, "CREATE", &subject(&a_intrusion), denials())
            .unwrap_or_else(|why| panic!("tool a wrote tool b's directory: {why}; out=[{}]", r.snippet()));
        refused_as(&r.out, "CREATE", &subject(&b_intrusion), denials())
            .unwrap_or_else(|why| panic!("tool b wrote a-work: {why}; out=[{}]", r.snippet()));
        assert!(!a_intrusion.exists(), "tool a's file landed in b's directory on the host");
        assert!(!b_intrusion.exists(), "tool b's file landed in a-work on the host");
        assert_eq!(std::fs::read_to_string(&b_only).unwrap(), "DET_B_ONLY_T07\n");
    }
}
