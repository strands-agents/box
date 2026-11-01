use strands_det_harness::{det_case, sh_quote};

// macOS only: a leaf discovers existence and metadata across the operator home, and content stays
// gated (docs/design/decisions.md#a-leaf-discovers-existence-and-metadata-content-stays-gated).
// The box runs with `HOME` set to the fixture root, so every planted file sits in a fixture home and
// none in the real one. From a tool leaf with no grant over them: `stat` of `~/.det-disc/cfg`
// answers, `stat` of an absent sibling answers ENOENT, and the read of `cfg` is refused; the
// credential store `~/.aws` and the box's `private/` state stay refused even for `stat`. The control is the
// agent, whose existence-denied home refuses the same `stat`.
const PROBE: &str = include_str!("../probes/fs_probe.rs");
include!("../probes/probe_lines.rs");

det_case! {
    name: cn_t_05,
    id:   "CN-T-05",
    platforms: [Macos],
    desc: "Leaf discovery: from a tool leaf, stat of a planted ~/.det-disc/cfg answers and its read is refused, while stat of ~/.aws and of <box_dir>/private is refused; the agent's own stat of cfg is refused",
    run: |b| {
        let probe = b.compile_probe("fsprobe-t05", PROBE);
        let home = b.workspace().parent().unwrap().to_path_buf();
        let home_text = home.to_string_lossy().into_owned();
        let discovered = home.join(".det-disc");
        std::fs::create_dir(&discovered).expect("DET_ERROR: plant ~/.det-disc");
        let cfg = discovered.join("cfg");
        let missing = discovered.join("missing");
        std::fs::write(&cfg, "DET_DISCOVERED_CONTENT_T05\n").expect("DET_ERROR: plant cfg");
        let aws = home.join(".aws");
        std::fs::create_dir(&aws).expect("DET_ERROR: plant the fixture ~/.aws");
        let credentials = aws.join("credentials");
        std::fs::write(&credentials, "[default]\naws_secret_access_key = DET_FIXTURE_AWS_T05\n")
            .expect("DET_ERROR: plant the fixture credentials");
        let box_dir = b.box_dir().to_path_buf();
        assert!(box_dir.starts_with(&home), "DET_ERROR: the box directory is not under the fixture home");
        let private = box_dir.join("private");

        let quoted = |p: &std::path::Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
        let exec_tree = b.with_exec_tree();
        let edit = |text: String| format!(
            "{}\n[tool.t05]\ncommand = [{}]\n",
            exec_tree(text), quoted(&probe)
        );
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        let p = sh_quote(&probe.to_string_lossy());
        let s = |path: &std::path::Path| sh_quote(&path.to_string_lossy());

        // The control: the agent box's home is existence-denied, so its own `stat` of cfg is refused.
        let agent = b.run_sh_with_config_meanwhile_env(
            edit,
            &format!(": > .det-ready; {p} stat {c}; printf 'AGENT_DONE\\n'", c = s(&cfg)),
            &[("HOME", home_text.as_str())],
            || {},
        );
        agent.assert_contains("AGENT_DONE");
        agent.assert_contains(&format!("[agent] HOME={home_text}"));
        refused_as(&agent.out, "STAT", &subject(&cfg), &[EPERM])
            .unwrap_or_else(|why| panic!("the agent stat'd cfg in its home: {why}; out=[{}]", agent.snippet()));

        let r = b.run_mediated_with_config_env(
            edit,
            &format!(
                "{p} stat {c}; {p} stat {m}; {p} read {c}; {p} stat {a}; {p} stat {cr}; {p} read {cr}; {p} stat {bp}; {p} stat {bpp}",
                c = s(&cfg), m = s(&missing), a = s(&aws), cr = s(&credentials),
                bp = s(&private), bpp = s(&private.join("policy.dw")),
            ),
            &[("HOME", home_text.as_str())],
        );
        r.assert_mediated_permitted("shell:spawn", "fsprobe-t05");
        r.assert_contains(&format!("[tool.t05] HOME={home_text}"));

        // Discovery: cfg exists to the leaf and an absent sibling is absent, so the stat is real.
        let size = std::fs::metadata(&cfg).unwrap().len();
        assert!(
            probe_line(&r.out, "STAT_OK", &subject(&cfg)).is_some_and(|l| l.ends_with(&format!("size={size}"))),
            "the tool leaf could not stat cfg in the operator home; out=[{}]", r.snippet()
        );
        refused_as(&r.out, "STAT", &subject(&missing), &[ENOENT])
            .unwrap_or_else(|why| panic!("an absent path did not read absent to the leaf: {why}; out=[{}]", r.snippet()));
        // Content stays gated.
        refused_as(&r.out, "READ", &subject(&cfg), &[EPERM])
            .unwrap_or_else(|why| panic!("the tool leaf read cfg: {why}; out=[{}]", r.snippet()));
        r.assert_absent("DET_DISCOVERED_CONTENT_T05");
        // The credential floor and the box's private state stay refused even for metadata.
        for refused in [&aws, &credentials, &private, &private.join("policy.dw")] {
            refused_as(&r.out, "STAT", &subject(refused), &[EPERM])
                .unwrap_or_else(|why| panic!("the tool leaf stat'd {}: {why}; out=[{}]", refused.display(), r.snippet()));
        }
        refused_as(&r.out, "READ", &subject(&credentials), &[EPERM])
            .unwrap_or_else(|why| panic!("the tool leaf read the fixture credentials: {why}; out=[{}]", r.snippet()));
        r.assert_absent("DET_FIXTURE_AWS_T05");
    }
}
