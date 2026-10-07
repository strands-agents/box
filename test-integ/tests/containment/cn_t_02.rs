use strands_det_harness::{Platform, det_case, sh_quote};

// A tool whose `read` list names the whole workspace still cannot reach the box's own authority:
// the workspace's `.strands-box/policy.dw` and `box.toml`, and the box directory's `private/`
// copies. The tool is the fs probe, run in its own leaf after a `shell:spawn` permit, so each read is
// the leaf's own syscall. The control is a sibling file under the same grant, read in the same run.
const PROBE: &str = include_str!("../probes/fs_probe.rs");
include!("../probes/probe_lines.rs");

/// On Linux the refused tree is not in the leaf's view; on macOS Seatbelt refuses it.
fn denials() -> &'static [i32] {
    match Platform::current() {
        Platform::Linux => &[ENOENT],
        Platform::Macos => &[EPERM],
    }
}

det_case! {
    name: cn_t_02,
    id:   "CN-T-02",
    desc: "A tool with read=[<workspace>] cannot read the workspace's .strands-box/policy.dw or box.toml, or <box_dir>/private/*; a sibling file under the same grant reads; the host files are unchanged",
    run: |b| {
        let probe = b.compile_probe("fsprobe-t02", PROBE);
        let quoted = |p: &std::path::Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
        let workspace = b.workspace().to_path_buf();
        let readable = workspace.join("readable.txt");
        let authority = workspace.join(".strands-box");
        let private = b.box_dir().join("private");
        let edit = |text: String| format!(
            "{text}\n[tool.t02]\ncommand = [{}]\nworkspace = {}\n\n[tool.t02.filesystem]\nread = [{}]\n",
            quoted(&probe), quoted(&workspace), quoted(&workspace)
        );
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        // Warm the box once so `private/` holds its stored copies before the snapshot.
        let warm = b.run_mediated_with_config(edit, "echo WARM");
        warm.assert_contains("WARM");
        let targets = [
            authority.join("policy.dw"),
            authority.join("box.toml"),
            private.join("policy.dw"),
            private.join("box.toml"),
        ];
        for target in &targets {
            assert!(target.is_file(), "DET_ERROR: {} is not on the host", target.display());
        }
        let before: Vec<Vec<u8>> = targets.iter().map(|t| std::fs::read(t).unwrap()).collect();

        let p = sh_quote(&probe.to_string_lossy());
        let mut script = format!("{p} read {}", sh_quote(&readable.to_string_lossy()));
        for target in &targets {
            let t = sh_quote(&target.to_string_lossy());
            script.push_str(&format!("; {p} read {t}; {p} append {t} DET_TOOL_TAMPER_T02"));
        }
        script.push_str(&format!("; {p} list {}", sh_quote(&private.to_string_lossy())));
        let r = b.run_mediated_with_config(edit, &script);
        r.assert_mediated_permitted("shell:spawn", "fsprobe-t02");

        // The control: the tool reads under its grant, so a refusal below is of the target.
        assert!(
            probe_line(&r.out, "READ_OK", &subject(&readable)).is_some_and(|l| l.contains("LISTED_CONTENT")),
            "the tool did not read its own grant; out=[{}]", r.snippet()
        );
        for target in &targets {
            let s = subject(target);
            refused_as(&r.out, "READ", &s, denials())
                .unwrap_or_else(|why| panic!("the tool read {s}: {why}; out=[{}]", r.snippet()));
            refused_as(&r.out, "APPEND", &s, denials())
                .unwrap_or_else(|why| panic!("the tool appended to {s}: {why}; out=[{}]", r.snippet()));
        }
        refused_as(&r.out, "LIST", &subject(&private), denials())
            .unwrap_or_else(|why| panic!("the tool listed the box's private tree: {why}; out=[{}]", r.snippet()));
        r.assert_absent("permit (principal, action == Box::Action::\"shell:exec\"");
        r.assert_absent("DET_PROTECTED_CONFIG_MARKER_7f3a9c");

        let after: Vec<Vec<u8>> = targets.iter().map(|t| std::fs::read(t).unwrap()).collect();
        for ((target, before), after) in targets.iter().zip(&before).zip(&after) {
            assert!(
                !String::from_utf8_lossy(after).contains("DET_TOOL_TAMPER_T02"),
                "the tool's append landed in {}", target.display()
            );
            if target.starts_with(&authority) {
                assert_eq!(before, after, "{} changed on the host", target.display());
            }
        }
    }
}
