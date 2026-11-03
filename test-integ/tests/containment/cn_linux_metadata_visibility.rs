use strands_det_harness::{det_case, sh_quote};

const PROBE: &str = include_str!("../probes/fs_probe.rs");
include!("../probes/probe_lines.rs");

det_case! {
    name: cn_linux_metadata_visibility,
    id: "CN-LINUX-METADATA",
    platforms: [Linux],
    desc: "Linux hides ungranted file metadata and contents from both agent and tool, while explicit read grants expose the same file",
    run: |b| {
        let probe = b.compile_probe("fsprobe-linux-metadata", PROBE);
        let file = b.listed_tree().join("entry.txt");
        let missing = b.listed_tree().join("absent-metadata-control");
        assert_eq!(std::fs::read_to_string(&file).unwrap().trim(), "LISTED_CONTENT");
        assert!(!missing.exists(), "DET_ERROR: the absent control already exists");
        let size = std::fs::metadata(&file).unwrap().len();
        let quoted_probe = serde_json::to_string(&probe.to_string_lossy()).unwrap();
        let quoted_file = serde_json::to_string(&file.to_string_lossy()).unwrap();
        let script = format!(
            "{p} stat {f}; {p} stat {m}; {p} read {f}; printf 'METADATA_PROBE_COMPLETE\n'",
            p = sh_quote(&probe.to_string_lossy()),
            f = sh_quote(&file.to_string_lossy()),
            m = sh_quote(&missing.to_string_lossy()),
        );
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        for tool in [false, true] {
            for granted in [true, false] {
                let exec_tree = b.with_exec_tree();
                let edit = |text: String| {
                    let text = exec_tree(text);
                    if tool {
                        format!(
                            "{text}\n[tool.metadata_probe]\ncommand = [{quoted_probe}]\n[tool.metadata_probe.filesystem]\nread_file = [{}]\n",
                            if granted { quoted_file.as_str() } else { "" },
                        )
                    } else if granted {
                        text.replacen("read_file = [", &format!("read_file = [{quoted_file}, "), 1)
                    } else {
                        text
                    }
                };
                let result = if tool {
                    b.run_mediated_with_config(edit, &script)
                } else {
                    b.run_sh_with_config(edit, &script)
                };
                result.assert_contains("METADATA_PROBE_COMPLETE");
                if tool {
                    result.assert_mediated_permitted("shell:spawn", "fsprobe-linux-metadata");
                }
                if granted {
                    assert!(
                        probe_line(&result.out, "STAT_OK", &subject(&file))
                            .is_some_and(|line| line.ends_with(&format!("size={size}"))),
                        "the granted file metadata must be visible: {}", result.snippet()
                    );
                    result.assert_contains("LISTED_CONTENT");
                } else {
                    for operation in ["STAT", "READ"] {
                        refused_as(&result.out, operation, &subject(&file), &[ENOENT])
                            .unwrap_or_else(|why| panic!("ungranted {operation}: {why}; {}", result.snippet()));
                    }
                    result.assert_absent("LISTED_CONTENT");
                }
                refused_as(&result.out, "STAT", &subject(&missing), &[ENOENT])
                    .unwrap_or_else(|why| panic!("absent control: {why}; {}", result.snippet()));
            }
        }
        assert_eq!(std::fs::read_to_string(&file).unwrap().trim(), "LISTED_CONTENT");
    }
}
