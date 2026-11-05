use std::os::unix::fs::MetadataExt as _;

use strands_det_harness::det_case;

// macOS only. Apple ships root-owned programs with several names on its sealed system volume:
// `/usr/bin/git` is one file that every developer-tool stub names, and `/usr/bin/unzip` shares its
// file with `zipinfo`. The user that runs Box cannot write either through any name, so a
// `[tool.<name>]` may name them. `[tool.git]` must load, so the box starts, and `[tool.unzip]` must
// launch through its table.
const GIT: &str = "/usr/bin/git";
const UNZIP: &str = "/usr/bin/unzip";

det_case! {
    name: cn_t_09,
    id:   "CN-T-09",
    platforms: [Macos],
    desc: "Root-owned macOS programs with several names are configured commands: [tool.git] (/usr/bin/git) loads so the box starts, and [tool.unzip] (/usr/bin/unzip) runs through its table",
    run: |b| {
        for program in [GIT, UNZIP] {
            let metadata = std::fs::symlink_metadata(program).expect("DET_ERROR: macOS ships the program");
            assert!(
                metadata.is_file() && metadata.nlink() > 1 && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "DET_ERROR: {program} is not a root-owned file with several names, so this case checks nothing"
            );
        }
        let edit = |text: String| format!(
            "{text}\n[tool.git]\ncommand = [\"{GIT}\"]\n\n[tool.unzip]\ncommand = [\"{UNZIP}\"]\n"
        );
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        let r = b.run_mediated_with_config(edit, "unzip -v; echo RC=$?");
        r.assert_mediated_permitted("shell:spawn", "unzip");
        r.assert_contains("by Info-ZIP");
        r.assert_contains("RC=0");
    }
}
