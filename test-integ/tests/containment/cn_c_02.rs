use std::process::Command;

use strands_det_harness::{NATIVE_PROBE_SEARCH_PATH, Platform, det_case};
det_case! {
    name: when_agent_searches_for_programs_then_aliases_come_first_and_ungranted_execution_is_refused,
    id:   "CN-C-02",
    platforms: [Macos, Linux],
    desc: "Exec surface: PATH is the alias directory then the declared search path; host programs outside the command and grants cannot execute",
    run: |b| {
        b.reset_policy();
        let alias_dir = b.alias_dir();
        let expected_path = format!("{}:{}", alias_dir.display(), NATIVE_PROBE_SEARCH_PATH);
        let (programs, denied) = match Platform::current() {
            Platform::Macos => (
                vec!["/bin/sh", "/bin/zsh", "/usr/bin/python3", "/usr/bin/env", "/bin/ls"],
                1,
            ),
            Platform::Linux => {
                for (program, args) in [
                    ("/bin/sh", vec!["-c", "printf HOST_EXEC_OK"]),
                    ("/usr/bin/env", vec!["printf", "HOST_EXEC_OK"]),
                    ("/bin/ls", vec!["-d", "/"]),
                ] {
                    let control = Command::new(program).args(args).output()
                        .expect("DET_ERROR: the host program starts");
                    assert!(control.status.success(), "DET_ERROR: {program} must run outside Box");
                    assert!(!control.stdout.is_empty(), "DET_ERROR: {program} must produce output");
                }
                (vec!["/bin/sh", "/usr/bin/env", "/bin/ls"], 2)
            }
        };
        let r = b.probe_py(&format!(
            r#"
print("path_composed", os.environ["PATH"] == {expected:?})
print("path_head_is_alias_dir", os.environ["PATH"].split(":")[0] == {alias:?})
print("path_value", os.environ["PATH"])
for p in {programs:?}:
    try:
        os.execv(p, [p, "-c", 'print("ESCAPED_MARKER")'])
        print(p, "RAN")
    except OSError as e:
        print("native_exec", p, "ERR", e.errno, e.strerror)
"#,
            expected = expected_path,
            alias = alias_dir.display().to_string(),
            programs = programs,
        ));

        // CN-C-02a: the composed PATH is the alias directory followed by exactly the declared path.
        r.assert_contains("path_composed True");
        // CN-C-02b: its head is the box's alias directory, not an inherited tree.
        r.assert_contains("path_head_is_alias_dir True");
        // Each ungranted host program is refused by its absolute path.
        for program in programs {
            r.assert_errno(&format!("native_exec {program}"), denied);
        }
        // CN-C-02h: no program ran, so the marker never reaches stdout.
        r.assert_absent("ESCAPED_MARKER");
    }
}
