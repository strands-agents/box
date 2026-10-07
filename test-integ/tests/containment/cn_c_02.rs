use strands_det_harness::{NATIVE_PROBE_SEARCH_PATH, det_case};

// macOS only.
//
// What the box guarantees about the exec surface, from `run/contain/boundary.rs`:
//   * the workload PATH is composed, not inherited: `composed_path` puts the box's alias directory
//     first and then exactly the declared search path (`[agent.env] PATH`, else the operator's
//     PATH). The probe declares `NATIVE_PROBE_SEARCH_PATH`, so the composed value is known in full;
//   * the agent command and the box's aliases are implicitly executable. This fixture grants
//     no additional exec paths, so the listed host programs outside those entries must be
//     refused at exec, including by absolute path, with EPERM (errno 1).
//
// Two claims the imported case made are outside that contract and are corrected here, with the
// native run of 2026-09-22 as the measurement: "the PATH is one entry" (the real composed PATH
// had eleven entries: alias dir + the operator's PATH, because nothing was declared) and "every
// absolute path is refused" (the agent's own command is not). The correct criterion is the alias
// directory first, the declared path after it, nothing inherited, and exec refused for the
// listed host programs outside the fixture's executable entries.
det_case! {
    name: cn_c_02,
    id:   "CN-C-02",
    platforms: [Macos],
    desc: "Exec surface: the composed PATH is the alias directory then exactly the declared search path; host programs other than the command are refused at exec with errno 1",
    run: |b| {
        b.reset_policy();
        let alias_dir = b.alias_dir();
        let expected_path = format!("{}:{}", alias_dir.display(), NATIVE_PROBE_SEARCH_PATH);
        let r = b.probe_py(&format!(
            r#"
print("path_composed", os.environ["PATH"] == {expected:?})
print("path_head_is_alias_dir", os.environ["PATH"].split(":")[0] == {alias:?})
print("path_value", os.environ["PATH"])
for p in ["/bin/sh", "/bin/zsh", "/usr/bin/python3", "/usr/bin/env", "/bin/ls"]:
    try:
        os.execv(p, [p, "-c", 'print("ESCAPED_MARKER")'])
        print(p, "RAN")
    except OSError as e:
        print("native_exec", p, "ERR", e.errno, e.strerror)
"#,
            expected = expected_path,
            alias = alias_dir.display().to_string()
        ));

        // CN-C-02a: the composed PATH is the alias directory followed by exactly the declared path.
        r.assert_contains("path_composed True");
        // CN-C-02b: its head is the box's alias directory, not an inherited tree.
        r.assert_contains("path_head_is_alias_dir True");
        // CN-C-02c..g: each host program that is not the agent's command is refused by absolute
        // path with exact errno 1 (Apple's /usr/bin/python3 shim included: it is not the command).
        r.assert_errno("native_exec /bin/sh", 1);
        r.assert_errno("native_exec /bin/zsh", 1);
        r.assert_errno("native_exec /usr/bin/python3", 1);
        r.assert_errno("native_exec /usr/bin/env", 1);
        r.assert_errno("native_exec /bin/ls", 1);
        // CN-C-02h: no program ran, so the marker never reaches stdout.
        r.assert_absent("ESCAPED_MARKER");
    }
}
