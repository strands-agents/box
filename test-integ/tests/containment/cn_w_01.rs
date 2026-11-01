use strands_det_harness::{det_case, user_home};

// Containment CN-W (Linux workload, act 1)
//
// The agent writes, reads back, and appends a project file through its own syscalls, and the
// startup disclosure names the workspace grants, the operator home as HOME, and PATH.
det_case! {
    name: cn_w_01,
    id:   "CN-W-01",
    desc: "Workload act 1: write, read, and edit a project file; the disclosure names the grants, HOME, and PATH",
    run: |b| {
        b.reset_policy();
        let file = b.workspace().join("act1.txt");
        let r = b.run_sh(&format!(
            "printf 'first' > '{f}' && v=$(<'{f}') && printf 'READ=%s\\n' \"$v\" && printf ' second' >> '{f}' && v=$(<'{f}') && printf 'EDIT=%s\\n' \"$v\"",
            f = file.display()
        ));
        r.assert_contains("READ=first");
        r.assert_contains("EDIT=first second");
        r.assert_contains(&format!("read        {}", b.workspace().display()));
        r.assert_contains(&format!("write       {}", b.workspace().display()));
        // The operator's HOME as spelled: the box hands the agent `$HOME` itself, not its canonical
        // form, so on the macOS instances this is /var/tmp/det-home, a link into /private.
        r.assert_contains(&format!("HOME={}", user_home().display()));
        r.assert_contains(" PATH=");
        r.assert_allow();
    }
}
