use strands_det_harness::{det_case, user_home};

// Containment CN-W (Linux workload, act 2)
//
// A file under the operator home reads only when `read_file` names it: the listed settings file
// reads, and an unlisted sibling under HOME does not.
det_case! {
    name: cn_w_02,
    id:   "CN-W-02",
    desc: "Workload act 2: a read_file entry under HOME reads and an unlisted sibling does not",
    run: |b| {
        b.reset_policy();
        // The kernel's spelling, which is the path the fixture's `read_file` grant names; on the
        // macOS instances HOME is /var/tmp/det-home, a link into /private.
        let home = user_home()
            .canonicalize()
            .expect("DET_ERROR: resolve operator home");
        let listed = home.join(".det-listed-settings.json");
        let unlisted = home.join(format!(".det-unlisted-settings-{}.json", std::process::id()));
        std::fs::write(&unlisted, "{\"unlisted\": \"UNLISTED_SETTINGS\"}\n")
            .expect("DET_ERROR: plant the unlisted file");
        let r = b.run_sh(&format!(
            "read -r v < '{}' && printf 'LISTED=%s\\n' \"$v\"; read -r v < '{}' 2>/dev/null && printf 'UNLISTED=%s\\n' \"$v\"; printf done",
            listed.display(),
            unlisted.display()
        ));
        let _ = std::fs::remove_file(&unlisted);
        r.assert_contains("LISTED_SETTINGS");
        r.assert_absent("UNLISTED_SETTINGS");
        r.assert_contains("done");
    }
}
