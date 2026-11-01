// macOS only. A RECORDED GAP, kept visible on purpose. Machine-wide existence still answers
// outside the operator home, because a blanket `(deny file-test-existence)` would refuse the
// workload's own exec and the loader never recovers — so the deny is SCOPED to the operator
// home. Inside that home, existence answers False for both present and absent paths; outside
// it (under /bin) a present name answers True and an absent one False.
//
// This case asserts the gap is still exactly as wide as it is recorded to be. It must NOT be
// rewritten to claim the disclosure is closed: it is not, and a suite that says otherwise is
// how a tracked residual stops being tracked.
use strands_det_harness::{det_case, operator_home};

det_case! {
    name: cn_e_04,
    id:   "CN-E-04",
    platforms: [Macos],
    desc: "Recorded gap: machine-wide existence still answers outside the operator home; the deny is scoped to it",
    run: |b| {
        b.reset_policy();
        let home = operator_home();
        let home = home.display();
        let r = b.probe_py(&format!(
            r#"
t("system_present", lambda: os.access("/bin/bash", os.F_OK))
t("system_absent",  lambda: os.access("/bin/sb-not-a-real-name", os.F_OK))
t("home_present",   lambda: os.access("{home}/.zshrc", os.F_OK))
t("home_absent",    lambda: os.access("{home}/sb-absent-e13b", os.F_OK))
"#
        ));
        // Outside the operator home the existence distinction stays observable.
        r.assert_ok("system_present", "True");
        r.assert_ok("system_absent", "False");
        // Inside the operator home even a PRESENT file answers False, unlike /bin.
        r.assert_ok("home_present", "False");
        r.assert_ok("home_absent", "False");
    }
}
