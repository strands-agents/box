
use strands_det_harness::det_case;

// A recorded GAP, kept visible on purpose. Foreign-process oracles stay open under this
// profile: getpgid, getsid, and getpriority on a pid outside the box still answer, each
// leaking whether that pid exists. They cannot be closed with the filters SBPL offers —
// `(deny syscall-unix (syscall-number N))` closes each call, but macOS has no
// syscall-ARGUMENT filter, so the same deny also refuses the workload's own `getpgid(0)`.
//
// This case asserts the gap is still exactly this wide. It must NEVER be rewritten to claim
// a denial: a suite that says the oracle is closed is how a tracked residual stops being
// tracked.
//
// macOS-only: there is no Linux counterpart in the shared tree.
det_case! {
    name: cn_i_04,
    id:   "CN-I-04",
    platforms: [Macos],
    desc: "Recorded gap: getpgid/getsid/getpriority on a foreign pid still answer",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
def oracle(label, name, *args):
    result = raw(name, *args)
    if result[3] == 0:
        print(label, "OK", "answered")
    else:
        print(label, "ERR", result[3], "rc", result[1])
oracle("getpgid_pid1", "getpgid", 1)
oracle("getsid_pid1", "getsid", 1)
oracle("getpriority_pid1", "getpriority", 0, 1)
"#,
        );
        // The exact pgid, sid, and priority are host state. The residual is
        // that all three foreign-pid queries answer with errno 0.
        r.assert_ok("getpgid_pid1", "answered");
        r.assert_ok("getsid_pid1", "answered");
        r.assert_ok("getpriority_pid1", "answered");
    }
}
