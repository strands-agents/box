
use strands_det_harness::det_case;

// The macOS profile carries `(deny process-info*)` then `(allow process-info* (target
// self))`, and `self` is the whole allowance: the workload inspects and signals itself and
// nothing else — including a child it forked a moment earlier, which is stricter than
// "another process outside the box". The forked-child arm is the one worth having: a denial
// against pid 1 is also what an ordinary unprivileged process gets, so it names the profile
// only weakly, whereas a denial against a child the workload owns is not something ordinary
// permissions would produce.
//
// macOS-only: there is no Linux counterpart in the shared tree.
det_case! {
    name: cn_i_03,
    id:   "CN-I-03",
    platforms: [Macos],
    desc: "Process isolation: the allow names only self, so even a forked child cannot be signalled",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
import signal, time
t("signal_self", lambda: os.kill(os.getpid(), 0))
t("signal_pid1", lambda: os.kill(1, 0))
pid = os.fork()
if pid == 0:
    time.sleep(5)
    os._exit(0)
time.sleep(0.5)
print("child_pid_nonzero", pid > 0)
t("signal_own_child", lambda: os.kill(pid, 0))
t("priority_own_child", lambda: os.setpriority(os.PRIO_PROCESS, pid, 5))
try:
    os.kill(pid, signal.SIGKILL)
except OSError as e:
    print("cleanup_kill ERR", e.errno, e.strerror)
"#,
        );
        // Positive control: the workload inspects itself, so process-info is allowed for self.
        r.assert_ok("signal_self", "None");
        // Signalling pid 1 (a foreign process) is refused with errno 1.
        r.assert_errno("signal_pid1", 1);
        // The fork succeeded, so there is a real child to address.
        r.assert_contains("child_pid_nonzero True");
        // Even a child the workload forked itself cannot be signalled.
        r.assert_errno("signal_own_child", 1);
        // Changing that child's priority is refused too.
        r.assert_errno("priority_own_child", 1);
    }
}
