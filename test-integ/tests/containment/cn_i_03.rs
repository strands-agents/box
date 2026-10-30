
use crate::phase3 as support;
use std::process::Command;
use strands_det_harness::{BoxFixture, Platform, det_case, native_python};

det_case! {
    name: when_agent_sends_signals_then_macos_refuses_child_signals_and_linux_hides_host_targets,
    id:   "CN-I-03",
    platforms: [Macos, Linux],
    desc: "Process signals: macOS refuses signals to an owned child; Linux permits self-signaling and cannot signal a live host marker",
    run: |b| {
        b.reset_policy();
        if Platform::current() == Platform::Linux {
            linux_signals(b);
            return;
        }
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

fn linux_signals(b: &BoxFixture) {
    let probe = support::compile(b);
    let mut marker =
        support::Marker::start(&probe, &b.workspace().with_file_name("tgkill-marker"), false);
    let pid = marker.pid();
    let control = Command::new(&native_python().executable)
        .args(["-c", &format!(
            "import ctypes, signal\n\
             libc = ctypes.CDLL(None, use_errno=True)\n\
             assert libc.tgkill({pid}, {pid}, signal.SIGUSR1) == 0, ctypes.get_errno()\n\
             print('HOST_TGKILL_SENT')"
        )])
        .output()
        .expect("DET_ERROR: run the host signal control");
    assert!(support::text(control).contains("HOST_TGKILL_SENT"));
    support::until(
        || marker.count() == 1,
        std::time::Duration::from_secs(3),
        "host tgkill signal observer",
    );
    let result = b.probe_py(&format!(
        "import signal\n\
         received = []\n\
         signal.signal(signal.SIGUSR1, lambda *_: received.append(1))\n\
         signal.raise_signal(signal.SIGUSR1)\n\
         print('self_signal_count', len(received))\n\
         print('signal_host', raw('tgkill', {pid}, {pid}, signal.SIGUSR1))"
    ));
    result.assert_contains("self_signal_count 1");
    result.assert_contains("signal_host ('rc', -1, 'errno', 3)");
    marker.advance();
    assert_eq!(marker.count(), 1, "only the host control signal reached the marker");
    marker.signal_control(2);
}
