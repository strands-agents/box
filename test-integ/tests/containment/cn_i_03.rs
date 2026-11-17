
use crate::phase3 as support;
use std::process::Command;
use strands_det_harness::{BoxFixture, Platform, det_case, native_python};

det_case! {
    name: cn_i_03,
    id:   "CN-I-03",
    platforms: [Macos, Linux],
    desc: "Process signals: macOS permits signals only to itself and an owned child; Linux permits self-signaling and cannot signal a live host marker",
    run: |b| {
        b.reset_policy();
        if Platform::current() == Platform::Linux {
            linux_signals(b);
            return;
        }
        // Uncontained control: an unsandboxed process of the same user reads the pidinfo of, and
        // signals, a same-user process that is not its child. So a refusal of the box's parent
        // below can only come from the profile, and not from the kernel's same-user check.
        let control = Command::new(&native_python().executable)
            .args(["-c", "import ctypes, ctypes.util, os\n\
                 libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)\n\
                 buffer = ctypes.create_string_buffer(512)\n\
                 rc = libc.proc_pidinfo(os.getppid(), 3, ctypes.c_uint64(0), buffer, 512)\n\
                 print('HOST_PIDINFO', rc > 0)\n\
                 os.kill(os.getppid(), 0)\n\
                 print('HOST_SIGNAL True')"])
            .output()
            .expect("DET_ERROR: run the host pidinfo and signal control");
        let control = support::text(control);
        assert!(
            control.contains("HOST_PIDINFO True"),
            "DET_ERROR: the host control must read a same-user process, or the arm below proves nothing"
        );
        assert!(
            control.contains("HOST_SIGNAL True"),
            "DET_ERROR: the host control must signal a same-user process, or the arm below proves nothing"
        );
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
t("signal_parent", lambda: os.kill(os.getppid(), 0))
t("priority_own_child", lambda: os.setpriority(os.PRIO_PROCESS, pid, 5))
import ctypes
def pidinfo(target):
    buffer = ctypes.create_string_buffer(512)
    _, rc, _, errno = raw("proc_pidinfo", target, 3, ctypes.c_uint64(0), buffer, 512)
    return "allowed" if rc > 0 else f"denied errno {errno}"
t("pidinfo_own_child", lambda: pidinfo(pid))
t("pidinfo_parent", lambda: pidinfo(os.getppid()))
t("kill_own_child", lambda: os.kill(pid, signal.SIGKILL))
t("reap_own_child", lambda: os.waitpid(pid, 0)[1] & 0x7f)
"#,
        );
        // Positive control: the workload inspects itself, so process-info is allowed for self.
        r.assert_ok("signal_self", "None");
        // Signalling pid 1 (a foreign process) is refused with errno 1.
        r.assert_errno("signal_pid1", 1);
        // The fork succeeded, so there is a real child to address.
        r.assert_contains("child_pid_nonzero True");
        // A child the workload forked itself can be signalled, so a harness can stop what it
        // started.
        r.assert_ok("signal_own_child", "None");
        // The parent is the unsandboxed `strands-box run` process of the same user. The host
        // control signals it, so the profile alone refuses this one.
        r.assert_errno("signal_parent", 1);
        // Changing that child's priority is still refused: it is not a signal.
        r.assert_errno("priority_own_child", 1);
        // Reading the child's process information is allowed. The parent is the unsandboxed
        // `strands-box run` process of the same user, and the profile alone hides it.
        r.assert_ok("pidinfo_own_child", "allowed");
        r.assert_ok("pidinfo_parent", "denied errno 1");
        // A real signal reaches the child: it dies by SIGKILL (9), not by its own exit.
        r.assert_ok("kill_own_child", "None");
        r.assert_ok("reap_own_child", "9");
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
