use strands_det_harness::det_case;

// A recorded GAP, kept visible on purpose. A FOURTH foreign-process oracle, beside the three
// CN-I-04 records. `kqueue(2)` plus a `kevent(2)` registration of `EVFILT_PROC` on a pid outside
// the box answers whether that pid exists: the registration succeeds for a live process and
// reports ESRCH for one that is not there, so the errno alone is the disclosure.
//
// It cannot be closed with the filters SBPL offers. `process-info*` is rendered `(target self)`
// and does not cover this: the registration is a kqueue filter, not a process-info query.
// `(deny syscall-unix (syscall-number N))` closes `kevent` outright, and macOS has no
// syscall-ARGUMENT filter, so the same deny refuses every other kqueue the workload needs —
// which is every async runtime on the platform. CN-I-03 covers the signal route and finds it
// closed; this filter is a different route to the same fact.
//
// This case asserts the gap is still exactly this wide. It must NEVER be rewritten to claim a
// denial: a suite that says the oracle is closed is how a tracked residual stops being tracked.
//
// Three things this case is written around:
//   * The contrast arm is what makes it an oracle rather than a permission. A registration that
//     merely succeeded would prove nothing; the pair — pid 1 registers, an absent pid answers
//     ESRCH — is the leak, and the case would stop measuring it if either arm were dropped.
//   * The absent pid is FOUND, never assumed. A literal 99999 was the first spelling and it is
//     unsafe: `PID_MAX` is 99999 on macOS and pids wrap, so a busy host can hold it — the
//     highest live pid measured here was 99149. The arm would then read `registered`, the case
//     would fail, and the message would say the residual had closed rather than that the pid was
//     taken. The probe asks `kill(pid, 0)` for a pid the kernel reports absent, and refuses to
//     guess if it cannot find one.
//   * `ident` is `uintptr_t` and is passed as `c_void_p`, because a plain `c_int` truncates a pid
//     on a 64-bit `struct kevent` and would move every later field. Constants from
//     `sys/event.h`: `EVFILT_PROC` -5, `EV_ADD` 0x0001, `NOTE_EXIT` 0x80000000.
//
// macOS-only: there is no Linux counterpart in the shared tree.
det_case! {
    name: cn_i_13,
    id: "CN-I-13",
    platforms: [Macos],
    desc: "Recorded gap: an EVFILT_PROC registration on a foreign pid still answers whether it exists",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
import ctypes

# struct kevent: uintptr_t ident, int16_t filter, uint16_t flags, uint32_t fflags,
# intptr_t data, void *udata (sys/event.h).
class Kevent(ctypes.Structure):
    _fields_ = [
        ("ident", ctypes.c_void_p),
        ("filter", ctypes.c_int16),
        ("flags", ctypes.c_uint16),
        ("fflags", ctypes.c_uint32),
        ("data", ctypes.c_ssize_t),
        ("udata", ctypes.c_void_p),
    ]

EVFILT_PROC = -5
EV_ADD = 0x0001
NOTE_EXIT = 0x80000000
ESRCH = 3

def watch(label, pid):
    """Register EVFILT_PROC/NOTE_EXIT on `pid` and report what the kernel answered."""
    c = libc()
    ctypes.set_errno(0)
    kq = c.kqueue()
    if kq < 0:
        print(label, "ERR", ctypes.get_errno(), "kqueue")
        return
    event = Kevent(ctypes.c_void_p(pid), EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, None)
    ctypes.set_errno(0)
    rc = c.kevent(kq, ctypes.byref(event), 1, None, 0, None)
    errno = ctypes.get_errno()
    os.close(kq)
    if rc == 0:
        print(label, "OK", "registered")
    elif errno == ESRCH:
        print(label, "OK", "no-such-process")
    else:
        print(label, "ERR", errno, "rc", rc)

def find_absent_pid():
    """A pid the kernel reports as absent. Counting down from PID_MAX finds one quickly, and
    every candidate is confirmed rather than assumed."""
    for pid in range(99999, 90000, -1):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return pid
        except OSError:
            continue    # EPERM means the pid IS live and owned by another user.
    return None

absent = find_absent_pid()
# Control on the control: without an absent pid there is no contrast, and the case must say so
# rather than assert against a live process.
t("found_an_absent_pid", lambda: absent is not None)

# pid 1 is launchd: outside the box, always alive, and never the workload's own.
watch("evfilt_proc_pid1", 1)
# A pid that is not there. The contrast is the oracle: the two answers differ.
watch("evfilt_proc_absent", absent)
"#,
        );
        // Control: the contrast arm names a pid the kernel confirmed absent.
        r.assert_ok("found_an_absent_pid", "True");
        // A live foreign process registers, so its existence is disclosed.
        r.assert_ok("evfilt_proc_pid1", "registered");
        // An absent pid answers differently, which is what makes the pair an oracle rather
        // than a uniform permission.
        r.assert_ok("evfilt_proc_absent", "no-such-process");
    }
}
