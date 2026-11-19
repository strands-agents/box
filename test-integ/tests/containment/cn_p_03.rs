
use strands_det_harness::det_case;

// OpenMP's runtime registers itself in shared memory; nothing else does.
//
// libomp registers each process that loads it in a POSIX shared-memory object named
// __KMP_REGISTERED_LIB_<pid>, and libomp 15 and older abort when the open fails. The profile
// allows that name and no other, so this case follows libomp's own sequence on it (create
// exclusively, size, map, write, reopen, unlink) and bounds the grant from ABOVE: a name of
// another program, and the libomp name with anything after the PID, stay refused (errno 1).
//
// macOS-only: Linux has no Seatbelt shared-memory rule to test.
det_case! {
    name: cn_p_03,
    id:   "CN-P-03",
    platforms: [Macos],
    desc: "OpenMP registration: its shared-memory name opens; other names stay refused with errno 1",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
import _posixshmem, mmap
pid = os.getpid()
def register(name):
    fd = _posixshmem.shm_open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR, mode=0o666)
    try:
        os.ftruncate(fd, 1024)
        m = mmap.mmap(fd, 1024)
        m[:5] = b"probe"
        m.close()
    finally:
        os.close(fd)
    os.close(_posixshmem.shm_open(name, os.O_RDONLY, mode=0))
    _posixshmem.shm_unlink(name)
    return "registered"
t("shm_openmp", lambda: register("/__KMP_REGISTERED_LIB_%d" % pid))
t("shm_other", lambda: register("/box_probe_%d" % pid))
t("shm_suffix", lambda: register("/__KMP_REGISTERED_LIB_%dx" % pid))
"#,
        );
        r.assert_ok("shm_openmp", "registered");
        r.assert_errno("shm_other", 1);
        r.assert_errno("shm_suffix", 1);
    }
}
